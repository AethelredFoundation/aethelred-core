package keeper

import (
	"container/heap"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync"

	"cosmossdk.io/log"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// JobScheduler manages the queue and scheduling of compute jobs for verification.
// It implements priority-based scheduling with validator capability matching.
//
// PERSISTENCE MODEL: The scheduler is an in-memory hot cache over on-chain state.
// The authoritative state for jobs and validator capabilities lives in the Keeper's
// on-chain collections (Jobs, PendingJobs, ValidatorCapabilities).
//
// Scheduling metadata (assignment/retry/last-attempt) is persisted into
// ComputeJob.Metadata under scheduler-specific keys. This allows deterministic
// recovery on node restart:
//   - Call SyncFromChain() to reload pending jobs and scheduling metadata
//   - Validator capabilities are refreshed from on-chain state each block
//     via refreshValidatorCapabilities()
type JobScheduler struct {
	logger log.Logger
	keeper *Keeper

	// Priority queue of pending jobs
	jobQueue *JobPriorityQueue

	// Map of job ID to job for quick lookup
	jobIndex map[string]*ScheduledJob

	// Validator capabilities cache
	validatorCapabilities map[string]*types.ValidatorCapability

	// Configuration
	config SchedulerConfig

	// Mutex for thread safety
	mu sync.RWMutex
}

// Stop gracefully stops the scheduler. Currently a no-op because the scheduler
// runs only on-demand, but the method exists to satisfy shutdown adapters.
func (s *JobScheduler) Stop() {
	// Intentionally no-op.
}

// ---------------------------------------------------------------------------
// Validator pools (indexed by proof type)
// ---------------------------------------------------------------------------

type validatorCandidate struct {
	validator *types.ValidatorCapability
	address   string
}

type validatorHeap []*validatorCandidate

func (h validatorHeap) Len() int { return len(h) }

// Max-heap by reputation, deterministic tie-breaker by address.
func (h validatorHeap) Less(i, j int) bool {
	if h[i].validator.ReputationScore != h[j].validator.ReputationScore {
		return h[i].validator.ReputationScore > h[j].validator.ReputationScore
	}
	return h[i].address < h[j].address
}

func (h validatorHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *validatorHeap) Push(x interface{}) {
	*h = append(*h, x.(*validatorCandidate))
}

func (h *validatorHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	*h = old[0 : n-1]
	return item
}

type validatorPool struct {
	totalAvailable int
	tee            *validatorHeap
	zkml           *validatorHeap
	hybrid         *validatorHeap
}

func newValidatorPool(caps map[string]*types.ValidatorCapability) *validatorPool {
	pool := &validatorPool{
		tee:    &validatorHeap{},
		zkml:   &validatorHeap{},
		hybrid: &validatorHeap{},
	}

	for _, cap := range caps {
		if cap == nil || cap.Address == "" {
			continue
		}
		if !cap.IsOnline || cap.CurrentJobs >= cap.MaxConcurrentJobs {
			continue
		}

		candidate := &validatorCandidate{
			validator: cap,
			address:   cap.Address,
		}
		pool.totalAvailable++

		if len(cap.TeePlatforms) > 0 {
			*pool.tee = append(*pool.tee, candidate)
		}
		if len(cap.ZkmlSystems) > 0 {
			*pool.zkml = append(*pool.zkml, candidate)
		}
		if len(cap.TeePlatforms) > 0 && len(cap.ZkmlSystems) > 0 {
			*pool.hybrid = append(*pool.hybrid, candidate)
		}
	}

	heap.Init(pool.tee)
	heap.Init(pool.zkml)
	heap.Init(pool.hybrid)

	return pool
}

func (p *validatorPool) assign(job *types.ComputeJob, required int, entropy []byte) ([]string, []VRFAssignmentRecord) {
	if job == nil {
		return nil, nil
	}
	if required <= 0 {
		return nil, nil
	}

	h := p.heapForProofType(job.ProofType)
	if h == nil || h.Len() == 0 {
		return nil, nil
	}

	var popped []*validatorCandidate
	eligible := make([]*validatorCandidate, 0, h.Len())

	for h.Len() > 0 {
		cand := heap.Pop(h).(*validatorCandidate)
		popped = append(popped, cand)

		if cand == nil || cand.validator == nil {
			continue
		}
		if !cand.validator.IsOnline || cand.validator.CurrentJobs >= cand.validator.MaxConcurrentJobs {
			continue
		}

		eligible = append(eligible, cand)
	}

	if len(eligible) < required {
		p.reinsertAvailable(h, popped)
		return nil, nil
	}

	alphaRoot := buildAssignmentAlphaRoot(job, entropy)
	scored := make([]vrfScoredCandidate, 0, len(eligible))
	for _, candidate := range eligible {
		record, score, ok := scoreCandidateWithVRF(alphaRoot, candidate)
		if !ok {
			continue
		}
		scored = append(scored, vrfScoredCandidate{
			candidate: candidate,
			score:     score,
			record:    record,
		})
	}

	if len(scored) < required {
		p.reinsertAvailable(h, popped)
		return nil, nil
	}

	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return bytesLess(scored[i].score[:], scored[j].score[:])
		}
		return scored[i].candidate.address < scored[j].candidate.address
	})

	selected := scored[:required]
	assigned := make([]string, 0, required)
	records := make([]VRFAssignmentRecord, 0, required)

	for _, picked := range selected {
		picked.candidate.validator.CurrentJobs++
		assigned = append(assigned, picked.candidate.address)
		records = append(records, picked.record)
	}

	p.reinsertAvailable(h, popped)

	return assigned, records
}

func (p *validatorPool) heapForProofType(proofType types.ProofType) *validatorHeap {
	switch proofType {
	case types.ProofTypeTEE:
		return p.tee
	case types.ProofTypeZKML:
		return p.zkml
	case types.ProofTypeHybrid:
		return p.hybrid
	default:
		return nil
	}
}

func (p *validatorPool) reinsertAvailable(h *validatorHeap, candidates []*validatorCandidate) {
	for _, cand := range candidates {
		if cand == nil || cand.validator == nil {
			continue
		}
		if !cand.validator.IsOnline || cand.validator.CurrentJobs >= cand.validator.MaxConcurrentJobs {
			continue
		}
		heap.Push(h, cand)
	}
}

func bytesLess(a, b []byte) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] == b[i] {
			continue
		}
		return a[i] < b[i]
	}
	return len(a) < len(b)
}

func buildAssignmentAlphaRoot(job *types.ComputeJob, entropy []byte) []byte {
	h := sha256.New()
	h.Write([]byte(vrfAssignmentVersion))
	h.Write([]byte(job.Id))
	h.Write([]byte(job.ProofType.String()))
	if len(job.ModelHash) > 0 {
		h.Write(job.ModelHash)
	}
	if len(job.InputHash) > 0 {
		h.Write(job.InputHash)
	}
	if len(entropy) > 0 {
		h.Write(entropy)
	}
	return h.Sum(nil)
}

func scoreCandidateWithVRF(alphaRoot []byte, candidate *validatorCandidate) (VRFAssignmentRecord, [32]byte, bool) {
	var zero [32]byte
	if candidate == nil || candidate.validator == nil || candidate.address == "" {
		return VRFAssignmentRecord{}, zero, false
	}

	seedInput := sha256.Sum256(append(alphaRoot, []byte(candidate.address)...))
	privateKey := ed25519.NewKeyFromSeed(seedInput[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)

	alpha := sha256.Sum256(append(alphaRoot, []byte("|"+candidate.address)...))
	proofSignature := ed25519.Sign(privateKey, alpha[:])
	verified := ed25519.Verify(publicKey, alpha[:], proofSignature)
	if !verified {
		return VRFAssignmentRecord{}, zero, false
	}

	var score [32]byte
	outputHash := sha256.Sum256(proofSignature)
	copy(score[:], outputHash[:])

	var gamma [32]byte
	var challenge [32]byte
	copy(gamma[:], proofSignature[:32])
	copy(challenge[:], proofSignature[32:64])

	record := VRFAssignmentRecord{
		ValidatorAddress: candidate.address,
		PublicKey:        hex.EncodeToString(publicKey),
		Alpha:            hex.EncodeToString(alpha[:]),
		OutputHash:       hex.EncodeToString(outputHash[:]),
		ProofGamma:       hex.EncodeToString(gamma[:]),
		ProofChallenge:   hex.EncodeToString(challenge[:]),
		ProofResponse:    hex.EncodeToString(proofSignature),
		Verified:         true,
	}

	return record, score, true
}

// SchedulerConfig contains configuration for the job scheduler
type SchedulerConfig struct {
	// MaxJobsPerBlock limits how many jobs can be processed per block
	MaxJobsPerBlock int

	// MaxJobsPerValidator limits concurrent jobs per validator
	MaxJobsPerValidator int

	// JobTimeoutBlocks is how many blocks before a job times out
	JobTimeoutBlocks int64

	// MinValidatorsRequired is the minimum validators needed for consensus
	MinValidatorsRequired int

	// PriorityBoostPerBlock increases priority for waiting jobs
	PriorityBoostPerBlock int64

	// MaxRetries for failed jobs
	MaxRetries int

	// RequireDKGBeacon enforces use of threshold-beacon entropy for assignment.
	RequireDKGBeacon bool

	// RequirePublicDrandPulse enforces that assignment entropy must come from
	// the public drand network (or an explicitly injected drand pulse).
	RequirePublicDrandPulse bool

	// AllowDKGBeaconFallback allows compatibility fallback to legacy DKG beacon
	// payloads while drand cutover is in progress.
	AllowDKGBeaconFallback bool

	// AllowLegacyEntropyFallback preserves deterministic legacy entropy when a
	// DKG beacon payload is unavailable.
	AllowLegacyEntropyFallback bool

	// DrandPulseProvider retrieves the latest drand pulse. When configured and
	// strict mode is enabled, scheduling is blocked if no verifiable pulse is available.
	DrandPulseProvider DrandPulseProvider
}

// DefaultSchedulerConfig returns sensible defaults
func DefaultSchedulerConfig() SchedulerConfig {
	return SchedulerConfig{
		MaxJobsPerBlock:            10,
		MaxJobsPerValidator:        3,
		JobTimeoutBlocks:           100,
		MinValidatorsRequired:      3,
		PriorityBoostPerBlock:      1,
		MaxRetries:                 3,
		RequireDKGBeacon:           true,
		RequirePublicDrandPulse:    false,
		AllowDKGBeaconFallback:     true,
		AllowLegacyEntropyFallback: true,
	}
}

// ScheduledJob wraps a ComputeJob with scheduling metadata
type ScheduledJob struct {
	Job *types.ComputeJob

	// Scheduling metadata
	EffectivePriority int64
	SubmittedBlock    int64
	RetryCount        int
	LastAttemptBlock  int64
	AssignedTo        []string // Validator addresses assigned to this job
	VRFEntropy        string
	VRFAssignments    []VRFAssignmentRecord
	BeaconSource      string
	BeaconVersion     string
	BeaconRound       uint64
	BeaconRandomness  string
	BeaconSigHash     string

	// Index in the priority queue (for heap operations)
	index int
}

const (
	schedulerMetaRetryCount       = "scheduler.retry_count"
	schedulerMetaLastAttemptBlock = "scheduler.last_attempt_block"
	schedulerMetaAssignedTo       = "scheduler.assigned_to"
	schedulerMetaSubmittedBlock   = "scheduler.submitted_block"
	schedulerMetaVRFVersion       = "scheduler.vrf_version"
	schedulerMetaVRFEntropy       = "scheduler.vrf_entropy"
	schedulerMetaVRFAssignments   = "scheduler.vrf_assignments"
	schedulerMetaBeaconSource     = "scheduler.beacon_source"
	schedulerMetaBeaconVersion    = "scheduler.beacon_version"
	schedulerMetaBeaconRound      = "scheduler.beacon_round"
	schedulerMetaBeaconRandomness = "scheduler.beacon_randomness"
	schedulerMetaBeaconSigHash    = "scheduler.beacon_signature_hash"
)

const vrfAssignmentVersion = "pouw-vrf-v1"
const thresholdBeaconSchemeV1 = "dkg-threshold-bls-v1"
const drandBeaconSchemeV1 = "drand-public-v1"

// VRFAssignmentRecord captures the deterministic proof tuple used for
// validator assignment. This is persisted into job metadata for auditability.
type VRFAssignmentRecord struct {
	ValidatorAddress string `json:"validator_address"`
	PublicKey        string `json:"public_key"`
	Alpha            string `json:"alpha"`
	OutputHash       string `json:"output_hash"`
	ProofGamma       string `json:"proof_gamma"`
	ProofChallenge   string `json:"proof_challenge"`
	ProofResponse    string `json:"proof_response"`
	Verified         bool   `json:"verified"`
}

type vrfScoredCandidate struct {
	candidate *validatorCandidate
	score     [32]byte
	record    VRFAssignmentRecord
}

// DKGBeaconPayload carries threshold-beacon randomness for deterministic and
// unbiased assignment ordering.
type DKGBeaconPayload struct {
	Round      uint64
	Randomness []byte
	Signature  []byte
	Scheme     string
}

// DrandPulsePayload carries an externally fetched drand pulse that can be
// injected into scheduling context (useful for deterministic tests and offline
// deterministic replay).
type DrandPulsePayload struct {
	Round      uint64
	Randomness []byte
	Signature  []byte
	Scheme     string
}

type dkgBeaconContextKey struct{}
type drandPulseContextKey struct{}

type entropyMeta struct {
	Source           string
	BeaconVersion    string
	BeaconRound      uint64
	BeaconRandomness string
	BeaconSigHash    string
}

// WithDKGBeaconPayload attaches threshold-beacon entropy to a scheduling context.
func WithDKGBeaconPayload(ctx context.Context, payload DKGBeaconPayload) context.Context {
	return context.WithValue(ctx, dkgBeaconContextKey{}, payload)
}

// WithDrandPulsePayload attaches a drand pulse to a scheduling context.
func WithDrandPulsePayload(ctx context.Context, payload DrandPulsePayload) context.Context {
	return context.WithValue(ctx, drandPulseContextKey{}, payload)
}

func assignmentEntropyFromContext(
	ctx context.Context,
	blockHeight int64,
	cfg SchedulerConfig,
) ([]byte, entropyMeta, error) {
	if pulse, ok, err := extractDrandPulsePayload(ctx); err != nil {
		return nil, entropyMeta{}, err
	} else if ok {
		sigHash := sha256.Sum256(pulse.Signature)
		return entropyFromBeaconPayload(
				pulse.Round,
				pulse.Scheme,
				pulse.Randomness,
				pulse.Signature,
				"drand-public",
			), entropyMeta{
				Source:           "drand-public",
				BeaconVersion:    pulse.Scheme,
				BeaconRound:      pulse.Round,
				BeaconRandomness: hex.EncodeToString(pulse.Randomness),
				BeaconSigHash:    hex.EncodeToString(sigHash[:]),
			}, nil
	}

	if cfg.DrandPulseProvider != nil {
		pulse, err := cfg.DrandPulseProvider.LatestPulse(ctx)
		if err == nil {
			sigHash := sha256.Sum256(pulse.Signature)
			if pulse.Scheme == "" {
				pulse.Scheme = drandBeaconSchemeV1
			}
			if pulse.Source == "" {
				pulse.Source = "drand-public"
			}
			return entropyFromBeaconPayload(
					pulse.Round,
					pulse.Scheme,
					pulse.Randomness,
					pulse.Signature,
					pulse.Source,
				), entropyMeta{
					Source:           pulse.Source,
					BeaconVersion:    pulse.Scheme,
					BeaconRound:      pulse.Round,
					BeaconRandomness: hex.EncodeToString(pulse.Randomness),
					BeaconSigHash:    hex.EncodeToString(sigHash[:]),
				}, nil
		}
		if cfg.RequirePublicDrandPulse {
			return nil, entropyMeta{}, fmt.Errorf("failed to fetch required drand pulse: %w", err)
		}
	}

	if cfg.RequirePublicDrandPulse {
		return nil, entropyMeta{}, fmt.Errorf("missing required drand pulse")
	}

	if payload, ok, err := extractDKGBeaconPayload(ctx); err != nil {
		return nil, entropyMeta{}, err
	} else if ok {
		if !cfg.AllowDKGBeaconFallback {
			return nil, entropyMeta{}, fmt.Errorf("legacy DKG payload provided but fallback disabled")
		}
		sigHash := sha256.Sum256(payload.Signature)
		return entropyFromBeaconPayload(
				payload.Round,
				payload.Scheme,
				payload.Randomness,
				payload.Signature,
				"dkg-threshold-beacon",
			), entropyMeta{
				Source:           "dkg-threshold-beacon",
				BeaconVersion:    payload.Scheme,
				BeaconRound:      payload.Round,
				BeaconRandomness: hex.EncodeToString(payload.Randomness),
				BeaconSigHash:    hex.EncodeToString(sigHash[:]),
			}, nil
	}

	if !cfg.AllowLegacyEntropyFallback {
		return nil, entropyMeta{}, fmt.Errorf("missing required DKG threshold beacon payload")
	}

	// Compatibility entropy path for environments where beacon feeds are not yet wired.
	h := sha256.New()
	h.Write([]byte(vrfAssignmentVersion))
	h.Write([]byte(strconv.FormatInt(blockHeight, 10)))

	if sdkCtx, ok := unwrapSDKContext(ctx); ok {
		h.Write([]byte(sdkCtx.ChainID()))
		h.Write([]byte(sdkCtx.BlockTime().UTC().Format("2006-01-02T15:04:05.999999999Z07:00")))
		if headerHash := sdkCtx.HeaderHash(); len(headerHash) > 0 {
			h.Write(headerHash)
		}
	}

	return h.Sum(nil), entropyMeta{
		Source:        "legacy-context-fallback",
		BeaconVersion: "legacy-context-v1",
	}, nil
}

func (s *JobScheduler) productionModeDisallowsLegacyEntropy(ctx context.Context) bool {
	// Preserve test/dev ergonomics for in-memory schedulers with no keeper.
	if s == nil || s.keeper == nil {
		return false
	}

	params, err := s.keeper.GetParams(ctx)
	if err != nil || params == nil {
		// Fail closed when keeper-backed scheduler cannot load params.
		return true
	}

	// In production mode, legacy context-derived entropy must never be used.
	return !params.AllowSimulated
}

func entropyFromBeaconPayload(
	round uint64,
	scheme string,
	randomness []byte,
	signature []byte,
	source string,
) []byte {
	h := sha256.New()
	h.Write([]byte(vrfAssignmentVersion))
	h.Write([]byte(scheme))
	h.Write([]byte(source))
	h.Write([]byte(strconv.FormatUint(round, 10)))
	h.Write(randomness)
	h.Write(signature)
	return h.Sum(nil)
}

func extractDrandPulsePayload(ctx context.Context) (DrandPulsePayload, bool, error) {
	if ctx == nil {
		return DrandPulsePayload{}, false, nil
	}

	raw := ctx.Value(drandPulseContextKey{})
	if raw == nil {
		return DrandPulsePayload{}, false, nil
	}

	payload, ok := raw.(DrandPulsePayload)
	if !ok {
		return DrandPulsePayload{}, false, fmt.Errorf("invalid drand pulse payload type")
	}
	if payload.Round == 0 {
		return DrandPulsePayload{}, false, fmt.Errorf("invalid drand round: must be > 0")
	}
	if len(payload.Randomness) != 32 {
		return DrandPulsePayload{}, false, fmt.Errorf("invalid drand randomness length: got %d want 32", len(payload.Randomness))
	}
	if len(payload.Signature) < 48 {
		return DrandPulsePayload{}, false, fmt.Errorf("invalid drand signature length: got %d", len(payload.Signature))
	}
	if payload.Scheme == "" {
		payload.Scheme = drandBeaconSchemeV1
	}
	return payload, true, nil
}

func extractDKGBeaconPayload(ctx context.Context) (DKGBeaconPayload, bool, error) {
	if ctx == nil {
		return DKGBeaconPayload{}, false, nil
	}

	raw := ctx.Value(dkgBeaconContextKey{})
	if raw == nil {
		return DKGBeaconPayload{}, false, nil
	}

	payload, ok := raw.(DKGBeaconPayload)
	if !ok {
		return DKGBeaconPayload{}, false, fmt.Errorf("invalid DKG beacon payload type")
	}

	if payload.Round == 0 {
		return DKGBeaconPayload{}, false, fmt.Errorf("invalid DKG beacon round: must be > 0")
	}
	if len(payload.Randomness) != 32 {
		return DKGBeaconPayload{}, false, fmt.Errorf("invalid DKG beacon randomness length: got %d want 32", len(payload.Randomness))
	}
	// Threshold BLS signatures are commonly 96 bytes (G2); accept >=48 as guardrail
	// to preserve compatibility with aggregator encodings.
	if len(payload.Signature) < 48 {
		return DKGBeaconPayload{}, false, fmt.Errorf("invalid DKG beacon signature length: got %d", len(payload.Signature))
	}

	if payload.Scheme == "" {
		payload.Scheme = thresholdBeaconSchemeV1
	}

	return payload, true, nil
}

func unwrapSDKContext(ctx context.Context) (sdk.Context, bool) {
	if ctx == nil {
		return sdk.Context{}, false
	}
	if sdkCtx, ok := ctx.(sdk.Context); ok {
		return sdkCtx, true
	}
	if val := ctx.Value(sdk.SdkContextKey); val != nil {
		if sdkCtx, ok := val.(sdk.Context); ok {
			return sdkCtx, true
		}
	}
	return sdk.Context{}, false
}

func getMetaInt(meta map[string]string, key string, fallback int64) int64 {
	raw, ok := meta[key]
	if !ok || raw == "" {
		return fallback
	}
	val, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fallback
	}
	return val
}

func getMetaIntAsInt(meta map[string]string, key string, fallback int) int {
	raw, ok := meta[key]
	if !ok || raw == "" {
		return fallback
	}
	val, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return val
}

func getMetaStringSlice(meta map[string]string, key string) []string {
	raw, ok := meta[key]
	if !ok || raw == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

func getMetaVRFAssignments(meta map[string]string, key string) []VRFAssignmentRecord {
	raw, ok := meta[key]
	if !ok || raw == "" {
		return nil
	}
	var out []VRFAssignmentRecord
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

func (s *JobScheduler) persistSchedulingMetadata(ctx context.Context, scheduledJob *ScheduledJob) {
	if s.keeper == nil || scheduledJob == nil || scheduledJob.Job == nil {
		return
	}
	if _, ok := unwrapSDKContext(ctx); !ok {
		return
	}

	job := scheduledJob.Job
	if job.Metadata == nil {
		job.Metadata = make(map[string]string)
	}

	job.Metadata[schedulerMetaRetryCount] = strconv.Itoa(scheduledJob.RetryCount)
	job.Metadata[schedulerMetaLastAttemptBlock] = strconv.FormatInt(scheduledJob.LastAttemptBlock, 10)
	if scheduledJob.SubmittedBlock > 0 {
		job.Metadata[schedulerMetaSubmittedBlock] = strconv.FormatInt(scheduledJob.SubmittedBlock, 10)
	}

	if len(scheduledJob.AssignedTo) > 0 {
		assigned, err := json.Marshal(scheduledJob.AssignedTo)
		if err != nil {
			s.logger.Warn("Failed to marshal scheduler assignment",
				"job_id", job.Id,
				"error", err,
			)
		} else {
			job.Metadata[schedulerMetaAssignedTo] = string(assigned)
		}
	} else {
		delete(job.Metadata, schedulerMetaAssignedTo)
	}

	if scheduledJob.VRFEntropy != "" {
		job.Metadata[schedulerMetaVRFVersion] = vrfAssignmentVersion
		job.Metadata[schedulerMetaVRFEntropy] = scheduledJob.VRFEntropy
	} else {
		delete(job.Metadata, schedulerMetaVRFVersion)
		delete(job.Metadata, schedulerMetaVRFEntropy)
	}

	if len(scheduledJob.VRFAssignments) > 0 {
		records, err := json.Marshal(scheduledJob.VRFAssignments)
		if err != nil {
			s.logger.Warn("Failed to marshal scheduler VRF assignments",
				"job_id", job.Id,
				"error", err,
			)
		} else {
			job.Metadata[schedulerMetaVRFAssignments] = string(records)
		}
	} else {
		delete(job.Metadata, schedulerMetaVRFAssignments)
	}

	if scheduledJob.BeaconSource != "" {
		job.Metadata[schedulerMetaBeaconSource] = scheduledJob.BeaconSource
	} else {
		delete(job.Metadata, schedulerMetaBeaconSource)
	}
	if scheduledJob.BeaconVersion != "" {
		job.Metadata[schedulerMetaBeaconVersion] = scheduledJob.BeaconVersion
	} else {
		delete(job.Metadata, schedulerMetaBeaconVersion)
	}
	if scheduledJob.BeaconRound > 0 {
		job.Metadata[schedulerMetaBeaconRound] = strconv.FormatUint(scheduledJob.BeaconRound, 10)
	} else {
		delete(job.Metadata, schedulerMetaBeaconRound)
	}
	if scheduledJob.BeaconRandomness != "" {
		job.Metadata[schedulerMetaBeaconRandomness] = scheduledJob.BeaconRandomness
	} else {
		delete(job.Metadata, schedulerMetaBeaconRandomness)
	}
	if scheduledJob.BeaconSigHash != "" {
		job.Metadata[schedulerMetaBeaconSigHash] = scheduledJob.BeaconSigHash
	} else {
		delete(job.Metadata, schedulerMetaBeaconSigHash)
	}

	if err := s.keeper.UpdateJob(ctx, job); err != nil {
		s.logger.Warn("Failed to persist scheduler metadata",
			"job_id", job.Id,
			"error", err,
		)
	}
}

func (s *JobScheduler) loadSchedulingMetadata(job *types.ComputeJob) (
	retryCount int,
	lastAttempt int64,
	assigned []string,
	submittedBlock int64,
	vrfEntropy string,
	vrfAssignments []VRFAssignmentRecord,
	beaconSource string,
	beaconVersion string,
	beaconRound uint64,
	beaconRandomness string,
	beaconSigHash string,
) {
	if job == nil {
		return 0, 0, nil, 0, "", nil, "", "", 0, "", ""
	}
	if job.Metadata == nil {
		return 0, 0, nil, job.BlockHeight, "", nil, "", "", 0, "", ""
	}
	retryCount = getMetaIntAsInt(job.Metadata, schedulerMetaRetryCount, 0)
	lastAttempt = getMetaInt(job.Metadata, schedulerMetaLastAttemptBlock, 0)
	assigned = getMetaStringSlice(job.Metadata, schedulerMetaAssignedTo)
	submittedBlock = getMetaInt(job.Metadata, schedulerMetaSubmittedBlock, job.BlockHeight)
	vrfEntropy = job.Metadata[schedulerMetaVRFEntropy]
	vrfAssignments = getMetaVRFAssignments(job.Metadata, schedulerMetaVRFAssignments)
	beaconSource = job.Metadata[schedulerMetaBeaconSource]
	beaconVersion = job.Metadata[schedulerMetaBeaconVersion]
	beaconRoundRaw := job.Metadata[schedulerMetaBeaconRound]
	if beaconRoundRaw != "" {
		if parsed, err := strconv.ParseUint(beaconRoundRaw, 10, 64); err == nil {
			beaconRound = parsed
		}
	}
	beaconRandomness = job.Metadata[schedulerMetaBeaconRandomness]
	beaconSigHash = job.Metadata[schedulerMetaBeaconSigHash]
	if job.Status != types.JobStatusProcessing {
		assigned = nil
	}
	return retryCount, lastAttempt, assigned, submittedBlock, vrfEntropy, vrfAssignments, beaconSource, beaconVersion, beaconRound, beaconRandomness, beaconSigHash
}

// NewJobScheduler creates a new job scheduler
func NewJobScheduler(logger log.Logger, keeper *Keeper, config SchedulerConfig) *JobScheduler {
	s := &JobScheduler{
		logger:                logger,
		keeper:                keeper,
		jobQueue:              &JobPriorityQueue{},
		jobIndex:              make(map[string]*ScheduledJob),
		validatorCapabilities: make(map[string]*types.ValidatorCapability),
		config:                config,
	}

	heap.Init(s.jobQueue)
	return s
}

// EnqueueJob adds a new job to the scheduler
func (s *JobScheduler) EnqueueJob(ctx context.Context, job *types.ComputeJob) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Check if job already exists
	if _, exists := s.jobIndex[job.Id]; exists {
		return fmt.Errorf("job already scheduled: %s", job.Id)
	}

	// Create scheduled job
	scheduledJob := &ScheduledJob{
		Job:               job,
		EffectivePriority: job.Priority,
		SubmittedBlock:    sdkCtx.BlockHeight(),
		RetryCount:        0,
		AssignedTo:        make([]string, 0),
	}

	// Add to queue and index
	heap.Push(s.jobQueue, scheduledJob)
	s.jobIndex[job.Id] = scheduledJob

	s.logger.Info("Job enqueued",
		"job_id", job.Id,
		"priority", job.Priority,
		"proof_type", job.ProofType,
	)

	s.persistSchedulingMetadata(ctx, scheduledJob)

	return nil
}

// GetNextJobs returns the next batch of jobs to process in this block
func (s *JobScheduler) GetNextJobs(ctx context.Context, blockHeight int64) []*types.ComputeJob {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Refresh validator capabilities from on-chain state
	s.refreshValidatorCapabilities(ctx)

	// Update priorities based on wait time
	s.updatePriorities(blockHeight)

	// Remove expired jobs
	s.removeExpiredJobs(ctx, blockHeight)

	// Build indexed validator pools (by proof type)
	pool := newValidatorPool(s.validatorCapabilities)
	if pool.totalAvailable < s.config.MinValidatorsRequired {
		s.logger.Warn("Not enough validators available",
			"available", pool.totalAvailable,
			"required", s.config.MinValidatorsRequired,
		)
		return nil
	}

	// Select jobs up to MaxJobsPerBlock
	var selectedJobs []*types.ComputeJob
	selectedCount := 0
	entropy, entropyDetails, entropyErr := assignmentEntropyFromContext(ctx, blockHeight, s.config)
	if entropyErr != nil {
		s.logger.Warn("Scheduler cannot derive assignment entropy",
			"height", blockHeight,
			"error", entropyErr,
		)
		return nil
	}
	if entropyDetails.Source == "legacy-context-fallback" && s.config.RequireDKGBeacon {
		s.logger.Warn("DKG beacon missing; falling back to legacy entropy",
			"height", blockHeight,
		)
	}
	if entropyDetails.Source == "legacy-context-fallback" && s.productionModeDisallowsLegacyEntropy(ctx) {
		s.logger.Error("SECURITY: legacy entropy fallback blocked in production mode",
			"height", blockHeight,
		)
		return nil
	}
	if s.config.RequirePublicDrandPulse && entropyDetails.Source != "drand-public" {
		s.logger.Warn("Drand strict mode expected public pulse source",
			"height", blockHeight,
			"observed_source", entropyDetails.Source,
		)
	}

	// Create a temporary slice to hold jobs we're processing
	var tempJobs []*ScheduledJob

	for s.jobQueue.Len() > 0 && selectedCount < s.config.MaxJobsPerBlock {
		scheduledJob := heap.Pop(s.jobQueue).(*ScheduledJob)

		// Skip jobs that aren't in Pending state (e.g., already Processing from a previous block).
		// The state machine prevents invalid transitions (Processing → Processing).
		if scheduledJob.Job.Status != types.JobStatusPending {
			tempJobs = append(tempJobs, scheduledJob)
			continue
		}

		// Check if job can be assigned to enough validators
		assignedValidators, assignmentProofs := pool.assign(scheduledJob.Job, s.config.MinValidatorsRequired, entropy)
		if len(assignedValidators) >= s.config.MinValidatorsRequired {
			if err := scheduledJob.Job.MarkProcessing(); err != nil {
				// State machine rejected the transition — skip this job
				s.logger.Warn("Failed to transition job to Processing",
					"job_id", scheduledJob.Job.Id,
					"status", scheduledJob.Job.Status,
					"error", err,
				)
				// Release validator slots since assignment failed
				for _, addr := range assignedValidators {
					if cap, ok := s.validatorCapabilities[addr]; ok {
						cap.CurrentJobs--
					}
				}
			} else {
				scheduledJob.AssignedTo = assignedValidators
				scheduledJob.LastAttemptBlock = blockHeight
				scheduledJob.VRFEntropy = hex.EncodeToString(entropy)
				scheduledJob.VRFAssignments = assignmentProofs
				scheduledJob.BeaconSource = entropyDetails.Source
				scheduledJob.BeaconVersion = entropyDetails.BeaconVersion
				scheduledJob.BeaconRound = entropyDetails.BeaconRound
				scheduledJob.BeaconRandomness = entropyDetails.BeaconRandomness
				scheduledJob.BeaconSigHash = entropyDetails.BeaconSigHash

				selectedJobs = append(selectedJobs, scheduledJob.Job)
				selectedCount++

				s.logger.Info("Job selected for processing",
					"job_id", scheduledJob.Job.Id,
					"assigned_validators", len(assignedValidators),
					"effective_priority", scheduledJob.EffectivePriority,
				)

				s.persistSchedulingMetadata(ctx, scheduledJob)
			}
		}

		tempJobs = append(tempJobs, scheduledJob)
	}

	// Put jobs back in queue (they stay until completed or expired)
	for _, job := range tempJobs {
		heap.Push(s.jobQueue, job)
	}

	return selectedJobs
}

// refreshValidatorCapabilities loads validator capabilities from keeper state.
// This keeps the in-memory scheduler aligned with on-chain registrations.
func (s *JobScheduler) refreshValidatorCapabilities(ctx context.Context) {
	if s.keeper == nil {
		return
	}
	caps, err := s.keeper.GetAllValidatorCapabilities(ctx)
	if err != nil {
		return
	}

	updated := make(map[string]*types.ValidatorCapability, len(caps))
	for _, cap := range caps {
		if cap == nil {
			continue
		}
		if !s.keeper.hasMinimumValidatorStake(ctx, cap.Address) {
			continue
		}
		// Preserve current job counters if already tracked
		if existing, ok := s.validatorCapabilities[cap.Address]; ok {
			cap.CurrentJobs = existing.CurrentJobs
		}
		capCopy := *cap
		updated[cap.Address] = &capCopy
	}

	s.validatorCapabilities = updated
}

// GetJobsForValidator returns jobs assigned to a specific validator
func (s *JobScheduler) GetJobsForValidator(ctx context.Context, validatorAddr string) []*types.ComputeJob {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var jobs []*types.ComputeJob

	for _, scheduledJob := range s.jobIndex {
		for _, addr := range scheduledJob.AssignedTo {
			if addr == validatorAddr {
				jobs = append(jobs, scheduledJob.Job)
				break
			}
		}
	}

	return jobs
}

// MarkJobComplete removes a job from the scheduler
func (s *JobScheduler) MarkJobComplete(jobID string) {
	s.markJobComplete(nil, jobID)
}

// MarkJobCompleteWithContext removes a job from the scheduler with a context.
// Completion is already persisted via CompleteJob(), so no additional persistence
// is performed here.
func (s *JobScheduler) MarkJobCompleteWithContext(ctx context.Context, jobID string) {
	s.markJobComplete(ctx, jobID)
}

func (s *JobScheduler) markJobComplete(_ context.Context, jobID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	scheduledJob, exists := s.jobIndex[jobID]
	if !exists {
		return
	}

	// Remove from index
	delete(s.jobIndex, jobID)

	// Remove from queue
	if scheduledJob.index >= 0 && scheduledJob.index < s.jobQueue.Len() {
		heap.Remove(s.jobQueue, scheduledJob.index)
	}

	// Release validator slots
	for _, validatorAddr := range scheduledJob.AssignedTo {
		if cap, ok := s.validatorCapabilities[validatorAddr]; ok {
			cap.CurrentJobs--
		}
	}

	s.logger.Info("Job marked complete", "job_id", jobID)
}

// MarkJobFailed handles a failed job, potentially requeueing it
func (s *JobScheduler) MarkJobFailed(jobID string, errorMsg string) {
	s.markJobFailed(nil, jobID, errorMsg)
}

// MarkJobFailedWithContext handles a failed job with a context for persistence.
func (s *JobScheduler) MarkJobFailedWithContext(ctx context.Context, jobID string, errorMsg string) {
	s.markJobFailed(ctx, jobID, errorMsg)
}

func (s *JobScheduler) markJobFailed(ctx context.Context, jobID string, errorMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	scheduledJob, exists := s.jobIndex[jobID]
	if !exists {
		return
	}

	scheduledJob.RetryCount++

	// Release validator slots
	for _, validatorAddr := range scheduledJob.AssignedTo {
		if cap, ok := s.validatorCapabilities[validatorAddr]; ok {
			cap.CurrentJobs--
		}
	}
	scheduledJob.AssignedTo = nil

	if scheduledJob.RetryCount >= s.config.MaxRetries {
		// Max retries exceeded, remove from scheduler
		delete(s.jobIndex, jobID)
		if scheduledJob.index >= 0 && scheduledJob.index < s.jobQueue.Len() {
			heap.Remove(s.jobQueue, scheduledJob.index)
		}
		_ = scheduledJob.Job.MarkFailed() // state machine: Processing → Failed

		s.persistSchedulingMetadata(ctx, scheduledJob)

		s.logger.Warn("Job failed permanently",
			"job_id", jobID,
			"retry_count", scheduledJob.RetryCount,
			"error", errorMsg,
		)
	} else {
		// Reset to pending for retry (state machine: Processing → Pending)
		_ = scheduledJob.Job.RequeueForRetry()
		// Boost priority for retried jobs
		scheduledJob.EffectivePriority += 10

		// Update heap
		heap.Fix(s.jobQueue, scheduledJob.index)

		s.persistSchedulingMetadata(ctx, scheduledJob)

		s.logger.Info("Job queued for retry",
			"job_id", jobID,
			"retry_count", scheduledJob.RetryCount,
			"new_priority", scheduledJob.EffectivePriority,
		)
	}
}

// RegisterValidator registers or updates a validator's capabilities
func (s *JobScheduler) RegisterValidator(capability *types.ValidatorCapability) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.validatorCapabilities[capability.Address] = capability

	s.logger.Info("Validator registered",
		"address", capability.Address,
		"tee_platforms", capability.TeePlatforms,
		"zkml_systems", capability.ZkmlSystems,
	)
}

// GetValidatorCapabilities returns a copy of all registered validator capabilities.
// Used by the ValidatorSelector to evaluate candidates for job assignment.
func (s *JobScheduler) GetValidatorCapabilities() map[string]*types.ValidatorCapability {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]*types.ValidatorCapability, len(s.validatorCapabilities))
	for addr, cap := range s.validatorCapabilities {
		result[addr] = cap
	}
	return result
}

// UnregisterValidator removes a validator from the scheduler
func (s *JobScheduler) UnregisterValidator(address string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.validatorCapabilities, address)
	s.logger.Info("Validator unregistered", "address", address)
}

// GetQueueStats returns statistics about the job queue
func (s *JobScheduler) GetQueueStats() QueueStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := QueueStats{
		TotalJobs:            s.jobQueue.Len(),
		RegisteredValidators: len(s.validatorCapabilities),
	}

	for _, job := range s.jobIndex {
		switch job.Job.Status {
		case types.JobStatusPending:
			stats.PendingJobs++
		case types.JobStatusProcessing:
			stats.ProcessingJobs++
		}

		switch job.Job.ProofType {
		case types.ProofTypeTEE:
			stats.TEEJobs++
		case types.ProofTypeZKML:
			stats.ZKMLJobs++
		case types.ProofTypeHybrid:
			stats.HybridJobs++
		}
	}

	for _, cap := range s.validatorCapabilities {
		if cap.IsOnline {
			stats.OnlineValidators++
		}
	}

	return stats
}

// QueueStats contains statistics about the job queue
type QueueStats struct {
	TotalJobs            int
	PendingJobs          int
	ProcessingJobs       int
	TEEJobs              int
	ZKMLJobs             int
	HybridJobs           int
	RegisteredValidators int
	OnlineValidators     int
}

// updatePriorities updates effective priorities based on wait time
func (s *JobScheduler) updatePriorities(currentBlock int64) {
	for i := 0; i < s.jobQueue.Len(); i++ {
		job := (*s.jobQueue)[i]
		waitBlocks := currentBlock - job.SubmittedBlock
		job.EffectivePriority = job.Job.Priority + (waitBlocks * s.config.PriorityBoostPerBlock)
	}

	// Rebuild heap with updated priorities
	heap.Init(s.jobQueue)
}

// removeExpiredJobs removes jobs that have timed out
func (s *JobScheduler) removeExpiredJobs(ctx context.Context, currentBlock int64) {
	var expiredIDs []string

	for id, job := range s.jobIndex {
		if currentBlock-job.SubmittedBlock > s.config.JobTimeoutBlocks {
			expiredIDs = append(expiredIDs, id)
		}
	}

	for _, id := range expiredIDs {
		scheduledJob := s.jobIndex[id]
		delete(s.jobIndex, id)

		if scheduledJob.index >= 0 && scheduledJob.index < s.jobQueue.Len() {
			heap.Remove(s.jobQueue, scheduledJob.index)
		}

		_ = scheduledJob.Job.MarkExpired() // state machine: Pending → Expired
		s.persistSchedulingMetadata(ctx, scheduledJob)

		s.logger.Info("Job expired", "job_id", id)
	}
}

// SyncFromChain synchronizes the scheduler with on-chain state
func (s *JobScheduler) SyncFromChain(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get all pending jobs from the keeper
	pendingJobs := s.keeper.GetPendingJobs(ctx)

	for _, job := range pendingJobs {
		if job == nil {
			continue
		}
		if _, exists := s.jobIndex[job.Id]; !exists {
			sdkCtx := sdk.UnwrapSDKContext(ctx)
			retryCount,
				lastAttempt,
				assigned,
				submittedBlock,
				vrfEntropy,
				vrfAssignments,
				beaconSource,
				beaconVersion,
				beaconRound,
				beaconRandomness,
				beaconSigHash := s.loadSchedulingMetadata(job)
			scheduledJob := &ScheduledJob{
				Job:               job,
				EffectivePriority: job.Priority,
				SubmittedBlock:    submittedBlock,
				RetryCount:        retryCount,
				LastAttemptBlock:  lastAttempt,
				AssignedTo:        assigned,
				VRFEntropy:        vrfEntropy,
				VRFAssignments:    vrfAssignments,
				BeaconSource:      beaconSource,
				BeaconVersion:     beaconVersion,
				BeaconRound:       beaconRound,
				BeaconRandomness:  beaconRandomness,
				BeaconSigHash:     beaconSigHash,
			}

			heap.Push(s.jobQueue, scheduledJob)
			s.jobIndex[job.Id] = scheduledJob

			s.logger.Debug("Synced job from chain",
				"job_id", job.Id,
				"block_height", sdkCtx.BlockHeight(),
			)
		}
	}

	return nil
}

// JobPriorityQueue implements heap.Interface for priority-based job scheduling
type JobPriorityQueue []*ScheduledJob

func (pq JobPriorityQueue) Len() int { return len(pq) }

func (pq JobPriorityQueue) Less(i, j int) bool {
	// Higher priority comes first (max heap)
	if pq[i].EffectivePriority != pq[j].EffectivePriority {
		return pq[i].EffectivePriority > pq[j].EffectivePriority
	}
	// Earlier submission comes first (FIFO for same priority)
	return pq[i].SubmittedBlock < pq[j].SubmittedBlock
}

func (pq JobPriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *JobPriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*ScheduledJob)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *JobPriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}

// Update modifies the priority of a job in the queue
func (pq *JobPriorityQueue) Update(job *ScheduledJob, priority int64) {
	job.EffectivePriority = priority
	heap.Fix(pq, job.index)
}
