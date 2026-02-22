package types

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// Job status aliases for readability.
	JobStatusPending    = JobStatus_JOB_STATUS_PENDING
	JobStatusProcessing = JobStatus_JOB_STATUS_PROCESSING
	JobStatusCompleted  = JobStatus_JOB_STATUS_COMPLETED
	JobStatusFailed     = JobStatus_JOB_STATUS_FAILED
	JobStatusExpired    = JobStatus_JOB_STATUS_EXPIRED

	// Proof type aliases for readability.
	ProofTypeTEE    = ProofType_PROOF_TYPE_TEE
	ProofTypeZKML   = ProofType_PROOF_TYPE_ZKML
	ProofTypeHybrid = ProofType_PROOF_TYPE_HYBRID
)

// DefaultJobExpiryBlocks is the default number of blocks before a job expires.
// At ~6s block time, 14400 blocks ≈ 24 hours.
const DefaultJobExpiryBlocks int64 = 14400

// NewComputeJob creates a new compute job.
//
// DEPRECATED: This function should NOT be used in consensus-critical paths.
// Use NewComputeJobWithBlockTime instead, which takes the deterministic block
// time from ctx.BlockTime().
//
// This function is kept for backwards compatibility with tests and tooling
// that run outside of consensus context.
//
// WARNING: Using this function in message handlers or ABCI callbacks will
// cause state divergence because different validators have different clocks.
func NewComputeJob(
	modelHash, inputHash []byte,
	requestedBy string,
	proofType ProofType,
	purpose string,
	fee sdk.Coin,
	blockHeight int64,
) *ComputeJob {
	// SECURITY WARNING: This uses time.Now() which is non-deterministic.
	// Only safe for use in tests and CLI tooling, NOT in consensus code.
	return NewComputeJobWithBlockTime(
		modelHash, inputHash, requestedBy, proofType,
		purpose, fee, blockHeight, time.Now().UTC(),
	)
}

// NewComputeJobWithBlockTime creates a compute job using the given block time
// for all timestamp fields. This is the deterministic constructor that should
// be used in all consensus-critical paths (msg handlers, BeginBlock, EndBlock).
func NewComputeJobWithBlockTime(
	modelHash, inputHash []byte,
	requestedBy string,
	proofType ProofType,
	purpose string,
	fee sdk.Coin,
	blockHeight int64,
	blockTime time.Time,
) *ComputeJob {
	now := timestamppb.New(blockTime)
	// Expiry is block-height-based, stored as ExpiryBlockHeight.
	// ExpiresAt is kept for backwards compatibility but derived from block time.
	expiresAt := timestamppb.New(blockTime.Add(24 * time.Hour))
	feeCopy := fee
	job := &ComputeJob{
		ModelHash:           modelHash,
		InputHash:           inputHash,
		RequestedBy:         requestedBy,
		ProofType:           proofType,
		Purpose:             purpose,
		Status:              JobStatusPending,
		CreatedAt:           now,
		UpdatedAt:           now,
		ExpiresAt:           expiresAt,
		Fee:                 &feeCopy,
		Priority:            0,
		BlockHeight:         blockHeight,
		VerificationResults: make([]*VerificationResult, 0),
		Metadata:            make(map[string]string),
	}

	// Generate unique ID — deterministic because CreatedAt is set from blockTime.
	job.Id = job.GenerateID()

	return job
}

// GenerateID creates a unique identifier for the job.
//
// DETERMINISM: The job ID MUST be identical across all validators for the
// same job. It is derived from (modelHash, inputHash, requestedBy, blockHeight,
// createdAt). Never uses time.Now(); requires CreatedAt to be set first.
func (j *ComputeJob) GenerateID() string {
	h := sha256.New()
	h.Write(j.ModelHash)
	h.Write(j.InputHash)
	h.Write([]byte(j.RequestedBy))

	// Use blockHeight for uniqueness (deterministic across validators)
	heightBytes := fmt.Sprintf("height:%d", j.BlockHeight)
	h.Write([]byte(heightBytes))

	// Include createdAt for within-block uniqueness.
	// CreatedAt MUST be set from block time, not wall-clock.
	if j.CreatedAt != nil {
		h.Write([]byte(j.CreatedAt.AsTime().String()))
	}

	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Validate validates the compute job
func (j *ComputeJob) Validate() error {
	if len(j.Id) == 0 {
		return fmt.Errorf("job ID cannot be empty")
	}
	if len(j.ModelHash) != 32 {
		return fmt.Errorf("model hash must be 32 bytes (SHA-256)")
	}
	if len(j.InputHash) != 32 {
		return fmt.Errorf("input hash must be 32 bytes (SHA-256)")
	}
	if _, err := sdk.AccAddressFromBech32(j.RequestedBy); err != nil {
		return fmt.Errorf("invalid requester address: %w", err)
	}
	if j.ProofType != ProofTypeTEE && j.ProofType != ProofTypeZKML && j.ProofType != ProofTypeHybrid {
		return fmt.Errorf("invalid proof type: %s", j.ProofType)
	}
	if len(j.Purpose) == 0 {
		return fmt.Errorf("purpose cannot be empty")
	}
	return nil
}

// AddVerificationResult adds a verification result from a validator.
// Uses wall-clock time for UpdatedAt (informational, not consensus-critical).
func (j *ComputeJob) AddVerificationResult(result VerificationResult) {
	j.VerificationResults = append(j.VerificationResults, &result)
	j.UpdatedAt = timestamppb.Now()
}

// AddVerificationResultAt adds a verification result using the given block time.
// This is the deterministic version for consensus-critical paths.
func (j *ComputeJob) AddVerificationResultAt(result VerificationResult, blockTime time.Time) {
	j.VerificationResults = append(j.VerificationResults, &result)
	j.UpdatedAt = timestamppb.New(blockTime)
}

// GetConsensusOutput returns the output hash if consensus is reached
func (j *ComputeJob) GetConsensusOutput(requiredVotes int) ([]byte, bool) {
	if len(j.VerificationResults) < requiredVotes {
		return nil, false
	}

	// Count votes for each output hash
	outputVotes := make(map[string]int)
	for _, result := range j.VerificationResults {
		if result == nil {
			continue
		}
		if result.Success {
			key := hex.EncodeToString(result.OutputHash)
			outputVotes[key]++
		}
	}

	// Find output with sufficient votes
	for outputHex, count := range outputVotes {
		if count >= requiredVotes {
			output, _ := hex.DecodeString(outputHex)
			return output, true
		}
	}

	return nil, false
}

// ValidTransitions defines the allowed state transitions for compute jobs.
// Any transition not in this map is REJECTED. This prevents impossible state
// sequences (e.g., Completed → Processing) that would break consensus.
var ValidTransitions = map[JobStatus][]JobStatus{
	JobStatusPending:    {JobStatusProcessing, JobStatusExpired, JobStatusFailed},
	JobStatusProcessing: {JobStatusCompleted, JobStatusFailed, JobStatusPending}, // Pending for retry
	// Terminal states: no outgoing transitions
	JobStatusCompleted: {},
	JobStatusFailed:    {},
	JobStatusExpired:   {},
}

// CanTransitionTo checks if a transition from the current status to the
// target status is valid according to the state machine.
func (j *ComputeJob) CanTransitionTo(target JobStatus) bool {
	allowed, ok := ValidTransitions[j.Status]
	if !ok {
		return false
	}
	for _, s := range allowed {
		if s == target {
			return true
		}
	}
	return false
}

// TransitionTo attempts a state transition, returning an error if the
// transition is invalid. This enforces the state machine at the type level.
func (j *ComputeJob) TransitionTo(target JobStatus) error {
	if !j.CanTransitionTo(target) {
		return fmt.Errorf("invalid state transition: %s → %s", j.Status, target)
	}
	j.Status = target
	j.UpdatedAt = timestamppb.Now()
	return nil
}

// MarkProcessing marks the job as being processed.
// Returns an error if the transition is invalid.
func (j *ComputeJob) MarkProcessing() error {
	return j.TransitionTo(JobStatusProcessing)
}

// MarkCompleted marks the job as completed.
// Returns an error if the transition is invalid.
func (j *ComputeJob) MarkCompleted(outputHash []byte, sealID string) error {
	if err := j.TransitionTo(JobStatusCompleted); err != nil {
		return err
	}
	j.OutputHash = outputHash
	j.SealId = sealID
	now := timestamppb.Now()
	j.CompletedAt = now
	j.UpdatedAt = now
	return nil
}

// MarkFailed marks the job as failed.
// Returns an error if the transition is invalid.
func (j *ComputeJob) MarkFailed() error {
	return j.TransitionTo(JobStatusFailed)
}

// MarkExpired marks the job as expired.
// Returns an error if the transition is invalid.
func (j *ComputeJob) MarkExpired() error {
	return j.TransitionTo(JobStatusExpired)
}

// RequeueForRetry transitions from Processing back to Pending for retry.
// Returns an error if the transition is invalid.
func (j *ComputeJob) RequeueForRetry() error {
	return j.TransitionTo(JobStatusPending)
}

// IsExpired checks if the job has expired.
// DEPRECATED: Use IsExpiredAt(blockTime) for deterministic consensus checks.
func (j *ComputeJob) IsExpired() bool {
	if j.ExpiresAt == nil {
		return false
	}
	return time.Now().After(j.ExpiresAt.AsTime())
}

// IsExpiredAt checks if the job has expired at the given block time.
// This is the deterministic version that should be used in consensus-critical
// paths (BeginBlock, vote extension verification, scheduler).
func (j *ComputeJob) IsExpiredAt(blockTime time.Time) bool {
	if j.ExpiresAt == nil {
		return false
	}
	return blockTime.After(j.ExpiresAt.AsTime())
}

// IsExpiredAtHeight checks if the job has expired based on block height.
// This is the most deterministic expiry check — it compares block heights
// rather than timestamps. Requires BlockHeight to be set at job creation.
func (j *ComputeJob) IsExpiredAtHeight(currentHeight int64) bool {
	return currentHeight-j.BlockHeight > DefaultJobExpiryBlocks
}

// NewRegisteredModel creates a new registered model
func NewRegisteredModel(
	modelHash []byte,
	modelID, name, description, version, architecture string,
	owner string,
) *RegisteredModel {
	return &RegisteredModel{
		ModelHash:    modelHash,
		ModelId:      modelID,
		Name:         name,
		Description:  description,
		Version:      version,
		Architecture: architecture,
		Owner:        owner,
		RegisteredAt: timestamppb.Now(),
		IsActive:     true,
	}
}

// NewValidatorStats creates new validator stats
func NewValidatorStats(validatorAddr string) *ValidatorStats {
	return &ValidatorStats{
		ValidatorAddress:       validatorAddr,
		TotalJobsProcessed:     0,
		SuccessfulJobs:         0,
		FailedJobs:             0,
		AverageExecutionTimeMs: 0,
		LastActiveAt:           timestamppb.Now(),
		TeeCapabilities:        make([]string, 0),
		ZkmlCapabilities:       make([]string, 0),
		ReputationScore:        50, // Start at 50%
		SlashingEvents:         0,
	}
}

// RecordSuccess records a successful verification
func (vs *ValidatorStats) RecordSuccess(executionTimeMs int64) {
	vs.TotalJobsProcessed++
	vs.SuccessfulJobs++
	vs.LastActiveAt = timestamppb.Now()

	// Update average execution time
	total := vs.AverageExecutionTimeMs * (vs.TotalJobsProcessed - 1)
	vs.AverageExecutionTimeMs = (total + executionTimeMs) / vs.TotalJobsProcessed

	// Increase reputation
	if vs.ReputationScore < 100 {
		vs.ReputationScore++
	}
}

// RecordFailure records a failed verification
func (vs *ValidatorStats) RecordFailure() {
	vs.TotalJobsProcessed++
	vs.FailedJobs++
	vs.LastActiveAt = timestamppb.Now()

	// Decrease reputation
	if vs.ReputationScore > 0 {
		vs.ReputationScore -= 5
	}
}

// RecordSlashing records a slashing event
func (vs *ValidatorStats) RecordSlashing() {
	vs.SlashingEvents++
	vs.ReputationScore = vs.ReputationScore / 2 // Halve reputation
}
