package keeper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"cosmossdk.io/log"
	abci "github.com/cometbft/cometbft/abci/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// ConsensusHandler handles the Proof-of-Useful-Work consensus logic
// It integrates with CometBFT's ABCI++ to enable computation verification during consensus.
//
// NOTE: The canonical vote extension types (VoteExtension, ComputeVerification,
// TEEAttestationData, ZKProofData) are defined in app/vote_extension.go.
// This handler uses its own internal wire format (VoteExtensionWire) for
// parsing vote extensions received from the ABCI layer. The ABCI layer in
// app/abci.go handles the authoritative type definitions and serialization.
type ConsensusHandler struct {
	logger    log.Logger
	keeper    *Keeper
	scheduler *JobScheduler
	verifier  JobVerifier

	// Evidence collection for misbehavior detection
	evidenceCollector *EvidenceCollector

	// Configuration
	consensusThreshold int // Percentage required for consensus (e.g., 67 for 2/3)
	maxJobsPerBlock    int
}

// Scheduler returns the job scheduler used by the consensus handler.
// It enables graceful shutdown coordination from the app layer.
func (ch *ConsensusHandler) Scheduler() *JobScheduler {
	if ch == nil {
		return nil
	}
	return ch.scheduler
}

// JobVerifier allows pluggable verification implementations (TEE/zkML).
// In production, this should call real enclave workers and proof verifiers.
type JobVerifier interface {
	VerifyJob(ctx sdk.Context, job *types.ComputeJob, model *types.RegisteredModel, validatorAddr string) (types.VerificationResult, error)
}

// NewConsensusHandler creates a new consensus handler
func NewConsensusHandler(logger log.Logger, keeper *Keeper, scheduler *JobScheduler) *ConsensusHandler {
	return &ConsensusHandler{
		logger:             logger,
		keeper:             keeper,
		scheduler:          scheduler,
		evidenceCollector:  NewEvidenceCollector(logger, keeper),
		consensusThreshold: 0, // Will be read from params dynamically; 0 means "use params"
		maxJobsPerBlock:    10,
	}
}

// getConsensusThreshold returns the consensus threshold from params or default (67%).
// This ensures the threshold is always read from on-chain governance params rather
// than a hardcoded value, while maintaining BFT safety with a minimum of 67%.
func (ch *ConsensusHandler) getConsensusThreshold(ctx sdk.Context) int {
	// If explicitly set (for testing), use that value
	if ch.consensusThreshold > 0 {
		return ch.consensusThreshold
	}

	// Read from on-chain params
	if ch.keeper != nil {
		params, err := ch.keeper.GetParams(ctx)
		if err == nil && params != nil && params.ConsensusThreshold >= 67 {
			return int(params.ConsensusThreshold)
		}
	}

	// Default to BFT-safe 67% if params unavailable or invalid
	return 67
}

// requiredThresholdCount computes ceil(total * threshold / 100) using integer
// math only and caps the requirement at total when threshold <= 100.
func requiredThresholdCount[T ~int | ~int64](total T, threshold int) T {
	if total <= 0 || threshold <= 0 {
		return 0
	}
	if threshold >= 100 {
		return total
	}
	numerator := total*T(threshold) + 99
	required := numerator / 100
	if required > total {
		return total
	}
	return required
}

// SetConsensusThresholdForTesting allows tests to override the threshold.
// SECURITY: This should NEVER be used in production - only for testing.
func (ch *ConsensusHandler) SetConsensusThresholdForTesting(threshold int) {
	ch.consensusThreshold = threshold
}

// SetVerifier injects a verifier implementation for production use.
func (ch *ConsensusHandler) SetVerifier(verifier JobVerifier) {
	ch.verifier = verifier
}

// GetEvidenceCollector returns the handler's evidence collector for use by
// the ABCI layer or tests. Returns nil if the handler was created without
// a keeper (which means the evidence collector is also nil).
func (ch *ConsensusHandler) GetEvidenceCollector() *EvidenceCollector {
	return ch.evidenceCollector
}

// VoteExtensionWire is the wire format for deserializing vote extensions
// received from the ABCI layer. This mirrors the canonical VoteExtension
// type in app/vote_extension.go to avoid circular imports.
type VoteExtensionWire struct {
	Version          int32              `json:"version"`
	Height           int64              `json:"height"`
	ValidatorAddress json.RawMessage    `json:"validator_address"`
	Verifications    []VerificationWire `json:"verifications"`
	Timestamp        time.Time          `json:"timestamp"`
	Signature        json.RawMessage    `json:"signature"`
	ExtensionHash    json.RawMessage    `json:"extension_hash"`
}

// VerificationWire is the wire format for a single verification result.
// Mirrors ComputeVerification from app/vote_extension.go.
type VerificationWire struct {
	JobID           string          `json:"job_id"`
	ModelHash       []byte          `json:"model_hash"`
	InputHash       []byte          `json:"input_hash"`
	OutputHash      []byte          `json:"output_hash"`
	AttestationType string          `json:"attestation_type"`
	TEEAttestation  json.RawMessage `json:"tee_attestation,omitempty"`
	ZKProof         json.RawMessage `json:"zk_proof,omitempty"`
	ExecutionTimeMs int64           `json:"execution_time_ms"`
	Success         bool            `json:"success"`
	ErrorCode       string          `json:"error_code,omitempty"`
	ErrorMessage    string          `json:"error_message,omitempty"`
	Nonce           []byte          `json:"nonce"`
}

// AggregatedResult represents consensus results for a job.
// This is the keeper's output format, consumed by the ABCI layer.
type AggregatedResult struct {
	JobID            string
	ModelHash        []byte
	InputHash        []byte
	OutputHash       []byte
	ValidatorResults []ValidatorResult
	TotalVotes       int
	TotalPower       int64
	AgreementCount   int
	AgreementPower   int64
	HasConsensus     bool
}

// ValidatorResult represents a single validator's result
type ValidatorResult struct {
	ValidatorAddress string
	OutputHash       []byte
	AttestationType  string
	TEEPlatform      string
	AttestationQuote []byte
	ZKProof          []byte
	ExecutionTimeMs  int64
	Timestamp        time.Time
}

// PrepareVoteExtension creates verification data for the current validator.
// Returns raw verification results that the ABCI layer wraps into a VoteExtension.
func (ch *ConsensusHandler) PrepareVoteExtension(ctx sdk.Context, validatorAddr string) ([]types.VerificationResult, error) {
	// Get jobs assigned to this validator
	jobs := ch.scheduler.GetJobsForValidator(ctx, validatorAddr)
	if len(jobs) == 0 {
		return nil, nil
	}

	// Execute verifications for each job
	var results []types.VerificationResult
	for _, job := range jobs {
		result := ch.executeVerification(ctx, job, validatorAddr)
		results = append(results, result)
	}

	return results, nil
}

// executeVerification executes a single compute job verification
func (ch *ConsensusHandler) executeVerification(ctx sdk.Context, job *types.ComputeJob, validatorAddr string) types.VerificationResult {
	startTime := time.Now()

	result := types.VerificationResult{
		ValidatorAddress: validatorAddr,
		Success:          false,
		Timestamp:        timestamppb.Now(),
	}

	// Get registered model to verify against
	model, err := ch.keeper.GetRegisteredModel(ctx, job.ModelHash)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("model not found: %s", err)
		result.ExecutionTimeMs = time.Since(startTime).Milliseconds()
		return result
	}

	// If a real verifier is configured, use it
	if ch.verifier != nil {
		verified, vErr := ch.verifier.VerifyJob(ctx, job, model, validatorAddr)
		if vErr != nil {
			result.ErrorMessage = vErr.Error()
			result.ExecutionTimeMs = time.Since(startTime).Milliseconds()
			return result
		}
		verified.ExecutionTimeMs = time.Since(startTime).Milliseconds()
		return verified
	}

	// ================================================================
	// SIMULATION GUARD: Only testnet/devnet may reach this code path.
	// In production, ch.verifier MUST be set. If AllowSimulated is
	// false (the default), this path returns an error.
	// ================================================================
	params, _ := ch.keeper.GetParams(ctx)
	if params == nil || !params.AllowSimulated {
		result.ErrorMessage = "SECURITY: no verifier configured and AllowSimulated=false; " +
			"set a real JobVerifier via ConsensusHandler.SetVerifier() " +
			"or enable AllowSimulated in genesis for testnet only"
		result.ExecutionTimeMs = time.Since(startTime).Milliseconds()
		ch.logger.Error("Verification blocked: no real verifier and simulation disabled",
			"job_id", job.Id,
			"validator", validatorAddr,
		)
		return result
	}

	ch.logger.Warn("SIMULATED verification — NOT FOR PRODUCTION",
		"job_id", job.Id,
		"validator", validatorAddr,
		"proof_type", job.ProofType,
	)

	// Execute verification based on proof type (SIMULATED)
	switch job.ProofType {
	case types.ProofTypeTEE:
		result.AttestationType = "tee"
		ch.executeTEEVerification(ctx, job, model, &result)

	case types.ProofTypeZKML:
		result.AttestationType = "zkml"
		ch.executeZKMLVerification(ctx, job, model, &result)

	case types.ProofTypeHybrid:
		result.AttestationType = "hybrid"
		ch.executeHybridVerification(ctx, job, model, &result)

	default:
		result.ErrorMessage = fmt.Sprintf("unknown proof type: %s", job.ProofType)
	}

	result.ExecutionTimeMs = time.Since(startTime).Milliseconds()

	ch.logger.Info("Verification executed",
		"job_id", job.Id,
		"validator", validatorAddr,
		"success", result.Success,
		"execution_time_ms", result.ExecutionTimeMs,
		"attestation_type", result.AttestationType,
	)

	return result
}

// executeTEEVerification performs SIMULATED TEE-based verification.
// WARNING: This function produces deterministic fake attestations.
// Production validators MUST use ConsensusHandler.SetVerifier() with a
// real JobVerifier that communicates with a TEE enclave.
// This code path is only reachable when AllowSimulated=true in module params.
func (ch *ConsensusHandler) executeTEEVerification(ctx sdk.Context, job *types.ComputeJob, model *types.RegisteredModel, result *types.VerificationResult) {
	outputHash := computeDeterministicOutput(job.ModelHash, job.InputHash)

	// Generate attestation data
	quote := generateAttestationQuote(outputHash, model.TeeMeasurement)

	result.OutputHash = outputHash
	result.TeePlatform = "aws-nitro"
	result.AttestationData = quote
	result.Success = true
}

// executeZKMLVerification performs SIMULATED zkML-based verification.
// WARNING: This function produces fake proofs. See executeTEEVerification doc.
func (ch *ConsensusHandler) executeZKMLVerification(ctx sdk.Context, job *types.ComputeJob, model *types.RegisteredModel, result *types.VerificationResult) {
	// Compute deterministic output
	outputHash := computeDeterministicOutput(job.ModelHash, job.InputHash)

	// Generate simulated zkML proof
	zkProof := generateZKProof(job.ModelHash, job.InputHash, outputHash, model.CircuitHash)

	result.OutputHash = outputHash
	result.AttestationData = zkProof
	result.Success = true
}

// executeHybridVerification performs SIMULATED hybrid verification.
// WARNING: This function produces fake attestations and proofs. See executeTEEVerification doc.
func (ch *ConsensusHandler) executeHybridVerification(ctx sdk.Context, job *types.ComputeJob, model *types.RegisteredModel, result *types.VerificationResult) {
	// Execute TEE first
	ch.executeTEEVerification(ctx, job, model, result)

	if result.Success {
		// Also generate zkML proof (stored alongside TEE attestation)
		zkProof := generateZKProof(job.ModelHash, job.InputHash, result.OutputHash, model.CircuitHash)
		// Append zkML proof after TEE attestation data, separated by marker
		result.AttestationData = append(result.AttestationData, []byte("|ZKML|")...)
		result.AttestationData = append(result.AttestationData, zkProof...)
	}
}

// computeDeterministicOutput generates a deterministic output hash.
// All validators must produce the same output for the same input.
func computeDeterministicOutput(modelHash, inputHash []byte) []byte {
	combined := make([]byte, 0, len(modelHash)+len(inputHash)+len("aethelred_compute_v1"))
	combined = append(combined, modelHash...)
	combined = append(combined, inputHash...)
	combined = append(combined, []byte("aethelred_compute_v1")...)
	return sha256Hash(combined)
}

// generateAttestationQuote generates a SIMULATED attestation quote (testnet only).
func generateAttestationQuote(outputHash, measurement []byte) []byte {
	data := make([]byte, 0, len("NITRO_QUOTE_V1:")+len(measurement)+len(outputHash))
	data = append(data, []byte("NITRO_QUOTE_V1:")...)
	data = append(data, measurement...)
	data = append(data, outputHash...)
	return sha256Hash(data)
}

// generateZKProof generates a SIMULATED zkML proof (testnet only).
func generateZKProof(modelHash, inputHash, outputHash, circuitHash []byte) []byte {
	data := make([]byte, 0, len("EZKL_PROOF_V1:")+len(modelHash)+len(inputHash)+len(outputHash)+len(circuitHash))
	data = append(data, []byte("EZKL_PROOF_V1:")...)
	data = append(data, modelHash...)
	data = append(data, inputHash...)
	data = append(data, outputHash...)
	if circuitHash != nil {
		data = append(data, circuitHash...)
	}
	return sha256Hash(data)
}

// VerifyVoteExtension validates a vote extension from another validator.
// In production mode (AllowSimulated=false), this applies strict validation
// that rejects simulated TEE platforms and enforces signature presence.
func (ch *ConsensusHandler) VerifyVoteExtension(ctx sdk.Context, extensionBytes []byte) error {
	var extension VoteExtensionWire
	if err := json.Unmarshal(extensionBytes, &extension); err != nil {
		return fmt.Errorf("failed to unmarshal vote extension: %w", err)
	}

	// Check version
	if extension.Version != 1 {
		return fmt.Errorf("unsupported vote extension version: %d", extension.Version)
	}

	// Check height matches
	if extension.Height != ctx.BlockHeight() {
		return fmt.Errorf("vote extension height mismatch: expected %d, got %d", ctx.BlockHeight(), extension.Height)
	}

	// SECURITY FIX (P1): Use deterministic block time instead of time.Now()
	// This ensures all validators make the same acceptance decision.
	// We allow a 1-minute window after block time to account for propagation delays.
	blockTime := ctx.BlockTime()
	if extension.Timestamp.After(blockTime.Add(time.Minute)) {
		return fmt.Errorf("vote extension timestamp is in the future (extension: %v, block: %v)",
			extension.Timestamp.Format(time.RFC3339), blockTime.Format(time.RFC3339))
	}

	// Determine if we're in production mode.
	// If the keeper is nil (e.g. in tests), default to production mode (fail-closed).
	isProduction := true
	if ch.keeper != nil {
		params, _ := ch.keeper.GetParams(ctx)
		isProduction = params == nil || !params.AllowSimulated
	}

	// ── Production guard: require signature ──
	if isProduction && isNullOrEmpty(extension.Signature) {
		return fmt.Errorf("SECURITY: unsigned vote extension rejected in production mode")
	}

	// ── Production guard: require extension hash ──
	if isProduction && isNullOrEmpty(extension.ExtensionHash) {
		return fmt.Errorf("SECURITY: missing extension hash in production mode")
	}

	// Validate each verification
	for i, v := range extension.Verifications {
		if err := ch.validateVerificationWireWithCtx(&ctx, &v); err != nil {
			return fmt.Errorf("invalid verification at index %d: %w", i, err)
		}

		// Production: reject simulated TEE at the keeper level too
		if isProduction && v.AttestationType == "tee" {
			if err := ch.validateTEEAttestationWireStrict(ctx, &v); err != nil {
				return fmt.Errorf("verification %d TEE rejected in production: %w", i, err)
			}
		}
		if isProduction && v.AttestationType == "hybrid" {
			if err := ch.validateTEEAttestationWireStrict(ctx, &v); err != nil {
				return fmt.Errorf("verification %d hybrid TEE rejected in production: %w", i, err)
			}
		}

		// Verify the job exists on-chain (prevent phantom job votes)
		if v.Success && ch.keeper != nil {
			_, err := ch.keeper.GetJob(ctx, v.JobID)
			if err != nil {
				return fmt.Errorf("verification %d references unknown job %s", i, v.JobID)
			}
		}
	}

	return nil
}

// TEEAttestationWire is the wire format for TEE attestation data inside a verification.
type TEEAttestationWire struct {
	Platform    string    `json:"platform"`
	EnclaveID   string    `json:"enclave_id"`
	Measurement []byte    `json:"measurement"`
	Quote       []byte    `json:"quote"`
	UserData    []byte    `json:"user_data"`
	Timestamp   time.Time `json:"timestamp"`
	Nonce       []byte    `json:"nonce"`
}

// ZKProofWire is the wire format for ZK proof data inside a verification.
type ZKProofWire struct {
	ProofSystem      string `json:"proof_system"`
	Proof            []byte `json:"proof"`
	PublicInputs     []byte `json:"public_inputs"`
	VerifyingKeyHash []byte `json:"verifying_key_hash"`
	CircuitHash      []byte `json:"circuit_hash"`
	ProofSize        int64  `json:"proof_size"`
}

// validateVerificationWire validates a single verification result from wire format.
// This now goes beyond presence checks and validates the structural integrity
// of attestations and proofs before they are counted toward consensus.
func (ch *ConsensusHandler) validateVerificationWire(v *VerificationWire) error {
	return ch.validateVerificationWireWithCtx(nil, v)
}

// validateVerificationWireWithCtx validates a single verification result from wire format.
// When ctxPtr is provided, deterministic block-time checks are enforced.
func (ch *ConsensusHandler) validateVerificationWireWithCtx(ctxPtr *sdk.Context, v *VerificationWire) error {
	if len(v.JobID) == 0 {
		return fmt.Errorf("missing job ID")
	}

	// Verify the job exists on-chain (prevent phantom job votes)
	// NOTE: ctx is not available here; this check is deferred to VerifyVoteExtension caller.

	if v.Success {
		if len(v.OutputHash) != 32 {
			return fmt.Errorf("successful verification must have 32-byte output hash")
		}

		// Model hash and input hash must be present for successful verifications
		if len(v.ModelHash) != 32 {
			return fmt.Errorf("successful verification must have 32-byte model hash")
		}

		// Nonce is required for replay protection
		if len(v.Nonce) == 0 {
			return fmt.Errorf("missing nonce for replay protection")
		}
		if len(v.Nonce) != 32 {
			return fmt.Errorf("nonce must be 32 bytes, got %d", len(v.Nonce))
		}

		// Execution time must be positive
		if v.ExecutionTimeMs <= 0 {
			return fmt.Errorf("execution time must be positive for successful verification")
		}

		// Validate attestation based on type — parse and structurally verify
		switch v.AttestationType {
		case "tee":
			if err := ch.validateTEEAttestationWireWithCtx(ctxPtr, v); err != nil {
				return fmt.Errorf("TEE attestation invalid: %w", err)
			}
		case "zkml":
			if err := ch.validateZKProofWire(v); err != nil {
				return fmt.Errorf("zkML proof invalid: %w", err)
			}
		case "hybrid":
			if err := ch.validateTEEAttestationWireWithCtx(ctxPtr, v); err != nil {
				return fmt.Errorf("hybrid TEE part invalid: %w", err)
			}
			if err := ch.validateZKProofWire(v); err != nil {
				return fmt.Errorf("hybrid zkML part invalid: %w", err)
			}
		default:
			return fmt.Errorf("unknown attestation type: %s", v.AttestationType)
		}
	}

	return nil
}

// validateTEEAttestationWire parses and validates the TEE attestation payload.
func (ch *ConsensusHandler) validateTEEAttestationWire(v *VerificationWire) error {
	return ch.validateTEEAttestationWireWithCtx(nil, v)
}

// validateTEEAttestationWireStrict parses and validates the TEE attestation
// using production-mode rules (rejects simulated platform when AllowSimulated=false).
func (ch *ConsensusHandler) validateTEEAttestationWireStrict(ctx sdk.Context, v *VerificationWire) error {
	return ch.validateTEEAttestationWireWithCtx(&ctx, v)
}

// validateTEEAttestationWireWithCtx is the internal implementation.
// When ctxPtr is non-nil, production-mode checks apply (reject simulated TEE).
func (ch *ConsensusHandler) validateTEEAttestationWireWithCtx(ctxPtr *sdk.Context, v *VerificationWire) error {
	if len(v.TEEAttestation) == 0 {
		return fmt.Errorf("missing TEE attestation data")
	}

	var attestation TEEAttestationWire
	if err := json.Unmarshal(v.TEEAttestation, &attestation); err != nil {
		return fmt.Errorf("failed to parse TEE attestation: %w", err)
	}

	// Validate platform
	validPlatforms := map[string]bool{
		"aws-nitro": true, "intel-sgx": true, "intel-tdx": true,
		"amd-sev": true, "arm-trustzone": true, "simulated": true,
	}
	if !validPlatforms[attestation.Platform] {
		return fmt.Errorf("unknown TEE platform: %s", attestation.Platform)
	}

	// ── Production guard: reject simulated TEE platform ──
	if ctxPtr != nil && attestation.Platform == "simulated" {
		// Default: reject (fail-closed)
		allowSimulated := false
		if ch.keeper != nil {
			params, _ := ch.keeper.GetParams(*ctxPtr)
			if params != nil {
				allowSimulated = params.AllowSimulated
			}
		}
		if !allowSimulated {
			return fmt.Errorf("SECURITY: simulated TEE platform rejected in production mode")
		}
	}

	// Measurement must match the model (checked at a higher level,
	// but must at least be present and non-empty)
	if len(attestation.Measurement) == 0 {
		return fmt.Errorf("missing enclave measurement")
	}

	// Enforce global trusted-measurement registry membership for supported
	// hardware attestation formats.
	if ctxPtr != nil && ch.keeper != nil {
		var (
			isRegistered   bool
			measurementHex string
			err            error
		)
		switch attestation.Platform {
		case "aws-nitro":
			isRegistered, measurementHex, err = ch.keeper.IsRegisteredMeasurement(
				*ctxPtr,
				"aws-nitro",
				attestation.Measurement,
			)
		case "intel-sgx":
			isRegistered, measurementHex, err = ch.keeper.IsRegisteredMeasurement(
				*ctxPtr,
				"intel-sgx",
				attestation.Measurement,
			)
		}
		if err != nil {
			return fmt.Errorf("failed TEE measurement registry lookup: %w", err)
		}
		if (attestation.Platform == "aws-nitro" || attestation.Platform == "intel-sgx") && !isRegistered {
			return fmt.Errorf("unregistered %s measurement: %s", attestation.Platform, measurementHex)
		}
	}

	// Quote must be present and meet minimum size
	if len(attestation.Quote) < 64 {
		return fmt.Errorf("attestation quote too short: %d bytes (minimum 64)", len(attestation.Quote))
	}

	// UserData should bind the attestation to the output
	if len(attestation.UserData) == 0 {
		return fmt.Errorf("TEE attestation missing user data binding")
	}

	// Cross-check: user data must contain the output hash
	if !bytes.Equal(attestation.UserData, v.OutputHash) {
		return fmt.Errorf("TEE attestation user data does not match output hash")
	}

	// Nonce must be present for freshness
	if len(attestation.Nonce) == 0 {
		return fmt.Errorf("TEE attestation missing nonce")
	}

	// Timestamp freshness.
	// Consensus paths must be deterministic and anchored to block time.
	if attestation.Timestamp.IsZero() {
		return fmt.Errorf("TEE attestation missing timestamp")
	}
	const maxAttestationAge = 10 * time.Minute
	const maxFutureSkew = 1 * time.Minute

	if ctxPtr != nil {
		blockTime := ctxPtr.BlockTime()
		if blockTime.IsZero() {
			return fmt.Errorf("missing block time for deterministic attestation freshness check")
		}
		if attestation.Timestamp.After(blockTime.Add(maxFutureSkew)) {
			return fmt.Errorf("TEE attestation timestamp is too far in the future")
		}
		if attestation.Timestamp.Before(blockTime.Add(-maxAttestationAge)) {
			return fmt.Errorf("TEE attestation is stale (>10 minutes old by block time)")
		}
	} else {
		// No block context: skip freshness enforcement to avoid non-deterministic
		// wall-clock checks in shared validation paths.
	}

	return nil
}

// validateZKProofWire parses and validates the ZK proof payload.
func (ch *ConsensusHandler) validateZKProofWire(v *VerificationWire) error {
	if len(v.ZKProof) == 0 {
		return fmt.Errorf("missing zkML proof data")
	}

	var proof ZKProofWire
	if err := json.Unmarshal(v.ZKProof, &proof); err != nil {
		return fmt.Errorf("failed to parse zkML proof: %w", err)
	}

	// Validate proof system
	validSystems := map[string]bool{
		"ezkl": true, "risc0": true, "plonky2": true, "halo2": true,
	}
	if !validSystems[proof.ProofSystem] {
		return fmt.Errorf("unknown proof system: %s", proof.ProofSystem)
	}

	// Proof must meet minimum size
	if len(proof.Proof) < 128 {
		return fmt.Errorf("proof data too short: %d bytes (minimum 128)", len(proof.Proof))
	}

	// Verifying key hash must be present
	if len(proof.VerifyingKeyHash) != 32 {
		return fmt.Errorf("verifying key hash must be 32 bytes")
	}

	// Public inputs must be present (contains model_hash, input_hash, output binding)
	if len(proof.PublicInputs) == 0 {
		return fmt.Errorf("missing public inputs in zkML proof")
	}

	return nil
}

// AggregateVoteExtensions combines vote extensions from all validators
// and determines consensus on computation results
func (ch *ConsensusHandler) AggregateVoteExtensions(ctx sdk.Context, votes []abci.ExtendedVoteInfo) map[string]*AggregatedResult {
	start := time.Now()
	aggregated := make(map[string]*AggregatedResult)
	outputVotes := make(map[string]map[string][]ValidatorResult) // jobID -> outputHashHex -> results
	outputPower := make(map[string]map[string]int64)             // jobID -> outputHashHex -> power

	totalVotes := len(votes)
	totalPower := int64(0)
	for _, vote := range votes {
		totalPower += vote.Validator.Power
	}

	// SECURITY FIX (P2): Only allow voting power fallback in simulated/test mode.
	// In production (AllowSimulated=false), zero voting power indicates misconfiguration
	// and should fail closed rather than silently proceeding with equal-weight votes.
	useFallbackPower := false
	if totalPower == 0 && totalVotes > 0 {
		// Check if we're in production mode
		allowSimulated := false
		if ch.keeper != nil {
			if params, err := ch.keeper.GetParams(ctx); err == nil && params != nil {
				allowSimulated = params.AllowSimulated
			}
		}

		if allowSimulated {
			// Dev/test mode: allow fallback to 1 power per vote
			totalPower = int64(totalVotes)
			useFallbackPower = true
			ch.logger.Warn("Total voting power is zero; falling back to 1 power per vote (allowed in simulated mode)",
				"total_votes", totalVotes,
			)
		} else {
			// Production mode: fail closed - this is a configuration error
			ch.logger.Error("SECURITY: Total voting power is zero in production mode - this indicates misconfiguration",
				"total_votes", totalVotes,
			)
			// Return empty results - no consensus possible with zero power
			return aggregated
		}
	}

	// Get consensus threshold from on-chain params (BFT-safe, minimum 67%)
	consensusThreshold := ch.getConsensusThreshold(ctx)
	requiredPower := requiredThresholdCount(totalPower, consensusThreshold)

	for _, vote := range votes {
		if len(vote.VoteExtension) == 0 {
			continue
		}

		votePower := vote.Validator.Power
		if useFallbackPower {
			votePower = 1
		}

		// Parse vote extension from wire format
		var extension VoteExtensionWire
		if err := json.Unmarshal(vote.VoteExtension, &extension); err != nil {
			ch.logger.Warn("Failed to unmarshal vote extension", "error", err)
			continue
		}

		// Extract validator address once per vote extension.
		var validatorAddr string
		if err := json.Unmarshal(extension.ValidatorAddress, &validatorAddr); err != nil || validatorAddr == "" {
			ch.logger.Warn("Invalid validator address in vote extension",
				"error", err,
			)
			continue
		}

		// SECURITY FIX (P2): Cross-check extension address against consensus validator identity.
		// A malicious validator could submit a mismatched address to mis-attribute votes.
		// We use the consensus validator address (from vote.Validator.Address) as the authoritative source.
		if len(vote.Validator.Address) > 0 {
			var extensionAddrBytes []byte
			if err := json.Unmarshal(extension.ValidatorAddress, &extensionAddrBytes); err != nil || len(extensionAddrBytes) == 0 {
				ch.logger.Warn("Failed to decode validator address bytes in vote extension",
					"error", err,
				)
				continue
			}
			if !bytes.Equal(extensionAddrBytes, vote.Validator.Address) {
				ch.logger.Warn("Vote extension validator address mismatch",
					"extension_addr", validatorAddr,
				)
				continue
			}
		}

		// Process each verification
		for _, v := range extension.Verifications {
			if !v.Success {
				continue
			}

			if ch.keeper != nil && len(v.TEEAttestation) > 0 && (v.AttestationType == "tee" || v.AttestationType == "hybrid") {
				var attestation TEEAttestationWire
				if err := json.Unmarshal(v.TEEAttestation, &attestation); err != nil {
					ch.logger.Warn("Skipping verification due to malformed TEE attestation payload",
						"job_id", v.JobID,
						"validator", validatorAddr,
						"error", err,
					)
					continue
				}

				if attestation.Platform == "aws-nitro" || attestation.Platform == "intel-sgx" {
					if err := ch.keeper.ValidateTEEAttestationMeasurement(
						ctx,
						validatorAddr,
						attestation.Platform,
						attestation.Measurement,
					); err != nil {
						ch.logger.Warn("Rejected verification due to untrusted TEE measurement",
							"job_id", v.JobID,
							"validator", validatorAddr,
							"platform", attestation.Platform,
							"error", err,
						)
						ch.keeper.slashUntrustedAttestationValidator(ctx, validatorAddr, v.JobID, err.Error())
						continue
					}
				}
			}

			outputHashHex := hex.EncodeToString(v.OutputHash)

			// Initialize maps
			if outputVotes[v.JobID] == nil {
				outputVotes[v.JobID] = make(map[string][]ValidatorResult)
			}
			if outputPower[v.JobID] == nil {
				outputPower[v.JobID] = make(map[string]int64)
			}

			// Create validator result
			valResult := ValidatorResult{
				ValidatorAddress: validatorAddr,
				OutputHash:       v.OutputHash,
				AttestationType:  v.AttestationType,
				ExecutionTimeMs:  v.ExecutionTimeMs,
				Timestamp:        extension.Timestamp,
			}

			outputVotes[v.JobID][outputHashHex] = append(outputVotes[v.JobID][outputHashHex], valResult)
			outputPower[v.JobID][outputHashHex] += votePower

			// Initialize aggregated result
			if aggregated[v.JobID] == nil {
				aggregated[v.JobID] = &AggregatedResult{
					JobID:            v.JobID,
					ModelHash:        v.ModelHash,
					InputHash:        v.InputHash,
					TotalVotes:       totalVotes,
					TotalPower:       totalPower,
					ValidatorResults: make([]ValidatorResult, 0),
				}
			}
		}
	}

	// Determine consensus for each job
	hasConsensus := false
	for jobID, outputs := range outputVotes {
		agg := aggregated[jobID]

		for outputHashHex, results := range outputs {
			agreementPower := outputPower[jobID][outputHashHex]
			if agreementPower >= requiredPower {
				outputHash, err := hex.DecodeString(outputHashHex)
				if err != nil {
					ch.logger.Error("Failed to decode output hash - skipping",
						"job_id", jobID,
						"output_hash_hex", outputHashHex,
						"error", err,
					)
					continue
				}
				agg.OutputHash = outputHash
				agg.ValidatorResults = results
				agg.AgreementCount = len(results)
				agg.AgreementPower = agreementPower
				agg.HasConsensus = true
				hasConsensus = true

				ch.logger.Info("Consensus reached for job",
					"job_id", jobID,
					"validators_agreed", len(results),
					"agreement_power", agreementPower,
					"total_votes", totalVotes,
					"total_power", totalPower,
					"output_hash", outputHashHex[:16],
				)
				if ch.keeper != nil && ch.keeper.auditLogger != nil {
					ch.keeper.auditLogger.AuditConsensusReached(ctx, jobID, len(results), totalVotes)
				}
				break
			}
		}
	}

	if ch.keeper != nil && ch.keeper.metrics != nil {
		ch.keeper.metrics.RecordConsensus(time.Since(start), hasConsensus)
	}

	// ── Misbehavior detection ──
	// After consensus is determined, scan vote extensions for evidence of
	// invalid outputs, double-signing, and collusion.
	if ch.evidenceCollector != nil {
		// Reconstruct full VoteExtensionWire list for evidence analysis
		var allExtensions []VoteExtensionWire
		for _, vote := range votes {
			if len(vote.VoteExtension) == 0 {
				continue
			}
			var ext VoteExtensionWire
			if err := json.Unmarshal(vote.VoteExtension, &ext); err == nil {
				allExtensions = append(allExtensions, ext)
			}
		}

		evidence := ch.evidenceCollector.CollectEvidenceFromConsensus(ctx, aggregated, allExtensions)
		if len(evidence) > 0 {
			ch.logger.Warn("Misbehavior evidence collected during aggregation",
				"evidence_count", len(evidence),
				"height", ctx.BlockHeight(),
			)
			if ch.keeper != nil && ch.keeper.auditLogger != nil {
				for _, record := range evidence {
					ch.keeper.auditLogger.AuditEvidenceDetected(ctx, record.ValidatorAddress, record.Condition, record.DetectedBy, record.JobID)
				}
			}

			// Apply economic penalties for detected misbehavior.
			if ch.keeper != nil {
				slashErrs := ch.evidenceCollector.ApplySlashingPenalties(ctx, evidence)
				for i, err := range slashErrs {
					if err != nil {
						ch.logger.Warn("Failed to apply slashing penalty",
							"validator", evidence[i].ValidatorAddress,
							"condition", evidence[i].Condition,
							"error", err,
						)
					}
				}
			}
		}
	}

	return aggregated
}

// SealCreationTx represents a transaction to create a Digital Seal
type SealCreationTx struct {
	Type             string            `json:"type"`
	JobID            string            `json:"job_id"`
	ModelHash        []byte            `json:"model_hash"`
	InputHash        []byte            `json:"input_hash"`
	OutputHash       []byte            `json:"output_hash"`
	ValidatorCount   int               `json:"validator_count"`
	TotalVotes       int               `json:"total_votes"`
	AgreementPower   int64             `json:"agreement_power"`
	TotalPower       int64             `json:"total_power"`
	ValidatorResults []ValidatorResult `json:"validator_results"`
	BlockHeight      int64             `json:"block_height"`
	Timestamp        time.Time         `json:"timestamp"`
}

// CreateSealTransactions creates transactions for jobs that reached consensus
func (ch *ConsensusHandler) CreateSealTransactions(ctx sdk.Context, results map[string]*AggregatedResult) [][]byte {
	var txs [][]byte

	for _, result := range results {
		if !result.HasConsensus {
			continue
		}

		// SECURITY FIX: Use deterministic block time instead of time.Now()
		// This ensures all validators create identical seal transactions.
		sealTx := SealCreationTx{
			Type:             "create_seal_from_consensus",
			JobID:            result.JobID,
			ModelHash:        result.ModelHash,
			InputHash:        result.InputHash,
			OutputHash:       result.OutputHash,
			ValidatorCount:   result.AgreementCount,
			TotalVotes:       result.TotalVotes,
			AgreementPower:   result.AgreementPower,
			TotalPower:       result.TotalPower,
			ValidatorResults: result.ValidatorResults,
			BlockHeight:      ctx.BlockHeight(),
			Timestamp:        ctx.BlockTime().UTC(),
		}

		txBytes, err := json.Marshal(sealTx)
		if err != nil {
			ch.logger.Error("Failed to marshal seal transaction", "error", err)
			continue
		}

		txs = append(txs, txBytes)

		ch.logger.Info("Seal transaction created",
			"job_id", result.JobID,
			"validator_count", result.AgreementCount,
		)
	}

	return txs
}

// ValidateSealTransaction validates a seal creation transaction
func (ch *ConsensusHandler) ValidateSealTransaction(ctx sdk.Context, txBytes []byte) error {
	var sealTx SealCreationTx
	if err := json.Unmarshal(txBytes, &sealTx); err != nil {
		return fmt.Errorf("failed to unmarshal seal transaction: %w", err)
	}

	if sealTx.Type != "create_seal_from_consensus" {
		return fmt.Errorf("invalid seal transaction type: %s", sealTx.Type)
	}

	if len(sealTx.JobID) == 0 {
		return fmt.Errorf("missing job ID")
	}

	if len(sealTx.OutputHash) != 32 {
		return fmt.Errorf("invalid output hash length")
	}

	// Validate job exists
	job, err := ch.keeper.GetJob(ctx, sealTx.JobID)
	if err != nil {
		return fmt.Errorf("job not found: %s", sealTx.JobID)
	}

	// Validate model and input hashes match
	if !bytes.Equal(job.ModelHash, sealTx.ModelHash) {
		return fmt.Errorf("model hash mismatch")
	}

	if !bytes.Equal(job.InputHash, sealTx.InputHash) {
		return fmt.Errorf("input hash mismatch")
	}

	// Validate consensus threshold was met (voting power preferred).
	// Get threshold from on-chain params (BFT-safe, minimum 67%)
	consensusThreshold := ch.getConsensusThreshold(ctx)
	if sealTx.TotalPower > 0 {
		requiredPower := requiredThresholdCount(sealTx.TotalPower, consensusThreshold)
		if sealTx.AgreementPower < requiredPower {
			return fmt.Errorf("insufficient validator power: got %d, need %d", sealTx.AgreementPower, requiredPower)
		}
	} else {
		requiredVotes := requiredThresholdCount(sealTx.TotalVotes, consensusThreshold)
		if sealTx.ValidatorCount < requiredVotes {
			return fmt.Errorf("insufficient validator consensus: got %d, need %d", sealTx.ValidatorCount, requiredVotes)
		}
	}

	return nil
}

// ProcessSealTransaction processes a validated seal transaction
func (ch *ConsensusHandler) ProcessSealTransaction(ctx context.Context, txBytes []byte) error {
	var sealTx SealCreationTx
	if err := json.Unmarshal(txBytes, &sealTx); err != nil {
		return fmt.Errorf("failed to unmarshal seal transaction: %w", err)
	}

	// Convert validator results to verification results
	var verificationResults []types.VerificationResult
	for _, vr := range sealTx.ValidatorResults {
		verificationResults = append(verificationResults, types.VerificationResult{
			ValidatorAddress: vr.ValidatorAddress,
			OutputHash:       vr.OutputHash,
			AttestationType:  vr.AttestationType,
			TeePlatform:      vr.TEEPlatform,
			AttestationData:  vr.AttestationQuote,
			ExecutionTimeMs:  vr.ExecutionTimeMs,
			Timestamp:        timestamppb.New(vr.Timestamp),
			Success:          true,
		})
	}

	// Complete the job (this creates the Digital Seal)
	if err := ch.keeper.CompleteJob(ctx, sealTx.JobID, sealTx.OutputHash, verificationResults); err != nil {
		return fmt.Errorf("failed to complete job: %w", err)
	}

	// Mark job complete in scheduler
	ch.scheduler.MarkJobComplete(sealTx.JobID)

	ch.logger.Info("Seal transaction processed",
		"job_id", sealTx.JobID,
		"validator_count", sealTx.ValidatorCount,
	)

	return nil
}

// IsSealTransaction checks if a transaction is a seal creation transaction
func IsSealTransaction(txBytes []byte) bool {
	var data map[string]interface{}
	if err := json.Unmarshal(txBytes, &data); err != nil {
		return false
	}
	txType, ok := data["type"].(string)
	return ok && txType == "create_seal_from_consensus"
}

// sha256Hash computes SHA-256 hash
func sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// isNullOrEmpty checks if a json.RawMessage is null, empty, or represents
// an empty JSON string. json.RawMessage(nil) marshals to "null" (4 bytes),
// so checking len() == 0 alone is insufficient.
func isNullOrEmpty(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	// JSON null literal
	if string(raw) == "null" {
		return true
	}
	// Empty JSON string ""
	if string(raw) == `""` {
		return true
	}
	return false
}
