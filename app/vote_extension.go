package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// VoteExtensionVersion is the current version of the vote extension format
const VoteExtensionVersion = 1

const (
	voteExtensionDefaultMaxPastSkew   = 10 * time.Minute
	voteExtensionDefaultMaxFutureSkew = 1 * time.Minute
)

const (
	// MaxVerificationsPerExtension caps the number of verifications a single
	// validator can include in a vote extension to prevent DoS.
	MaxVerificationsPerExtension = 100

	// MaxVoteExtensionSizeBytes caps the serialized size of a vote extension.
	MaxVoteExtensionSizeBytes = 5 * 1024 * 1024 // 5MB
)

// VoteExtension represents the Proof-of-Useful-Work verification data
// included in each validator's vote during consensus.
// This is the core data structure for Aethelred's custom consensus.
type VoteExtension struct {
	// Version for future compatibility
	Version int32 `json:"version"`

	// Height at which this extension was created
	Height int64 `json:"height"`

	// ValidatorAddress of the validator submitting this extension
	ValidatorAddress []byte `json:"validator_address"`

	// Verifications contains the compute verification results
	Verifications []ComputeVerification `json:"verifications"`

	// Timestamp when the verification was performed
	Timestamp time.Time `json:"timestamp"`

	// Nonce provides replay protection for extension-level signatures.
	Nonce []byte `json:"nonce,omitempty"`

	// Signature of the validator over the verification data
	Signature []byte `json:"signature"`

	// ExtensionHash is the hash of the extension contents (excluding signature)
	ExtensionHash []byte `json:"extension_hash"`
}

// ComputeVerification represents the result of verifying a compute job
type ComputeVerification struct {
	// JobID is the unique identifier of the compute job
	JobID string `json:"job_id"`

	// ModelHash is the hash of the model that was executed
	ModelHash []byte `json:"model_hash"`

	// InputHash is the hash of the input data
	InputHash []byte `json:"input_hash"`

	// OutputHash is the SHA-256 hash of the computation output
	OutputHash []byte `json:"output_hash"`

	// AttestationType indicates whether TEE, zkML, or both were used
	AttestationType AttestationType `json:"attestation_type"`

	// TEEAttestation contains the hardware attestation (if available)
	TEEAttestation *TEEAttestationData `json:"tee_attestation,omitempty"`

	// ZKProof contains the zero-knowledge proof (if available)
	ZKProof *ZKProofData `json:"zk_proof,omitempty"`

	// ExecutionTimeMs is how long the computation took
	ExecutionTimeMs int64 `json:"execution_time_ms"`

	// Success indicates if the verification succeeded
	Success bool `json:"success"`

	// ErrorCode for categorized errors
	ErrorCode ErrorCode `json:"error_code,omitempty"`

	// ErrorMessage contains any error that occurred
	ErrorMessage string `json:"error_message,omitempty"`

	// Nonce to prevent replay attacks
	Nonce []byte `json:"nonce"`
}

// AttestationType represents the type of attestation used
type AttestationType string

const (
	AttestationTypeTEE    AttestationType = "tee"
	AttestationTypeZKML   AttestationType = "zkml"
	AttestationTypeHybrid AttestationType = "hybrid"
	AttestationTypeNone   AttestationType = "none"
)

// ErrorCode represents categorized verification errors
type ErrorCode string

const (
	ErrorCodeNone           ErrorCode = ""
	ErrorCodeModelNotFound  ErrorCode = "MODEL_NOT_FOUND"
	ErrorCodeInvalidInput   ErrorCode = "INVALID_INPUT"
	ErrorCodeTEEFailure     ErrorCode = "TEE_FAILURE"
	ErrorCodeZKMLFailure    ErrorCode = "ZKML_FAILURE"
	ErrorCodeTimeout        ErrorCode = "TIMEOUT"
	ErrorCodeInternalError  ErrorCode = "INTERNAL_ERROR"
	ErrorCodeOutputMismatch ErrorCode = "OUTPUT_MISMATCH"
)

// TEEAttestationData contains the Trusted Execution Environment attestation
type TEEAttestationData struct {
	// Platform identifies the TEE platform (e.g., "aws-nitro", "intel-sgx")
	Platform string `json:"platform"`

	// EnclaveID is the unique identifier of the enclave
	EnclaveID string `json:"enclave_id"`

	// Measurement is the hash of the enclave code (PCR values)
	Measurement []byte `json:"measurement"`

	// Quote is the attestation quote from the TEE
	Quote []byte `json:"quote"`

	// UserData bound to the attestation (typically output hash)
	UserData []byte `json:"user_data"`

	// CertificateChain for quote verification
	CertificateChain [][]byte `json:"certificate_chain,omitempty"`

	// Timestamp when the attestation was generated
	Timestamp time.Time `json:"timestamp"`

	// Nonce used in attestation generation
	Nonce []byte `json:"nonce"`
}

// ZKProofData contains the zero-knowledge ML proof
type ZKProofData struct {
	// ProofSystem identifies the proof system (e.g., "ezkl", "risc0")
	ProofSystem string `json:"proof_system"`

	// Proof is the actual ZK proof bytes
	Proof []byte `json:"proof"`

	// PublicInputs are the public inputs to the proof
	PublicInputs []byte `json:"public_inputs"`

	// VerifyingKeyHash is the hash of the verifying key used
	VerifyingKeyHash []byte `json:"verifying_key_hash"`

	// CircuitHash is the hash of the circuit
	CircuitHash []byte `json:"circuit_hash"`

	// ProofSize in bytes
	ProofSize int64 `json:"proof_size"`
}

// NewVoteExtension creates a new VoteExtension.
//
// NOTE: this convenience wrapper intentionally leaves Timestamp unset so that
// consensus-critical callers can stamp deterministic block time explicitly.
func NewVoteExtension(height int64, validatorAddr []byte) *VoteExtension {
	return NewVoteExtensionAtBlockTime(height, validatorAddr, time.Time{})
}

// NewVoteExtensionAtBlockTime creates a new VoteExtension with an explicit block time.
func NewVoteExtensionAtBlockTime(height int64, validatorAddr []byte, blockTime time.Time) *VoteExtension {
	timestamp := time.Time{}
	if !blockTime.IsZero() {
		timestamp = blockTime.UTC()
	}
	return &VoteExtension{
		Version:          VoteExtensionVersion,
		Height:           height,
		ValidatorAddress: validatorAddr,
		Verifications:    make([]ComputeVerification, 0),
		Timestamp:        timestamp,
	}
}

// AddVerification adds a verification result to the extension
func (ve *VoteExtension) AddVerification(v ComputeVerification) {
	ve.Verifications = append(ve.Verifications, v)
}

// ComputeHash computes the hash of the extension contents (excluding signature).
// Uses length-prefixed encoding to prevent domain-separation collisions.
func (ve *VoteExtension) ComputeHash() []byte {
	h := sha256.New()

	writeLenBytes := func(b []byte) {
		lenBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBytes, uint32(len(b)))
		h.Write(lenBytes)
		if len(b) > 0 {
			h.Write(b)
		}
	}
	writeString := func(s string) { writeLenBytes([]byte(s)) }
	writeBool := func(v bool) {
		if v {
			h.Write([]byte{1})
		} else {
			h.Write([]byte{0})
		}
	}
	writeInt64 := func(v int64) {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(v))
		h.Write(buf)
	}

	// Domain separator
	h.Write([]byte("aethelred_vote_ext_v1:"))

	// Version (fixed 4 bytes)
	versionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, uint32(ve.Version))
	h.Write(versionBytes)

	// Height (fixed 8 bytes)
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, uint64(ve.Height))
	h.Write(heightBytes)

	// Validator address (length-prefixed)
	writeLenBytes(ve.ValidatorAddress)

	// Timestamp (fixed 8 bytes, Unix nanos)
	writeInt64(ve.Timestamp.UnixNano())

	// Extension-level nonce (length-prefixed)
	writeLenBytes(ve.Nonce)

	// Number of verifications (fixed 4 bytes)
	numVerifications := make([]byte, 4)
	binary.BigEndian.PutUint32(numVerifications, uint32(len(ve.Verifications)))
	h.Write(numVerifications)

	// Each verification (length-prefixed fields)
	for _, v := range ve.Verifications {
		writeString(v.JobID)
		writeLenBytes(v.ModelHash)
		writeLenBytes(v.InputHash)
		writeLenBytes(v.OutputHash)
		writeString(string(v.AttestationType))
		writeInt64(v.ExecutionTimeMs)
		writeBool(v.Success)
		writeString(string(v.ErrorCode))
		writeString(v.ErrorMessage)
		writeLenBytes(v.Nonce)

		if v.TEEAttestation == nil {
			writeBool(false)
		} else {
			writeBool(true)
			writeString(v.TEEAttestation.Platform)
			writeString(v.TEEAttestation.EnclaveID)
			writeLenBytes(v.TEEAttestation.Measurement)
			writeLenBytes(v.TEEAttestation.Quote)
			writeLenBytes(v.TEEAttestation.UserData)
			writeInt64(v.TEEAttestation.Timestamp.UnixNano())
			writeLenBytes(v.TEEAttestation.Nonce)
			chainLen := make([]byte, 4)
			binary.BigEndian.PutUint32(chainLen, uint32(len(v.TEEAttestation.CertificateChain)))
			h.Write(chainLen)
			for _, cert := range v.TEEAttestation.CertificateChain {
				writeLenBytes(cert)
			}
		}

		if v.ZKProof == nil {
			writeBool(false)
		} else {
			writeBool(true)
			writeString(v.ZKProof.ProofSystem)
			writeLenBytes(v.ZKProof.Proof)
			writeLenBytes(v.ZKProof.PublicInputs)
			writeLenBytes(v.ZKProof.VerifyingKeyHash)
			writeLenBytes(v.ZKProof.CircuitHash)
			writeInt64(v.ZKProof.ProofSize)
		}
	}

	return h.Sum(nil)
}

// Marshal serializes the VoteExtension to bytes
func (ve *VoteExtension) Marshal() ([]byte, error) {
	// Compute hash before marshaling
	ve.ExtensionHash = ve.ComputeHash()
	return json.Marshal(ve)
}

// MarshalForSigning returns bytes for signing (excludes signature)
func (ve *VoteExtension) MarshalForSigning() ([]byte, error) {
	// Create a copy without signature
	copy := *ve
	copy.Signature = nil
	return json.Marshal(copy)
}

// UnmarshalVoteExtension deserializes bytes to VoteExtension
func UnmarshalVoteExtension(data []byte) (*VoteExtension, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty vote extension data")
	}

	var ve VoteExtension
	if err := json.Unmarshal(data, &ve); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vote extension: %w", err)
	}

	return &ve, nil
}

// ValidationMode controls the strictness of vote extension validation.
type ValidationMode int

const (
	// ValidationModePermissive allows unsigned extensions and simulated TEE
	// platforms. Suitable for devnets and testnets where AllowSimulated=true.
	ValidationModePermissive ValidationMode = iota

	// ValidationModeStrict requires signatures, rejects simulated TEE
	// platforms, and enforces extension hash presence. This is the default
	// for production (AllowSimulated=false).
	ValidationModeStrict
)

// Validate performs validation of the VoteExtension including hash integrity.
// This is the permissive validation that does not require signatures.
// For production, use ValidateStrict().
func (ve *VoteExtension) Validate() error {
	return ve.ValidateAtBlockTime(time.Time{})
}

// ValidateStrict performs strict production-mode validation:
//   - Signatures MUST be present
//   - Extension hash MUST be present
//   - Simulated TEE platforms are REJECTED
//   - All permissive checks also apply
func (ve *VoteExtension) ValidateStrict() error {
	return ve.ValidateStrictAtBlockTime(time.Time{})
}

// ValidateAtBlockTime performs permissive validation anchored to deterministic block time.
func (ve *VoteExtension) ValidateAtBlockTime(blockTime time.Time) error {
	return ve.validateAt(ValidationModePermissive, normalizeValidationTime(blockTime))
}

// ValidateStrictAtBlockTime performs strict validation anchored to deterministic block time.
func (ve *VoteExtension) ValidateStrictAtBlockTime(blockTime time.Time) error {
	return ve.validateAt(ValidationModeStrict, normalizeValidationTime(blockTime))
}

// validateAt is the internal validation implementation parameterized by mode
// and a caller-provided reference time. If now is zero, time-based checks are skipped.
func (ve *VoteExtension) validateAt(mode ValidationMode, now time.Time) error {
	return ve.validateAtWithWindow(mode, now, voteExtensionDefaultMaxPastSkew, voteExtensionDefaultMaxFutureSkew)
}

func normalizeValidationTime(ts time.Time) time.Time {
	if ts.IsZero() {
		return time.Time{}
	}
	return ts.UTC()
}

func (ve *VoteExtension) validateAtWithWindow(mode ValidationMode, now time.Time, maxPastSkew, maxFutureSkew time.Duration) error {
	if ve.Version != VoteExtensionVersion {
		return fmt.Errorf("unsupported vote extension version: %d", ve.Version)
	}

	if ve.Height <= 0 {
		return fmt.Errorf("invalid height: %d", ve.Height)
	}

	if len(ve.ValidatorAddress) == 0 {
		return fmt.Errorf("missing validator address")
	}

	if len(ve.Verifications) > MaxVerificationsPerExtension {
		return fmt.Errorf("too many verifications: %d (max %d)", len(ve.Verifications), MaxVerificationsPerExtension)
	}

	if !now.IsZero() {
		// Timestamp should not be in the future (with some tolerance)
		if ve.Timestamp.After(now.Add(maxFutureSkew)) {
			return fmt.Errorf("vote extension timestamp is in the future")
		}

		// Timestamp should not be too old (stale extensions)
		if ve.Timestamp.Before(now.Add(-maxPastSkew)) {
			return fmt.Errorf("vote extension timestamp is too old")
		}
	}

	// ── Strict mode: extension hash MUST be present ──
	if mode == ValidationModeStrict && len(ve.ExtensionHash) == 0 {
		return fmt.Errorf("SECURITY: extension hash is required in production mode")
	}

	// Verify extension hash integrity if present
	if len(ve.ExtensionHash) > 0 {
		expectedHash := ve.ComputeHash()
		if !bytes.Equal(ve.ExtensionHash, expectedHash) {
			return fmt.Errorf("extension hash mismatch: data has been tampered with")
		}
	}

	// ── Strict mode: signature MUST be present ──
	if mode == ValidationModeStrict && len(ve.Signature) == 0 {
		return fmt.Errorf("SECURITY: unsigned vote extensions are rejected in production mode")
	}

	// ── Strict mode: validate signature length ──
	if mode == ValidationModeStrict && len(ve.Signature) != 64 {
		return fmt.Errorf("SECURITY: invalid signature length %d (expected 64 bytes ed25519)", len(ve.Signature))
	}

	// Validate each verification
	for i, v := range ve.Verifications {
		if err := v.validate(mode); err != nil {
			return fmt.Errorf("invalid verification at index %d: %w", i, err)
		}
	}

	return nil
}

// Validate performs validation of a ComputeVerification including replay protection.
// This is the permissive mode; use validate(ValidationModeStrict) for production.
func (cv *ComputeVerification) Validate() error {
	return cv.validate(ValidationModePermissive)
}

// validate is the internal validation parameterized by mode.
func (cv *ComputeVerification) validate(mode ValidationMode) error {
	if len(cv.JobID) == 0 {
		return fmt.Errorf("missing job ID")
	}

	// JobID length sanity check
	if len(cv.JobID) > 256 {
		return fmt.Errorf("job ID too long: %d bytes (max 256)", len(cv.JobID))
	}

	// Nonce is required for replay protection
	if len(cv.Nonce) == 0 {
		return fmt.Errorf("missing nonce for replay protection")
	}
	if len(cv.Nonce) != 32 {
		return fmt.Errorf("nonce must be exactly 32 bytes, got %d", len(cv.Nonce))
	}

	// Model hash must be present
	if len(cv.ModelHash) == 0 {
		return fmt.Errorf("missing model hash")
	}
	if len(cv.ModelHash) != 32 {
		return fmt.Errorf("model hash must be 32 bytes (SHA-256)")
	}

	if cv.Success {
		if len(cv.OutputHash) != 32 {
			return fmt.Errorf("successful verification must have 32-byte output hash")
		}

		// Execution time must be positive for successful verifications
		if cv.ExecutionTimeMs <= 0 {
			return fmt.Errorf("successful verification must have positive execution time")
		}
	}

	// Validate attestation based on type
	switch cv.AttestationType {
	case AttestationTypeTEE:
		if cv.TEEAttestation == nil {
			return fmt.Errorf("TEE attestation type requires TEE attestation data")
		}
		if err := cv.TEEAttestation.validate(mode); err != nil {
			return fmt.Errorf("invalid TEE attestation: %w", err)
		}
	case AttestationTypeZKML:
		if cv.ZKProof == nil {
			return fmt.Errorf("zkML attestation type requires ZK proof data")
		}
		if err := cv.ZKProof.Validate(); err != nil {
			return fmt.Errorf("invalid ZK proof: %w", err)
		}
	case AttestationTypeHybrid:
		if cv.TEEAttestation == nil || cv.ZKProof == nil {
			return fmt.Errorf("hybrid attestation type requires both TEE and zkML data")
		}
		// In strict mode, validate nested attestation and proof
		if mode == ValidationModeStrict {
			if err := cv.TEEAttestation.validate(mode); err != nil {
				return fmt.Errorf("invalid TEE attestation in hybrid: %w", err)
			}
			if err := cv.ZKProof.Validate(); err != nil {
				return fmt.Errorf("invalid ZK proof in hybrid: %w", err)
			}
		}
	case AttestationTypeNone:
		// Only valid for failed verifications
		if cv.Success {
			return fmt.Errorf("successful verification cannot have no attestation")
		}
	default:
		return fmt.Errorf("unknown attestation type: %s", cv.AttestationType)
	}

	// ── Strict mode: bind attestation/proof to output hash ──
	if mode == ValidationModeStrict && cv.Success {
		if len(cv.OutputHash) != 32 {
			return fmt.Errorf("SECURITY: output hash must be 32 bytes for binding checks")
		}

		if cv.TEEAttestation != nil {
			if len(cv.TEEAttestation.UserData) != len(cv.OutputHash) {
				return fmt.Errorf("SECURITY: TEE user_data length must match output hash length")
			}
			if !bytes.Equal(cv.TEEAttestation.UserData, cv.OutputHash) {
				return fmt.Errorf("SECURITY: TEE user_data must equal output hash")
			}
		}

		if cv.ZKProof != nil {
			if !bytes.Contains(cv.ZKProof.PublicInputs, cv.OutputHash) {
				return fmt.Errorf("SECURITY: zkML public inputs must bind output hash")
			}
		}
	}

	return nil
}

// Validate performs basic validation of TEEAttestationData (permissive mode).
func (ta *TEEAttestationData) Validate() error {
	return ta.validate(ValidationModePermissive)
}

// validate is the internal validation parameterized by mode.
func (ta *TEEAttestationData) validate(mode ValidationMode) error {
	if len(ta.Platform) == 0 {
		return fmt.Errorf("missing TEE platform")
	}

	// ── Strict mode: reject simulated TEE platform ──
	if mode == ValidationModeStrict && ta.Platform == "simulated" {
		return fmt.Errorf("SECURITY: simulated TEE platform is rejected in production mode")
	}

	validPlatforms := map[string]bool{
		"aws-nitro":     true,
		"intel-sgx":     true,
		"intel-tdx":     true,
		"amd-sev":       true,
		"arm-trustzone": true,
		"simulated":     true, // testnet only — production validators MUST use real TEE
	}

	if !validPlatforms[ta.Platform] {
		return fmt.Errorf("unknown TEE platform: %s", ta.Platform)
	}

	if len(ta.Measurement) == 0 {
		return fmt.Errorf("missing enclave measurement")
	}

	if len(ta.Quote) == 0 {
		return fmt.Errorf("missing attestation quote")
	}

	// Quote must be at least 64 bytes for any real attestation
	if len(ta.Quote) < 64 {
		return fmt.Errorf("attestation quote too short: %d bytes (minimum 64)", len(ta.Quote))
	}

	// Nonce must be present for replay protection
	if len(ta.Nonce) == 0 {
		return fmt.Errorf("missing attestation nonce")
	}

	// UserData should contain the output hash (32 bytes)
	if len(ta.UserData) == 0 {
		return fmt.Errorf("missing user data in attestation")
	}

	// Timestamp validation
	if ta.Timestamp.IsZero() {
		return fmt.Errorf("missing attestation timestamp")
	}

	// Strict mode: validate quote schema for supported platforms.
	if mode == ValidationModeStrict {
		if err := validateTEEQuoteSchema(ta); err != nil {
			return fmt.Errorf("invalid attestation quote schema: %w", err)
		}
	}

	return nil
}

// Validate performs validation of ZKProofData
func (zp *ZKProofData) Validate() error {
	if len(zp.ProofSystem) == 0 {
		return fmt.Errorf("missing proof system")
	}

	validSystems := map[string]bool{
		"ezkl":    true,
		"risc0":   true,
		"plonky2": true,
		"halo2":   true,
	}

	if !validSystems[zp.ProofSystem] {
		return fmt.Errorf("unknown proof system: %s", zp.ProofSystem)
	}

	if len(zp.Proof) == 0 {
		return fmt.Errorf("missing proof data")
	}

	// Minimum proof size for any real ZK proof system
	if len(zp.Proof) < 128 {
		return fmt.Errorf("proof data too short: %d bytes (minimum 128)", len(zp.Proof))
	}

	if len(zp.VerifyingKeyHash) != 32 {
		return fmt.Errorf("verifying key hash must be 32 bytes")
	}

	if len(zp.CircuitHash) > 0 && len(zp.CircuitHash) != 32 {
		return fmt.Errorf("circuit hash must be 32 bytes if provided")
	}

	if len(zp.PublicInputs) == 0 {
		return fmt.Errorf("missing public inputs")
	}

	return nil
}

// AggregatedVerification represents combined results from multiple validators
type AggregatedVerification struct {
	JobID            string
	ModelHash        []byte
	InputHash        []byte
	OutputHash       []byte
	ValidatorCount   int
	TotalVotes       int
	AgreementPower   int64
	TotalPower       int64
	Attestations     []ValidatorAttestation
	HasConsensus     bool
	ConsensusReached time.Time
}

// ValidatorAttestation represents a single validator's attestation for aggregation
type ValidatorAttestation struct {
	ValidatorAddress []byte
	OutputHash       []byte
	AttestationType  AttestationType
	TEEAttestation   *TEEAttestationData
	ZKProof          *ZKProofData
	ExecutionTimeMs  int64
	Timestamp        time.Time
}

// VoteExtensionWithPower bundles a vote extension with its validator's voting power.
type VoteExtensionWithPower struct {
	Extension *VoteExtension
	Power     int64
}

// AggregateVoteExtensions combines vote extensions from multiple validators
// and determines consensus on computation results
func AggregateVoteExtensions(
	ctx sdk.Context,
	votes []VoteExtensionWithPower,
	consensusThreshold int, // percentage (e.g., 67 for 2/3)
	allowSimulated bool,
) map[string]*AggregatedVerification {
	aggregated := make(map[string]*AggregatedVerification)
	outputVotes := make(map[string]map[string][]ValidatorAttestation) // jobID -> outputHashHex -> attestations
	outputPower := make(map[string]map[string]int64)                  // jobID -> outputHashHex -> power

	totalVotes := len(votes)
	totalPower := int64(0)
	for _, vote := range votes {
		totalPower += vote.Power
	}

	useFallbackPower := false
	if totalPower == 0 && totalVotes > 0 {
		if allowSimulated {
			totalPower = int64(totalVotes)
			useFallbackPower = true
		} else {
			return aggregated
		}
	}

	requiredPower := (totalPower * int64(consensusThreshold) / 100) + 1

	// Collect all successful verifications
	for _, vote := range votes {
		ext := vote.Extension
		if ext == nil {
			continue
		}

		votePower := vote.Power
		if useFallbackPower {
			votePower = 1
		}

		for _, v := range ext.Verifications {
			if !v.Success {
				continue
			}

			outputHashHex := fmt.Sprintf("%x", v.OutputHash)

			// Initialize maps if needed
			if outputVotes[v.JobID] == nil {
				outputVotes[v.JobID] = make(map[string][]ValidatorAttestation)
			}
			if outputPower[v.JobID] == nil {
				outputPower[v.JobID] = make(map[string]int64)
			}

			// Create validator attestation
			attestation := ValidatorAttestation{
				ValidatorAddress: ext.ValidatorAddress,
				OutputHash:       v.OutputHash,
				AttestationType:  v.AttestationType,
				TEEAttestation:   v.TEEAttestation,
				ZKProof:          v.ZKProof,
				ExecutionTimeMs:  v.ExecutionTimeMs,
				Timestamp:        ext.Timestamp,
			}

			outputVotes[v.JobID][outputHashHex] = append(
				outputVotes[v.JobID][outputHashHex],
				attestation,
			)
			outputPower[v.JobID][outputHashHex] += votePower

			// Initialize aggregated result
			if aggregated[v.JobID] == nil {
				aggregated[v.JobID] = &AggregatedVerification{
					JobID:        v.JobID,
					ModelHash:    v.ModelHash,
					InputHash:    v.InputHash,
					TotalVotes:   totalVotes,
					TotalPower:   totalPower,
					Attestations: make([]ValidatorAttestation, 0),
				}
			}
		}
	}

	// Determine consensus for each job
	for jobID, outputs := range outputVotes {
		for outputHashHex, attestations := range outputs {
			if outputPower[jobID][outputHashHex] >= requiredPower {
				agg := aggregated[jobID]
				outputHash, _ := hexToBytes(outputHashHex)
				agg.OutputHash = outputHash
				agg.ValidatorCount = len(attestations)
				agg.AgreementPower = outputPower[jobID][outputHashHex]
				agg.Attestations = attestations
				agg.HasConsensus = true
				// Deterministic consensus timestamp for all validators.
				agg.ConsensusReached = ctx.BlockTime().UTC()
				break
			}
		}
	}

	return aggregated
}

// hexToBytes converts hex string to bytes using standard library
func hexToBytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}

// SortVerificationsByJobID sorts verifications by job ID for deterministic ordering
func SortVerificationsByJobID(verifications []ComputeVerification) {
	sort.Slice(verifications, func(i, j int) bool {
		return verifications[i].JobID < verifications[j].JobID
	})
}

// InjectedVoteExtensionTx represents a vote extension injected as a transaction
// in the block for validators to process during DeliverTx
type InjectedVoteExtensionTx struct {
	// JobID of the completed computation
	JobID string `json:"job_id"`

	// OutputHash that reached consensus
	OutputHash []byte `json:"output_hash"`

	// ValidatorCount that agreed
	ValidatorCount int `json:"validator_count"`

	// TotalVotes in the round
	TotalVotes int `json:"total_votes"`

	// AgreementPower is the voting power that agreed on the output
	AgreementPower int64 `json:"agreement_power"`

	// TotalPower is the total voting power in the round
	TotalPower int64 `json:"total_power"`

	// Attestations from validators (for seal creation)
	Attestations []ValidatorAttestation `json:"attestations"`

	// BlockHeight when consensus was reached
	BlockHeight int64 `json:"block_height"`

	// Type identifier for tx routing
	Type string `json:"type"`
}

// NewInjectedVoteExtensionTx creates a new injected tx from an aggregated verification
func NewInjectedVoteExtensionTx(agg *AggregatedVerification, height int64) *InjectedVoteExtensionTx {
	return &InjectedVoteExtensionTx{
		JobID:          agg.JobID,
		OutputHash:     agg.OutputHash,
		ValidatorCount: agg.ValidatorCount,
		TotalVotes:     agg.TotalVotes,
		AgreementPower: agg.AgreementPower,
		TotalPower:     agg.TotalPower,
		Attestations:   agg.Attestations,
		BlockHeight:    height,
		Type:           "create_seal_from_consensus",
	}
}

// Marshal serializes the injected tx
func (tx *InjectedVoteExtensionTx) Marshal() ([]byte, error) {
	return json.Marshal(tx)
}

// UnmarshalInjectedVoteExtensionTx deserializes an injected tx
func UnmarshalInjectedVoteExtensionTx(data []byte) (*InjectedVoteExtensionTx, error) {
	var tx InjectedVoteExtensionTx
	if err := json.Unmarshal(data, &tx); err != nil {
		return nil, err
	}
	return &tx, nil
}

// IsInjectedVoteExtensionTx checks if a transaction is an injected vote extension tx
func IsInjectedVoteExtensionTx(txBytes []byte) bool {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(txBytes, &probe); err != nil {
		return false
	}
	return probe.Type == "create_seal_from_consensus"
}

// VoteExtensionCodec provides encoding/decoding for vote extensions
type VoteExtensionCodec struct {
	cdc codec.Codec
}

// NewVoteExtensionCodec creates a new codec
func NewVoteExtensionCodec(cdc codec.Codec) *VoteExtensionCodec {
	return &VoteExtensionCodec{cdc: cdc}
}

// Encode encodes a vote extension
func (vec *VoteExtensionCodec) Encode(ve *VoteExtension) ([]byte, error) {
	return ve.Marshal()
}

// Decode decodes a vote extension
func (vec *VoteExtensionCodec) Decode(data []byte) (*VoteExtension, error) {
	return UnmarshalVoteExtension(data)
}

// SignVoteExtension signs the vote extension with the validator's ed25519 private key
func SignVoteExtension(ve *VoteExtension, privKey ed25519.PrivateKey) error {
	// Compute and set the extension hash
	ve.ExtensionHash = ve.ComputeHash()

	// Get the bytes to sign
	signingBytes, err := ve.MarshalForSigning()
	if err != nil {
		return fmt.Errorf("failed to marshal for signing: %w", err)
	}

	// Sign with ed25519
	ve.Signature = ed25519.Sign(privKey, signingBytes)
	return nil
}

// VerifyVoteExtensionSignature verifies the ed25519 signature on a vote extension
func VerifyVoteExtensionSignature(ve *VoteExtension, pubKey ed25519.PublicKey) bool {
	if len(ve.Signature) == 0 {
		return false
	}

	// Validate signature length (ed25519 signatures are 64 bytes)
	if len(ve.Signature) != ed25519.SignatureSize {
		return false
	}

	// Validate public key length
	if len(pubKey) != ed25519.PublicKeySize {
		return false
	}

	// Compute expected hash and verify integrity
	expectedHash := ve.ComputeHash()
	if !bytes.Equal(ve.ExtensionHash, expectedHash) {
		return false
	}

	// Get the bytes that were signed
	signingBytes, err := ve.MarshalForSigning()
	if err != nil {
		return false
	}

	// Verify the ed25519 signature
	return ed25519.Verify(pubKey, signingBytes, ve.Signature)
}
