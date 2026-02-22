package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// EnhancedDigitalSeal extends DigitalSeal with comprehensive verification binding
type EnhancedDigitalSeal struct {
	DigitalSeal

	// Version of the seal format
	Version int32 `json:"version"`

	// JobID links this seal to the compute job
	JobID string `json:"job_id"`

	// ConsensusInfo contains information about the consensus that created this seal
	ConsensusInfo *ConsensusInfo `json:"consensus_info"`

	// VerificationBundle contains all verification proofs
	VerificationBundle *VerificationBundle `json:"verification_bundle"`

	// AuditTrail tracks all modifications to this seal
	AuditTrail []AuditEntry `json:"audit_trail"`

	// Metadata for additional seal data
	Metadata *SealMetadata `json:"metadata,omitempty"`

	// Signatures contains cryptographic signatures over the seal
	Signatures []SealSignature `json:"signatures"`

	// ExpiresAt is when this seal expires (optional)
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// ChainID identifies the blockchain
	ChainID string `json:"chain_id"`

	// SealHash is the complete hash of the seal contents
	SealHash []byte `json:"seal_hash"`
}

// ConsensusInfo contains information about the consensus that verified the computation
type ConsensusInfo struct {
	// Height at which consensus was reached
	Height int64 `json:"height"`

	// Round in which consensus was reached
	Round int32 `json:"round"`

	// TotalValidators in the validator set
	TotalValidators int `json:"total_validators"`

	// ParticipatingValidators who submitted vote extensions
	ParticipatingValidators int `json:"participating_validators"`

	// AgreementCount is how many validators agreed on the output
	AgreementCount int `json:"agreement_count"`

	// ConsensusThreshold percentage required
	ConsensusThreshold int `json:"consensus_threshold"`

	// VoteExtensionHashes from participating validators
	VoteExtensionHashes [][]byte `json:"vote_extension_hashes"`

	// BlockHash of the block containing this seal
	BlockHash []byte `json:"block_hash,omitempty"`

	// Timestamp when consensus was reached
	Timestamp time.Time `json:"timestamp"`
}

// VerificationBundle contains all verification evidence
type VerificationBundle struct {
	// TEEVerifications from validators
	TEEVerifications []TEEVerification `json:"tee_verifications"`

	// ZKMLVerification if zkML proof was generated
	ZKMLVerification *ZKMLVerification `json:"zkml_verification,omitempty"`

	// HybridVerification if both TEE and zkML were used
	HybridVerification *HybridVerification `json:"hybrid_verification,omitempty"`

	// VerificationType used (tee, zkml, hybrid)
	VerificationType string `json:"verification_type"`

	// AggregatedOutputHash is the consensus output
	AggregatedOutputHash []byte `json:"aggregated_output_hash"`

	// ModelVerification contains model verification info
	ModelVerification *ModelVerification `json:"model_verification,omitempty"`

	// BundleHash is the hash of the entire bundle
	BundleHash []byte `json:"bundle_hash"`
}

// TEEVerification contains a single TEE verification result
type TEEVerification struct {
	// ValidatorAddress who performed the verification
	ValidatorAddress string `json:"validator_address"`

	// ValidatorPubKey for signature verification
	ValidatorPubKey []byte `json:"validator_pub_key,omitempty"`

	// Platform (aws-nitro, intel-sgx, etc.)
	Platform string `json:"platform"`

	// EnclaveID of the enclave used
	EnclaveID string `json:"enclave_id"`

	// Measurement (PCR values)
	Measurement []byte `json:"measurement"`

	// AttestationDocument raw attestation
	AttestationDocument []byte `json:"attestation_document"`

	// OutputHash computed by this validator
	OutputHash []byte `json:"output_hash"`

	// ExecutionTimeMs how long execution took
	ExecutionTimeMs int64 `json:"execution_time_ms"`

	// Timestamp when verification was performed
	Timestamp time.Time `json:"timestamp"`

	// Signature over the verification result
	Signature []byte `json:"signature"`

	// Nonce used in attestation
	Nonce []byte `json:"nonce"`
}

// ZKMLVerification contains zkML proof verification
type ZKMLVerification struct {
	// ProofSystem used (ezkl, risc0, etc.)
	ProofSystem string `json:"proof_system"`

	// Proof bytes
	Proof []byte `json:"proof"`

	// PublicInputs to the proof
	PublicInputs *ZKMLPublicInputs `json:"public_inputs"`

	// VerifyingKeyHash used
	VerifyingKeyHash []byte `json:"verifying_key_hash"`

	// CircuitHash of the circuit
	CircuitHash []byte `json:"circuit_hash"`

	// ProofSizeBytes size of the proof
	ProofSizeBytes int64 `json:"proof_size_bytes"`

	// GenerationTimeMs proof generation time
	GenerationTimeMs int64 `json:"generation_time_ms"`

	// VerificationTimeMs proof verification time
	VerificationTimeMs int64 `json:"verification_time_ms"`

	// Verified indicates proof was verified
	Verified bool `json:"verified"`

	// GeneratedBy validator that generated the proof
	GeneratedBy string `json:"generated_by"`

	// Timestamp when proof was generated
	Timestamp time.Time `json:"timestamp"`
}

// ZKMLPublicInputs contains the public inputs to a zkML proof
type ZKMLPublicInputs struct {
	// ModelCommitment
	ModelCommitment []byte `json:"model_commitment"`

	// InputCommitment
	InputCommitment []byte `json:"input_commitment"`

	// OutputCommitment
	OutputCommitment []byte `json:"output_commitment"`

	// ScaleFactors for quantization
	ScaleFactors []float64 `json:"scale_factors,omitempty"`

	// Instances are the public circuit instances
	Instances [][]byte `json:"instances"`
}

// HybridVerification combines TEE and zkML
type HybridVerification struct {
	// TEEVerifications for TEE part
	TEEVerifications []TEEVerification `json:"tee_verifications"`

	// ZKMLVerification for zkML part
	ZKMLVerification *ZKMLVerification `json:"zkml_verification"`

	// CrossValidated indicates outputs were cross-validated
	CrossValidated bool `json:"cross_validated"`

	// OutputsMatch indicates TEE and zkML outputs match
	OutputsMatch bool `json:"outputs_match"`
}

// ModelVerification contains model verification info
type ModelVerification struct {
	// ModelHash of the model
	ModelHash []byte `json:"model_hash"`

	// ModelID human-readable identifier
	ModelID string `json:"model_id"`

	// ModelVersion
	ModelVersion string `json:"model_version"`

	// CircuitHash for zkML
	CircuitHash []byte `json:"circuit_hash,omitempty"`

	// TEEMeasurement expected
	TEEMeasurement []byte `json:"tee_measurement,omitempty"`

	// RegistrationTx where model was registered
	RegistrationTx string `json:"registration_tx,omitempty"`
}

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	// Timestamp of the event
	Timestamp time.Time `json:"timestamp"`

	// EventType (created, verified, accessed, revoked, etc.)
	EventType AuditEventType `json:"event_type"`

	// Actor who performed the action
	Actor string `json:"actor"`

	// Details of the event
	Details string `json:"details"`

	// TransactionHash if on-chain
	TransactionHash string `json:"transaction_hash,omitempty"`

	// BlockHeight when event occurred
	BlockHeight int64 `json:"block_height"`

	// PreviousStateHash for state tracking
	PreviousStateHash []byte `json:"previous_state_hash,omitempty"`

	// Signature over the audit entry
	Signature []byte `json:"signature,omitempty"`
}

// AuditEventType represents types of audit events
type AuditEventType string

const (
	AuditEventCreated        AuditEventType = "created"
	AuditEventVerified       AuditEventType = "verified"
	AuditEventActivated      AuditEventType = "activated"
	AuditEventAccessed       AuditEventType = "accessed"
	AuditEventExported       AuditEventType = "exported"
	AuditEventRevoked        AuditEventType = "revoked"
	AuditEventExpired        AuditEventType = "expired"
	AuditEventMetadataUpdated AuditEventType = "metadata_updated"
	AuditEventComplianceCheck AuditEventType = "compliance_check"
)

// SealMetadata contains additional seal metadata
type SealMetadata struct {
	// Tags for categorization
	Tags []string `json:"tags,omitempty"`

	// Description of the seal
	Description string `json:"description,omitempty"`

	// ExternalRef for external system references
	ExternalRef string `json:"external_ref,omitempty"`

	// CustomData for application-specific data
	CustomData map[string]string `json:"custom_data,omitempty"`

	// InputSchema describes the input format
	InputSchema string `json:"input_schema,omitempty"`

	// OutputSchema describes the output format
	OutputSchema string `json:"output_schema,omitempty"`

	// ModelArchitecture describes the model
	ModelArchitecture string `json:"model_architecture,omitempty"`
}

// SealSignature represents a signature over the seal
type SealSignature struct {
	// SignerAddress
	SignerAddress string `json:"signer_address"`

	// SignerType (validator, authority, user)
	SignerType string `json:"signer_type"`

	// Algorithm used
	Algorithm string `json:"algorithm"`

	// PublicKey of signer
	PublicKey []byte `json:"public_key"`

	// Signature bytes
	Signature []byte `json:"signature"`

	// Timestamp when signed
	Timestamp time.Time `json:"timestamp"`
}

// EnhancedRegulatoryInfo extends RegulatoryInfo with more compliance fields
type EnhancedRegulatoryInfo struct {
	RegulatoryInfo

	// IndustryStandards (e.g., "Basel III", "Solvency II")
	IndustryStandards []string `json:"industry_standards,omitempty"`

	// DataResidency requirements
	DataResidency []string `json:"data_residency,omitempty"`

	// PrivacyFlags for PII handling
	PrivacyFlags *PrivacyFlags `json:"privacy_flags,omitempty"`

	// ComplianceStatus
	ComplianceStatus ComplianceStatus `json:"compliance_status"`

	// LastComplianceCheck
	LastComplianceCheck *time.Time `json:"last_compliance_check,omitempty"`

	// ComplianceNotes
	ComplianceNotes string `json:"compliance_notes,omitempty"`

	// ApprovalChain for multi-party approval
	ApprovalChain []ApprovalRecord `json:"approval_chain,omitempty"`
}

// PrivacyFlags indicates privacy-related flags
type PrivacyFlags struct {
	// ContainsPII indicates personally identifiable information
	ContainsPII bool `json:"contains_pii"`

	// ContainsPHI indicates protected health information
	ContainsPHI bool `json:"contains_phi"`

	// ContainsFinancial indicates financial data
	ContainsFinancial bool `json:"contains_financial"`

	// DataMinimized indicates data minimization was applied
	DataMinimized bool `json:"data_minimized"`

	// ConsentObtained indicates user consent was obtained
	ConsentObtained bool `json:"consent_obtained"`

	// AnonymizationApplied indicates anonymization was applied
	AnonymizationApplied bool `json:"anonymization_applied"`
}

// ComplianceStatus represents the compliance status
type ComplianceStatus string

const (
	ComplianceStatusPending   ComplianceStatus = "pending"
	ComplianceStatusCompliant ComplianceStatus = "compliant"
	ComplianceStatusNonCompliant ComplianceStatus = "non_compliant"
	ComplianceStatusExempt    ComplianceStatus = "exempt"
	ComplianceStatusUnderReview ComplianceStatus = "under_review"
)

// ApprovalRecord represents an approval in the chain
type ApprovalRecord struct {
	// Approver address
	Approver string `json:"approver"`

	// ApproverRole
	ApproverRole string `json:"approver_role"`

	// Approved status
	Approved bool `json:"approved"`

	// Timestamp of approval
	Timestamp time.Time `json:"timestamp"`

	// Comments
	Comments string `json:"comments,omitempty"`

	// Signature
	Signature []byte `json:"signature,omitempty"`
}

// CurrentSealVersion is the current seal format version
const CurrentSealVersion = 2

// NewEnhancedDigitalSeal creates a new enhanced seal from consensus results
func NewEnhancedDigitalSeal(
	jobID string,
	modelHash, inputHash, outputHash []byte,
	consensusInfo *ConsensusInfo,
	verificationBundle *VerificationBundle,
	requestedBy, purpose, chainID string,
) *EnhancedDigitalSeal {
	seal := &EnhancedDigitalSeal{
		DigitalSeal: DigitalSeal{
			ModelCommitment:  modelHash,
			InputCommitment:  inputHash,
			OutputCommitment: outputHash,
			BlockHeight:      consensusInfo.Height,
			Timestamp:        timestamppb.Now(),
			RequestedBy:      requestedBy,
			Purpose:          purpose,
			Status:           SealStatusPending,
			TeeAttestations:  make([]*TEEAttestation, 0),
			ValidatorSet:     make([]string, 0),
		},
		Version:            CurrentSealVersion,
		JobID:              jobID,
		ConsensusInfo:      consensusInfo,
		VerificationBundle: verificationBundle,
		AuditTrail:         make([]AuditEntry, 0),
		Signatures:         make([]SealSignature, 0),
		ChainID:            chainID,
	}

	// Extract validator set from verifications
	if verificationBundle != nil {
		for _, tee := range verificationBundle.TEEVerifications {
			seal.ValidatorSet = append(seal.ValidatorSet, tee.ValidatorAddress)
		}
	}

	// Generate ID
	seal.Id = seal.GenerateEnhancedID()

	// Add creation audit entry
	seal.AddAuditEntry(AuditEventCreated, requestedBy, "Seal created from consensus", consensusInfo.Height)

	// Compute seal hash
	seal.SealHash = seal.ComputeSealHash()

	return seal
}

// GenerateEnhancedID creates a unique ID for the enhanced seal
func (s *EnhancedDigitalSeal) GenerateEnhancedID() string {
	h := sha256.New()
	h.Write(s.ModelCommitment)
	h.Write(s.InputCommitment)
	h.Write(s.OutputCommitment)
	h.Write([]byte(s.JobID))
	h.Write([]byte(fmt.Sprintf("%d", s.ConsensusInfo.Height)))
	h.Write([]byte(s.RequestedBy))
	h.Write([]byte(s.ChainID))
	return hex.EncodeToString(h.Sum(nil))[:24] // 24 chars for uniqueness
}

// ComputeSealHash computes a comprehensive hash of the seal
func (s *EnhancedDigitalSeal) ComputeSealHash() []byte {
	h := sha256.New()
	h.Write([]byte(s.Id))
	h.Write(s.ModelCommitment)
	h.Write(s.InputCommitment)
	h.Write(s.OutputCommitment)
	h.Write([]byte(s.JobID))
	h.Write([]byte(fmt.Sprintf("%d", s.Version)))
	h.Write([]byte(fmt.Sprintf("%d", s.BlockHeight)))
	h.Write([]byte(s.ChainID))

	if s.VerificationBundle != nil {
		h.Write(s.VerificationBundle.AggregatedOutputHash)
		h.Write(s.VerificationBundle.BundleHash)
	}

	return h.Sum(nil)
}

// AddAuditEntry adds an entry to the audit trail
func (s *EnhancedDigitalSeal) AddAuditEntry(eventType AuditEventType, actor, details string, blockHeight int64) {
	var prevHash []byte
	if len(s.AuditTrail) > 0 {
		prevEntry := s.AuditTrail[len(s.AuditTrail)-1]
		h := sha256.New()
		h.Write([]byte(prevEntry.Timestamp.String()))
		h.Write([]byte(prevEntry.EventType))
		h.Write([]byte(prevEntry.Actor))
		prevHash = h.Sum(nil)
	}

	entry := AuditEntry{
		Timestamp:         time.Now().UTC(),
		EventType:         eventType,
		Actor:             actor,
		Details:           details,
		BlockHeight:       blockHeight,
		PreviousStateHash: prevHash,
	}

	s.AuditTrail = append(s.AuditTrail, entry)
}

// Activate activates the seal and adds audit entry
func (s *EnhancedDigitalSeal) Activate(actor string, blockHeight int64) {
	s.Status = SealStatusActive
	s.AddAuditEntry(AuditEventActivated, actor, "Seal activated after consensus verification", blockHeight)
	s.SealHash = s.ComputeSealHash()
}

// Revoke revokes the seal with reason
func (s *EnhancedDigitalSeal) Revoke(actor, reason string, blockHeight int64) {
	s.Status = SealStatusRevoked
	s.AddAuditEntry(AuditEventRevoked, actor, fmt.Sprintf("Seal revoked: %s", reason), blockHeight)
	s.SealHash = s.ComputeSealHash()
}

// RecordAccess records an access to the seal
func (s *EnhancedDigitalSeal) RecordAccess(actor, purpose string, blockHeight int64) {
	s.AddAuditEntry(AuditEventAccessed, actor, fmt.Sprintf("Accessed for: %s", purpose), blockHeight)
}

// AddSignature adds a signature to the seal
func (s *EnhancedDigitalSeal) AddSignature(sig SealSignature) {
	s.Signatures = append(s.Signatures, sig)
}

// ValidateEnhanced performs comprehensive validation
func (s *EnhancedDigitalSeal) ValidateEnhanced() error {
	// Basic validation
	if err := s.Validate(); err != nil {
		return err
	}

	// Version check
	if s.Version < 1 || s.Version > CurrentSealVersion {
		return fmt.Errorf("unsupported seal version: %d", s.Version)
	}

	// Job ID required
	if len(s.JobID) == 0 {
		return fmt.Errorf("job ID is required")
	}

	// Chain ID required
	if len(s.ChainID) == 0 {
		return fmt.Errorf("chain ID is required")
	}

	// Consensus info required
	if s.ConsensusInfo == nil {
		return fmt.Errorf("consensus info is required")
	}

	// Verification bundle required
	if s.VerificationBundle == nil {
		return fmt.Errorf("verification bundle is required")
	}

	// Validate verification bundle
	if err := s.validateVerificationBundle(); err != nil {
		return fmt.Errorf("invalid verification bundle: %w", err)
	}

	return nil
}

// validateVerificationBundle validates the verification bundle
func (s *EnhancedDigitalSeal) validateVerificationBundle() error {
	bundle := s.VerificationBundle

	if len(bundle.VerificationType) == 0 {
		return fmt.Errorf("verification type is required")
	}

	if len(bundle.AggregatedOutputHash) != 32 {
		return fmt.Errorf("aggregated output hash must be 32 bytes")
	}

	switch bundle.VerificationType {
	case "tee":
		if len(bundle.TEEVerifications) == 0 {
			return fmt.Errorf("TEE verifications required for TEE type")
		}
	case "zkml":
		if bundle.ZKMLVerification == nil {
			return fmt.Errorf("zkML verification required for zkML type")
		}
	case "hybrid":
		if bundle.HybridVerification == nil {
			return fmt.Errorf("hybrid verification required for hybrid type")
		}
	default:
		return fmt.Errorf("unknown verification type: %s", bundle.VerificationType)
	}

	return nil
}

// VerifyOutputConsistency checks if all verifications agree on the output
func (s *EnhancedDigitalSeal) VerifyOutputConsistency() bool {
	if s.VerificationBundle == nil {
		return false
	}

	expectedOutput := s.VerificationBundle.AggregatedOutputHash

	for _, tee := range s.VerificationBundle.TEEVerifications {
		if !bytes.Equal(tee.OutputHash, expectedOutput) {
			return false
		}
	}

	return true
}

// GetVerificationSummary returns a summary of the verification
func (s *EnhancedDigitalSeal) GetVerificationSummary() *VerificationSummary {
	summary := &VerificationSummary{
		SealID:           s.Id,
		VerificationType: s.VerificationBundle.VerificationType,
		IsValid:          s.Status == SealStatusActive,
		ConsensusReached: s.ConsensusInfo.AgreementCount >= (s.ConsensusInfo.TotalValidators*2/3)+1,
	}

	if s.VerificationBundle != nil {
		summary.TEECount = len(s.VerificationBundle.TEEVerifications)
		summary.HasZKML = s.VerificationBundle.ZKMLVerification != nil
		summary.OutputHash = s.VerificationBundle.AggregatedOutputHash
	}

	if s.ConsensusInfo != nil {
		summary.ValidatorsParticipated = s.ConsensusInfo.ParticipatingValidators
		summary.ValidatorsAgreed = s.ConsensusInfo.AgreementCount
		summary.TotalValidators = s.ConsensusInfo.TotalValidators
	}

	return summary
}

// VerificationSummary provides a quick overview of verification
type VerificationSummary struct {
	SealID                 string `json:"seal_id"`
	VerificationType       string `json:"verification_type"`
	IsValid                bool   `json:"is_valid"`
	ConsensusReached       bool   `json:"consensus_reached"`
	TEECount               int    `json:"tee_count"`
	HasZKML                bool   `json:"has_zkml"`
	ValidatorsParticipated int    `json:"validators_participated"`
	ValidatorsAgreed       int    `json:"validators_agreed"`
	TotalValidators        int    `json:"total_validators"`
	OutputHash             []byte `json:"output_hash"`
}

// ToJSON serializes the seal to JSON
func (s *EnhancedDigitalSeal) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

// ToCBOR serializes the seal to CBOR (simulated as JSON for MVP)
func (s *EnhancedDigitalSeal) ToCBOR() ([]byte, error) {
	// In production: use cbor library
	return json.Marshal(s)
}

// FromJSON deserializes a seal from JSON
func FromJSON(data []byte) (*EnhancedDigitalSeal, error) {
	var seal EnhancedDigitalSeal
	if err := json.Unmarshal(data, &seal); err != nil {
		return nil, err
	}
	return &seal, nil
}
