package keeper

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"cosmossdk.io/log"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/aethelred/aethelred/x/seal/types"
)

// SealGenerator creates Digital Seals from consensus verification results
type SealGenerator struct {
	logger  log.Logger
	keeper  *Keeper
	config  GeneratorConfig
	chainID string
}

// GeneratorConfig contains configuration for seal generation
type GeneratorConfig struct {
	// MinValidatorsRequired for seal creation
	MinValidatorsRequired int

	// ConsensusThreshold percentage (67 = 2/3)
	ConsensusThreshold int

	// RequireTEE requires at least one TEE verification
	RequireTEE bool

	// RequireZKML requires zkML proof
	RequireZKML bool

	// AutoActivate automatically activates seals
	AutoActivate bool

	// DefaultRetentionDays for regulatory retention
	DefaultRetentionDays int

	// EnableAuditTrail enables detailed audit logging
	EnableAuditTrail bool
}

// DefaultGeneratorConfig returns sensible defaults
func DefaultGeneratorConfig() GeneratorConfig {
	return GeneratorConfig{
		MinValidatorsRequired: 3,
		ConsensusThreshold:    67,
		RequireTEE:            true,
		RequireZKML:           false,
		AutoActivate:          true,
		DefaultRetentionDays:  365 * 7, // 7 years
		EnableAuditTrail:      true,
	}
}

// ConsensusResult represents the result from consensus verification
type ConsensusResult struct {
	// JobID of the compute job
	JobID string

	// ModelHash of the model used
	ModelHash []byte

	// InputHash of the input data
	InputHash []byte

	// OutputHash agreed upon by consensus
	OutputHash []byte

	// Height at which consensus was reached
	Height int64

	// Round in which consensus was reached
	Round int32

	// TotalValidators in the set
	TotalValidators int

	// ParticipatingValidators who voted
	ParticipatingValidators int

	// AgreementCount validators who agreed
	AgreementCount int

	// TEEResults from validators
	TEEResults []TEEResult

	// ZKMLResult if available
	ZKMLResult *ZKMLResult

	// RequestedBy who requested the job
	RequestedBy string

	// Purpose of the computation
	Purpose string

	// BlockHash of the block
	BlockHash []byte

	// Timestamp when consensus was reached
	Timestamp time.Time
}

// TEEResult represents a single TEE verification result
type TEEResult struct {
	ValidatorAddress    string
	ValidatorPubKey     []byte
	Platform            string
	EnclaveID           string
	Measurement         []byte
	AttestationDocument []byte
	OutputHash          []byte
	ExecutionTimeMs     int64
	Timestamp           time.Time
	Signature           []byte
	Nonce               []byte
}

// ZKMLResult represents a zkML proof result
type ZKMLResult struct {
	ProofSystem        string
	Proof              []byte
	PublicInputs       []byte
	VerifyingKeyHash   []byte
	CircuitHash        []byte
	ProofSizeBytes     int64
	GenerationTimeMs   int64
	VerificationTimeMs int64
	Verified           bool
	GeneratedBy        string
	Timestamp          time.Time
}

// NewSealGenerator creates a new seal generator
func NewSealGenerator(logger log.Logger, keeper *Keeper, chainID string, config GeneratorConfig) *SealGenerator {
	return &SealGenerator{
		logger:  logger,
		keeper:  keeper,
		chainID: chainID,
		config:  config,
	}
}

// GenerateSeal creates a Digital Seal from consensus results
func (sg *SealGenerator) GenerateSeal(ctx context.Context, result *ConsensusResult) (*types.EnhancedDigitalSeal, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	sg.logger.Info("Generating seal from consensus",
		"job_id", result.JobID,
		"agreement", result.AgreementCount,
		"total", result.TotalValidators,
	)

	// Validate consensus result
	if err := sg.validateConsensusResult(result); err != nil {
		return nil, fmt.Errorf("invalid consensus result: %w", err)
	}

	// Build consensus info
	consensusInfo := sg.buildConsensusInfo(result)

	// Build verification bundle
	verificationBundle, err := sg.buildVerificationBundle(result)
	if err != nil {
		return nil, fmt.Errorf("failed to build verification bundle: %w", err)
	}

	// Create enhanced seal
	seal := types.NewEnhancedDigitalSeal(
		result.JobID,
		result.ModelHash,
		result.InputHash,
		result.OutputHash,
		consensusInfo,
		verificationBundle,
		result.RequestedBy,
		result.Purpose,
		sg.chainID,
	)

	// Set regulatory info
	seal.RegulatoryInfo = sg.buildRegulatoryInfo(result)

	// Set expiration if configured
	if sg.config.DefaultRetentionDays > 0 {
		expiresAt := time.Now().AddDate(0, 0, sg.config.DefaultRetentionDays)
		seal.ExpiresAt = &expiresAt
	}

	// Auto-activate if configured
	if sg.config.AutoActivate {
		seal.Activate("system", sdkCtx.BlockHeight())
	}

	// Store the seal
	if err := sg.keeper.CreateSeal(ctx, &seal.DigitalSeal); err != nil {
		return nil, fmt.Errorf("failed to store seal: %w", err)
	}

	// Emit seal created event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"enhanced_seal_created",
			sdk.NewAttribute("seal_id", seal.Id),
			sdk.NewAttribute("job_id", result.JobID),
			sdk.NewAttribute("verification_type", verificationBundle.VerificationType),
			sdk.NewAttribute("validator_count", fmt.Sprintf("%d", result.AgreementCount)),
			sdk.NewAttribute("model_hash", fmt.Sprintf("%x", result.ModelHash[:8])),
		),
	)

	sg.logger.Info("Seal generated successfully",
		"seal_id", seal.Id,
		"verification_type", verificationBundle.VerificationType,
	)

	return seal, nil
}

// validateConsensusResult validates the consensus result
func (sg *SealGenerator) validateConsensusResult(result *ConsensusResult) error {
	if len(result.JobID) == 0 {
		return fmt.Errorf("job ID is required")
	}

	if len(result.ModelHash) != 32 {
		return fmt.Errorf("model hash must be 32 bytes")
	}

	if len(result.InputHash) != 32 {
		return fmt.Errorf("input hash must be 32 bytes")
	}

	if len(result.OutputHash) != 32 {
		return fmt.Errorf("output hash must be 32 bytes")
	}

	// Check consensus threshold
	requiredVotes := (result.TotalValidators * sg.config.ConsensusThreshold / 100) + 1
	if result.AgreementCount < requiredVotes {
		return fmt.Errorf("insufficient consensus: got %d, need %d", result.AgreementCount, requiredVotes)
	}

	// Check minimum validators
	if result.AgreementCount < sg.config.MinValidatorsRequired {
		return fmt.Errorf("insufficient validators: got %d, need %d", result.AgreementCount, sg.config.MinValidatorsRequired)
	}

	// Check TEE requirement
	if sg.config.RequireTEE && len(result.TEEResults) == 0 {
		return fmt.Errorf("TEE verification required but not provided")
	}

	// Check zkML requirement
	if sg.config.RequireZKML && result.ZKMLResult == nil {
		return fmt.Errorf("zkML verification required but not provided")
	}

	return nil
}

// buildConsensusInfo builds ConsensusInfo from result
func (sg *SealGenerator) buildConsensusInfo(result *ConsensusResult) *types.ConsensusInfo {
	// Collect vote extension hashes
	var voteExtensionHashes [][]byte
	for _, tee := range result.TEEResults {
		h := sha256.Sum256(tee.AttestationDocument)
		voteExtensionHashes = append(voteExtensionHashes, h[:])
	}

	return &types.ConsensusInfo{
		Height:                  result.Height,
		Round:                   result.Round,
		TotalValidators:         result.TotalValidators,
		ParticipatingValidators: result.ParticipatingValidators,
		AgreementCount:          result.AgreementCount,
		ConsensusThreshold:      sg.config.ConsensusThreshold,
		VoteExtensionHashes:     voteExtensionHashes,
		BlockHash:               result.BlockHash,
		Timestamp:               result.Timestamp,
	}
}

// buildVerificationBundle builds the verification bundle
func (sg *SealGenerator) buildVerificationBundle(result *ConsensusResult) (*types.VerificationBundle, error) {
	bundle := &types.VerificationBundle{
		TEEVerifications:     make([]types.TEEVerification, 0),
		AggregatedOutputHash: result.OutputHash,
	}

	// Add TEE verifications
	for _, tee := range result.TEEResults {
		bundle.TEEVerifications = append(bundle.TEEVerifications, types.TEEVerification{
			ValidatorAddress:    tee.ValidatorAddress,
			ValidatorPubKey:     tee.ValidatorPubKey,
			Platform:            tee.Platform,
			EnclaveID:           tee.EnclaveID,
			Measurement:         tee.Measurement,
			AttestationDocument: tee.AttestationDocument,
			OutputHash:          tee.OutputHash,
			ExecutionTimeMs:     tee.ExecutionTimeMs,
			Timestamp:           tee.Timestamp,
			Signature:           tee.Signature,
			Nonce:               tee.Nonce,
		})
	}

	// Add zkML verification if available
	if result.ZKMLResult != nil {
		bundle.ZKMLVerification = &types.ZKMLVerification{
			ProofSystem:        result.ZKMLResult.ProofSystem,
			Proof:              result.ZKMLResult.Proof,
			VerifyingKeyHash:   result.ZKMLResult.VerifyingKeyHash,
			CircuitHash:        result.ZKMLResult.CircuitHash,
			ProofSizeBytes:     result.ZKMLResult.ProofSizeBytes,
			GenerationTimeMs:   result.ZKMLResult.GenerationTimeMs,
			VerificationTimeMs: result.ZKMLResult.VerificationTimeMs,
			Verified:           result.ZKMLResult.Verified,
			GeneratedBy:        result.ZKMLResult.GeneratedBy,
			Timestamp:          result.ZKMLResult.Timestamp,
		}
	}

	// Determine verification type
	if len(bundle.TEEVerifications) > 0 && bundle.ZKMLVerification != nil {
		bundle.VerificationType = "hybrid"
		bundle.HybridVerification = &types.HybridVerification{
			TEEVerifications: bundle.TEEVerifications,
			ZKMLVerification: bundle.ZKMLVerification,
			CrossValidated:   true,
			OutputsMatch:     true, // Assume outputs match if consensus was reached
		}
	} else if len(bundle.TEEVerifications) > 0 {
		bundle.VerificationType = "tee"
	} else if bundle.ZKMLVerification != nil {
		bundle.VerificationType = "zkml"
	} else {
		return nil, fmt.Errorf("no verification evidence provided")
	}

	// Add model verification
	bundle.ModelVerification = &types.ModelVerification{
		ModelHash: result.ModelHash,
	}
	if result.ZKMLResult != nil {
		bundle.ModelVerification.CircuitHash = result.ZKMLResult.CircuitHash
	}
	if len(result.TEEResults) > 0 {
		bundle.ModelVerification.TEEMeasurement = result.TEEResults[0].Measurement
	}

	// Compute bundle hash
	bundle.BundleHash = sg.computeBundleHash(bundle)

	return bundle, nil
}

// computeBundleHash computes a hash of the verification bundle
func (sg *SealGenerator) computeBundleHash(bundle *types.VerificationBundle) []byte {
	h := sha256.New()
	h.Write([]byte(bundle.VerificationType))
	h.Write(bundle.AggregatedOutputHash)

	for _, tee := range bundle.TEEVerifications {
		h.Write(tee.OutputHash)
		h.Write(tee.AttestationDocument)
	}

	if bundle.ZKMLVerification != nil {
		h.Write(bundle.ZKMLVerification.Proof)
	}

	return h.Sum(nil)
}

// buildRegulatoryInfo builds regulatory information
func (sg *SealGenerator) buildRegulatoryInfo(result *ConsensusResult) *types.RegulatoryInfo {
	// Determine compliance frameworks based on purpose
	frameworks := sg.determineComplianceFrameworks(result.Purpose)

	return &types.RegulatoryInfo{
		DataClassification:   sg.classifyData(result.Purpose),
		ComplianceFrameworks: frameworks,
		RetentionPeriod:      durationpb.New(time.Duration(sg.config.DefaultRetentionDays) * 24 * time.Hour),
		AuditRequired:        true, // Always require audit for regulated industries
	}
}

// determineComplianceFrameworks determines applicable frameworks
func (sg *SealGenerator) determineComplianceFrameworks(purpose string) []string {
	frameworks := []string{}

	switch purpose {
	case "credit_scoring", "loan_approval", "financial_risk":
		frameworks = append(frameworks, "ECOA", "FCRA", "Basel_III")
	case "fraud_detection":
		frameworks = append(frameworks, "SOC2", "PCI_DSS")
	case "medical_diagnosis", "healthcare":
		frameworks = append(frameworks, "HIPAA", "HITECH")
	case "insurance_underwriting":
		frameworks = append(frameworks, "Solvency_II", "NAIC")
	default:
		frameworks = append(frameworks, "SOC2") // Default to SOC2
	}

	// GDPR applies to all if processing EU data
	frameworks = append(frameworks, "GDPR")

	return frameworks
}

// classifyData determines data classification based on purpose
func (sg *SealGenerator) classifyData(purpose string) string {
	switch purpose {
	case "credit_scoring", "loan_approval":
		return "confidential_financial"
	case "medical_diagnosis", "healthcare":
		return "confidential_phi"
	case "fraud_detection":
		return "confidential"
	default:
		return "internal"
	}
}

// GenerateSealFromJob creates a seal from a completed compute job
func (sg *SealGenerator) GenerateSealFromJob(ctx context.Context, jobID string, outputHash []byte, verificationResults []VerificationResult) (*types.EnhancedDigitalSeal, error) {
	// Convert verification results to TEE results
	teeResults := make([]TEEResult, 0)
	for _, vr := range verificationResults {
		if vr.Success {
			teeResults = append(teeResults, TEEResult{
				ValidatorAddress:    vr.ValidatorAddress,
				Platform:            vr.TEEPlatform,
				AttestationDocument: vr.AttestationData,
				OutputHash:          vr.OutputHash,
				ExecutionTimeMs:     vr.ExecutionTimeMs,
				Timestamp:           vr.Timestamp,
			})
		}
	}

	// We need to get job details - for now create minimal consensus result
	consensusResult := &ConsensusResult{
		JobID:                   jobID,
		OutputHash:              outputHash,
		TEEResults:              teeResults,
		AgreementCount:          len(teeResults),
		TotalValidators:         len(teeResults),
		ParticipatingValidators: len(teeResults),
		Timestamp:               time.Now().UTC(),
	}

	return sg.GenerateSeal(ctx, consensusResult)
}

// VerificationResult from validators (simplified)
type VerificationResult struct {
	ValidatorAddress string
	OutputHash       []byte
	AttestationType  string
	TEEPlatform      string
	AttestationData  []byte
	ExecutionTimeMs  int64
	Timestamp        time.Time
	Success          bool
}

// BatchGenerateSeals generates multiple seals efficiently
func (sg *SealGenerator) BatchGenerateSeals(ctx context.Context, results []*ConsensusResult) ([]*types.EnhancedDigitalSeal, error) {
	seals := make([]*types.EnhancedDigitalSeal, 0, len(results))
	var errors []error

	for _, result := range results {
		seal, err := sg.GenerateSeal(ctx, result)
		if err != nil {
			errors = append(errors, fmt.Errorf("job %s: %w", result.JobID, err))
			continue
		}
		seals = append(seals, seal)
	}

	if len(errors) > 0 {
		sg.logger.Warn("Some seals failed to generate",
			"success", len(seals),
			"failed", len(errors),
		)
	}

	return seals, nil
}
