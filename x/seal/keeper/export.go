package keeper

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"cosmossdk.io/log"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/seal/types"
)

// SealExporter handles seal export in various formats
type SealExporter struct {
	logger   log.Logger
	keeper   *Keeper
	verifier *SealVerifier
}

// ExportFormat represents supported export formats
type ExportFormat string

const (
	ExportFormatJSON     ExportFormat = "json"
	ExportFormatCBOR     ExportFormat = "cbor"
	ExportFormatCompact  ExportFormat = "compact"
	ExportFormatPortable ExportFormat = "portable"
	ExportFormatAudit    ExportFormat = "audit"
)

// ExportOptions configures export behavior
type ExportOptions struct {
	// Format to export in
	Format ExportFormat

	// IncludeProofs includes full proof data
	IncludeProofs bool

	// IncludeAttestations includes full attestation data
	IncludeAttestations bool

	// IncludeAuditTrail includes audit trail
	IncludeAuditTrail bool

	// VerifyBeforeExport verifies seal before exporting
	VerifyBeforeExport bool

	// AddExportSignature adds export signature
	AddExportSignature bool

	// ExporterAddress for audit
	ExporterAddress string
}

// DefaultExportOptions returns default options
func DefaultExportOptions() ExportOptions {
	return ExportOptions{
		Format:              ExportFormatJSON,
		IncludeProofs:       true,
		IncludeAttestations: true,
		IncludeAuditTrail:   true,
		VerifyBeforeExport:  true,
		AddExportSignature:  false,
	}
}

// ExportedSeal represents an exported seal package
type ExportedSeal struct {
	// Version of the export format
	Version string `json:"version"`

	// Format used
	Format ExportFormat `json:"format"`

	// Seal data
	Seal interface{} `json:"seal"`

	// Verification result if verified before export
	Verification *SealVerificationResult `json:"verification,omitempty"`

	// ExportMetadata
	Metadata *ExportMetadata `json:"metadata"`

	// Signature over the export (optional)
	Signature *ExportSignature `json:"signature,omitempty"`
}

// ExportMetadata contains metadata about the export
type ExportMetadata struct {
	// ExportedAt timestamp
	ExportedAt time.Time `json:"exported_at"`

	// ExportedBy address
	ExportedBy string `json:"exported_by"`

	// ChainID of source chain
	ChainID string `json:"chain_id"`

	// BlockHeight at export time
	BlockHeight int64 `json:"block_height"`

	// ContentHash of the exported data
	ContentHash string `json:"content_hash"`

	// ExportReason for audit
	ExportReason string `json:"export_reason,omitempty"`
}

// ExportSignature provides signature over the export
type ExportSignature struct {
	// SignerAddress
	SignerAddress string `json:"signer_address"`

	// Algorithm used
	Algorithm string `json:"algorithm"`

	// Signature bytes (base64)
	Signature string `json:"signature"`

	// Timestamp when signed
	Timestamp time.Time `json:"timestamp"`
}

// CompactSeal is a minimal seal representation
type CompactSeal struct {
	ID               string `json:"id"`
	ModelHash        string `json:"model_hash"`
	InputHash        string `json:"input_hash"`
	OutputHash       string `json:"output_hash"`
	VerificationType string `json:"verification_type"`
	Status           string `json:"status"`
	BlockHeight      int64  `json:"block_height"`
	ValidatorCount   int    `json:"validator_count"`
	Timestamp        string `json:"timestamp"`
}

// PortableSeal is designed for cross-system portability
type PortableSeal struct {
	// Header information
	Header PortableSealHeader `json:"header"`

	// Core seal data
	Core PortableSealCore `json:"core"`

	// Verification evidence
	Evidence PortableSealEvidence `json:"evidence"`

	// Compliance information
	Compliance PortableSealCompliance `json:"compliance"`
}

// PortableSealHeader contains header info
type PortableSealHeader struct {
	Version     string    `json:"version"`
	SealID      string    `json:"seal_id"`
	ChainID     string    `json:"chain_id"`
	BlockHeight int64     `json:"block_height"`
	Timestamp   time.Time `json:"timestamp"`
}

// PortableSealCore contains core seal data
type PortableSealCore struct {
	ModelCommitment  string `json:"model_commitment"`
	InputCommitment  string `json:"input_commitment"`
	OutputCommitment string `json:"output_commitment"`
	Purpose          string `json:"purpose"`
	RequestedBy      string `json:"requested_by"`
	Status           string `json:"status"`
}

// PortableSealEvidence contains verification evidence
type PortableSealEvidence struct {
	VerificationType string   `json:"verification_type"`
	ValidatorCount   int      `json:"validator_count"`
	Validators       []string `json:"validators"`
	HasZKProof       bool     `json:"has_zk_proof"`
	ProofSystem      string   `json:"proof_system,omitempty"`
}

// PortableSealCompliance contains compliance info
type PortableSealCompliance struct {
	Frameworks         []string `json:"frameworks"`
	DataClassification string   `json:"data_classification"`
	AuditRequired      bool     `json:"audit_required"`
}

// AuditExport is a detailed export for audit purposes
type AuditExport struct {
	// Seal information
	SealID           string `json:"seal_id"`
	JobID            string `json:"job_id,omitempty"`
	ModelHash        string `json:"model_hash"`
	InputHash        string `json:"input_hash"`
	OutputHash       string `json:"output_hash"`

	// Verification details
	VerificationType string                    `json:"verification_type"`
	TEEAttestations  []AuditTEEAttestation     `json:"tee_attestations"`
	ZKMLProof        *AuditZKMLProof           `json:"zkml_proof,omitempty"`

	// Consensus details
	Consensus        *AuditConsensus           `json:"consensus,omitempty"`

	// Compliance
	Compliance       AuditCompliance           `json:"compliance"`

	// Audit trail
	AuditTrail       []AuditTrailEntry         `json:"audit_trail"`

	// Chain info
	ChainInfo        AuditChainInfo            `json:"chain_info"`
}

// AuditTEEAttestation for audit export
type AuditTEEAttestation struct {
	ValidatorAddress string `json:"validator_address"`
	Platform         string `json:"platform"`
	EnclaveID        string `json:"enclave_id"`
	MeasurementHash  string `json:"measurement_hash"`
	QuoteHash        string `json:"quote_hash"`
	Timestamp        string `json:"timestamp"`
}

// AuditZKMLProof for audit export
type AuditZKMLProof struct {
	ProofSystem      string `json:"proof_system"`
	ProofHash        string `json:"proof_hash"`
	VerifyingKeyHash string `json:"verifying_key_hash"`
	CircuitHash      string `json:"circuit_hash,omitempty"`
	ProofSizeBytes   int64  `json:"proof_size_bytes"`
}

// AuditConsensus for audit export
type AuditConsensus struct {
	Height              int64  `json:"height"`
	TotalValidators     int    `json:"total_validators"`
	ParticipatingCount  int    `json:"participating_count"`
	AgreementCount      int    `json:"agreement_count"`
	ConsensusThreshold  int    `json:"consensus_threshold"`
	Timestamp           string `json:"timestamp"`
}

// AuditCompliance for audit export
type AuditCompliance struct {
	Frameworks         []string `json:"frameworks"`
	DataClassification string   `json:"data_classification"`
	RetentionPeriod    string   `json:"retention_period"`
	AuditRequired      bool     `json:"audit_required"`
}

// AuditTrailEntry for audit export
type AuditTrailEntry struct {
	Timestamp   string `json:"timestamp"`
	EventType   string `json:"event_type"`
	Actor       string `json:"actor"`
	Details     string `json:"details"`
	BlockHeight int64  `json:"block_height"`
}

// AuditChainInfo for audit export
type AuditChainInfo struct {
	ChainID         string `json:"chain_id"`
	BlockHeight     int64  `json:"block_height"`
	BlockHash       string `json:"block_hash,omitempty"`
	TransactionHash string `json:"transaction_hash,omitempty"`
}

// NewSealExporter creates a new seal exporter
func NewSealExporter(logger log.Logger, keeper *Keeper, verifier *SealVerifier) *SealExporter {
	return &SealExporter{
		logger:   logger,
		keeper:   keeper,
		verifier: verifier,
	}
}

// Export exports a seal in the specified format
func (se *SealExporter) Export(ctx context.Context, sealID string, options ExportOptions) (*ExportedSeal, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Get the seal
	seal, err := se.keeper.GetSeal(ctx, sealID)
	if err != nil {
		return nil, err
	}

	// Verify if requested
	var verification *SealVerificationResult
	if options.VerifyBeforeExport {
		verification, err = se.verifier.VerifySeal(ctx, sealID)
		if err != nil {
			return nil, fmt.Errorf("verification failed: %w", err)
		}
		if !verification.Valid {
			return nil, fmt.Errorf("seal verification failed: %s", verification.Summary)
		}
	}

	// Create export based on format
	var sealData interface{}
	switch options.Format {
	case ExportFormatJSON:
		sealData = seal
	case ExportFormatCompact:
		sealData = se.toCompactSeal(seal)
	case ExportFormatPortable:
		sealData = se.toPortableSeal(seal, sdkCtx)
	case ExportFormatAudit:
		sealData = se.toAuditExport(seal, sdkCtx)
	default:
		sealData = seal
	}

	// Build export
	export := &ExportedSeal{
		Version:      "1.0",
		Format:       options.Format,
		Seal:         sealData,
		Verification: verification,
		Metadata: &ExportMetadata{
			ExportedAt:  time.Now().UTC(),
			ExportedBy:  options.ExporterAddress,
			ChainID:     sdkCtx.ChainID(),
			BlockHeight: sdkCtx.BlockHeight(),
		},
	}

	// Compute content hash
	contentBytes, _ := json.Marshal(sealData)
	contentHash := sha256.Sum256(contentBytes)
	export.Metadata.ContentHash = hex.EncodeToString(contentHash[:])

	// Record export event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"seal_exported",
			sdk.NewAttribute("seal_id", sealID),
			sdk.NewAttribute("format", string(options.Format)),
			sdk.NewAttribute("exported_by", options.ExporterAddress),
		),
	)

	se.logger.Info("Seal exported",
		"seal_id", sealID,
		"format", options.Format,
	)

	return export, nil
}

// toCompactSeal converts to compact format
func (se *SealExporter) toCompactSeal(seal *types.DigitalSeal) *CompactSeal {
	timestamp := ""
	if seal.Timestamp != nil {
		timestamp = seal.Timestamp.AsTime().UTC().Format(time.RFC3339)
	}

	return &CompactSeal{
		ID:               seal.Id,
		ModelHash:        hex.EncodeToString(seal.ModelCommitment),
		InputHash:        hex.EncodeToString(seal.InputCommitment),
		OutputHash:       hex.EncodeToString(seal.OutputCommitment),
		VerificationType: seal.GetVerificationType(),
		Status:           seal.Status.String(),
		BlockHeight:      seal.BlockHeight,
		ValidatorCount:   len(seal.ValidatorSet),
		Timestamp:        timestamp,
	}
}

// toPortableSeal converts to portable format
func (se *SealExporter) toPortableSeal(seal *types.DigitalSeal, sdkCtx sdk.Context) *PortableSeal {
	createdAt := time.Time{}
	if seal.Timestamp != nil {
		createdAt = seal.Timestamp.AsTime()
	}

	compliance := PortableSealCompliance{}
	if seal.RegulatoryInfo != nil {
		compliance.Frameworks = seal.RegulatoryInfo.ComplianceFrameworks
		compliance.DataClassification = seal.RegulatoryInfo.DataClassification
		compliance.AuditRequired = seal.RegulatoryInfo.AuditRequired
	}

	portable := &PortableSeal{
		Header: PortableSealHeader{
			Version:     "1.0",
			SealID:      seal.Id,
			ChainID:     sdkCtx.ChainID(),
			BlockHeight: seal.BlockHeight,
			Timestamp:   createdAt,
		},
		Core: PortableSealCore{
			ModelCommitment:  hex.EncodeToString(seal.ModelCommitment),
			InputCommitment:  hex.EncodeToString(seal.InputCommitment),
			OutputCommitment: hex.EncodeToString(seal.OutputCommitment),
			Purpose:          seal.Purpose,
			RequestedBy:      seal.RequestedBy,
			Status:           seal.Status.String(),
		},
		Evidence: PortableSealEvidence{
			VerificationType: seal.GetVerificationType(),
			ValidatorCount:   len(seal.ValidatorSet),
			Validators:       seal.ValidatorSet,
			HasZKProof:       seal.ZkProof != nil,
		},
		Compliance: compliance,
	}

	if seal.ZkProof != nil {
		portable.Evidence.ProofSystem = seal.ZkProof.ProofSystem
	}

	return portable
}

// toAuditExport converts to audit export format
func (se *SealExporter) toAuditExport(seal *types.DigitalSeal, sdkCtx sdk.Context) *AuditExport {
	compliance := AuditCompliance{}
	if seal.RegulatoryInfo != nil {
		compliance.Frameworks = seal.RegulatoryInfo.ComplianceFrameworks
		compliance.DataClassification = seal.RegulatoryInfo.DataClassification
		if seal.RegulatoryInfo.RetentionPeriod != nil {
			compliance.RetentionPeriod = seal.RegulatoryInfo.RetentionPeriod.AsDuration().String()
		}
		compliance.AuditRequired = seal.RegulatoryInfo.AuditRequired
	}

	audit := &AuditExport{
		SealID:           seal.Id,
		ModelHash:        hex.EncodeToString(seal.ModelCommitment),
		InputHash:        hex.EncodeToString(seal.InputCommitment),
		OutputHash:       hex.EncodeToString(seal.OutputCommitment),
		VerificationType: seal.GetVerificationType(),
		TEEAttestations:  make([]AuditTEEAttestation, 0),
		Compliance:      compliance,
		AuditTrail: make([]AuditTrailEntry, 0),
		ChainInfo: AuditChainInfo{
			ChainID:     sdkCtx.ChainID(),
			BlockHeight: seal.BlockHeight,
		},
	}

	// Add TEE attestations
	for _, att := range seal.TeeAttestations {
		if att == nil {
			continue
		}
		attTimestamp := ""
		if att.Timestamp != nil {
			attTimestamp = att.Timestamp.AsTime().UTC().Format(time.RFC3339)
		}
		audit.TEEAttestations = append(audit.TEEAttestations, AuditTEEAttestation{
			ValidatorAddress: att.ValidatorAddress,
			Platform:         att.Platform,
			EnclaveID:        att.EnclaveId,
			MeasurementHash:  hex.EncodeToString(att.Measurement),
			QuoteHash:        hex.EncodeToString(sha256Hash(att.Quote)),
			Timestamp:        attTimestamp,
		})
	}

	// Add zkML proof
	if seal.ZkProof != nil {
		audit.ZKMLProof = &AuditZKMLProof{
			ProofSystem:      seal.ZkProof.ProofSystem,
			ProofHash:        hex.EncodeToString(sha256Hash(seal.ZkProof.ProofBytes)),
			VerifyingKeyHash: hex.EncodeToString(seal.ZkProof.VerifyingKeyHash),
			CircuitHash:      hex.EncodeToString(seal.ZkProof.CircuitHash),
			ProofSizeBytes:   int64(len(seal.ZkProof.ProofBytes)),
		}
	}

	return audit
}

// ExportBatch exports multiple seals
func (se *SealExporter) ExportBatch(ctx context.Context, sealIDs []string, options ExportOptions) ([]*ExportedSeal, error) {
	exports := make([]*ExportedSeal, 0, len(sealIDs))

	for _, sealID := range sealIDs {
		export, err := se.Export(ctx, sealID, options)
		if err != nil {
			se.logger.Warn("Failed to export seal",
				"seal_id", sealID,
				"error", err,
			)
			continue
		}
		exports = append(exports, export)
	}

	return exports, nil
}

// ExportToBase64 exports seal as base64-encoded JSON
func (se *SealExporter) ExportToBase64(ctx context.Context, sealID string, options ExportOptions) (string, error) {
	export, err := se.Export(ctx, sealID, options)
	if err != nil {
		return "", err
	}

	jsonBytes, err := json.Marshal(export)
	if err != nil {
		return "", fmt.Errorf("failed to marshal export: %w", err)
	}

	return base64.StdEncoding.EncodeToString(jsonBytes), nil
}

// ImportFromBase64 imports a seal from base64-encoded JSON
func (se *SealExporter) ImportFromBase64(data string) (*ExportedSeal, error) {
	jsonBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	var export ExportedSeal
	if err := json.Unmarshal(jsonBytes, &export); err != nil {
		return nil, fmt.Errorf("failed to unmarshal export: %w", err)
	}

	return &export, nil
}

// sha256Hash computes SHA-256 hash
func sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}
