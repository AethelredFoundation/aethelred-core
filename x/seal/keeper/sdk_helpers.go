package keeper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cosmossdk.io/log"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// SDKHelper provides helper functions for SDK integrations
type SDKHelper struct {
	logger   log.Logger
	keeper   *Keeper
	verifier *SealVerifier
	exporter *SealExporter
}

// NewSDKHelper creates a new SDK helper
func NewSDKHelper(logger log.Logger, keeper *Keeper, verifier *SealVerifier, exporter *SealExporter) *SDKHelper {
	return &SDKHelper{
		logger:   logger,
		keeper:   keeper,
		verifier: verifier,
		exporter: exporter,
	}
}

// QuickVerifyResponse is a simplified verification response for SDK users
type QuickVerifyResponse struct {
	// SealID being verified
	SealID string `json:"seal_id"`

	// IsValid indicates overall validity
	IsValid bool `json:"is_valid"`

	// VerificationType used (tee, zkml, hybrid)
	VerificationType string `json:"verification_type"`

	// Status of the seal
	Status string `json:"status"`

	// ModelHash of the verified model
	ModelHash string `json:"model_hash"`

	// OutputHash of the verified output
	OutputHash string `json:"output_hash"`

	// ValidatorCount who verified
	ValidatorCount int `json:"validator_count"`

	// ConsensusReached indicates if consensus was achieved
	ConsensusReached bool `json:"consensus_reached"`

	// HasZKProof indicates if zkML proof is available
	HasZKProof bool `json:"has_zk_proof"`

	// Timestamp when seal was created
	Timestamp time.Time `json:"timestamp"`

	// BlockHeight where seal was recorded
	BlockHeight int64 `json:"block_height"`

	// ChainID where seal exists
	ChainID string `json:"chain_id"`

	// Warnings if any
	Warnings []string `json:"warnings,omitempty"`
}

// QuickVerify provides a simple verification for SDK users
func (h *SDKHelper) QuickVerify(ctx context.Context, sealID string) (*QuickVerifyResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Get seal
	seal, err := h.keeper.GetSeal(ctx, sealID)
	if err != nil {
		return nil, fmt.Errorf("seal not found: %w", err)
	}

	// Verify seal
	verification, err := h.verifier.VerifySeal(ctx, sealID)
	if err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	createdAt := time.Time{}
	if seal.Timestamp != nil {
		createdAt = seal.Timestamp.AsTime()
	}

	response := &QuickVerifyResponse{
		SealID:           seal.Id,
		IsValid:          verification.Valid,
		VerificationType: seal.GetVerificationType(),
		Status:           seal.Status.String(),
		ModelHash:        hex.EncodeToString(seal.ModelCommitment),
		OutputHash:       hex.EncodeToString(seal.OutputCommitment),
		ValidatorCount:   len(seal.ValidatorSet),
		HasZKProof:       seal.ZkProof != nil,
		Timestamp:        createdAt,
		BlockHeight:      seal.BlockHeight,
		ChainID:          sdkCtx.ChainID(),
		Warnings:         make([]string, 0),
	}

	// Check consensus
	if len(seal.ValidatorSet) >= 3 {
		response.ConsensusReached = true
	}

	// Add warnings
	response.Warnings = append(response.Warnings, verification.Warnings...)

	return response, nil
}

// VerifyOutputHash verifies that a given output matches the sealed output
func (h *SDKHelper) VerifyOutputHash(ctx context.Context, sealID string, outputHash []byte) (bool, error) {
	seal, err := h.keeper.GetSeal(ctx, sealID)
	if err != nil {
		return false, err
	}

	return bytes.Equal(seal.OutputCommitment, outputHash), nil
}

// VerifyModelAndOutput verifies both model and output hashes
func (h *SDKHelper) VerifyModelAndOutput(ctx context.Context, sealID string, modelHash, outputHash []byte) (*ModelOutputVerification, error) {
	seal, err := h.keeper.GetSeal(ctx, sealID)
	if err != nil {
		return nil, err
	}

	result := &ModelOutputVerification{
		SealID:          sealID,
		ModelMatches:    bytes.Equal(seal.ModelCommitment, modelHash),
		OutputMatches:   bytes.Equal(seal.OutputCommitment, outputHash),
		ExpectedModel:   hex.EncodeToString(seal.ModelCommitment),
		ExpectedOutput:  hex.EncodeToString(seal.OutputCommitment),
		ProvidedModel:   hex.EncodeToString(modelHash),
		ProvidedOutput:  hex.EncodeToString(outputHash),
		VerifiedAt:      time.Now().UTC(),
	}

	result.Valid = result.ModelMatches && result.OutputMatches

	return result, nil
}

// ModelOutputVerification contains model and output verification result
type ModelOutputVerification struct {
	SealID         string    `json:"seal_id"`
	Valid          bool      `json:"valid"`
	ModelMatches   bool      `json:"model_matches"`
	OutputMatches  bool      `json:"output_matches"`
	ExpectedModel  string    `json:"expected_model"`
	ExpectedOutput string    `json:"expected_output"`
	ProvidedModel  string    `json:"provided_model"`
	ProvidedOutput string    `json:"provided_output"`
	VerifiedAt     time.Time `json:"verified_at"`
}

// GenerateVerificationProof generates a proof of verification for external use
func (h *SDKHelper) GenerateVerificationProof(ctx context.Context, sealID string) (*VerificationProof, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Get and verify seal
	seal, err := h.keeper.GetSeal(ctx, sealID)
	if err != nil {
		return nil, err
	}

	verification, err := h.verifier.VerifySeal(ctx, sealID)
	if err != nil {
		return nil, err
	}

	// Build proof
	proof := &VerificationProof{
		SealID:          seal.Id,
		ChainID:         sdkCtx.ChainID(),
		BlockHeight:     seal.BlockHeight,
		Timestamp:       time.Now().UTC(),
		Valid:           verification.Valid,
		ModelCommitment: hex.EncodeToString(seal.ModelCommitment),
		InputCommitment: hex.EncodeToString(seal.InputCommitment),
		OutputCommitment: hex.EncodeToString(seal.OutputCommitment),
		ValidatorSet:    seal.ValidatorSet,
	}

	// Include zkML proof reference if available
	if seal.ZkProof != nil {
		proof.ZKProofHash = hex.EncodeToString(sha256Hash(seal.ZkProof.ProofBytes))
		proof.ZKProofSystem = seal.ZkProof.ProofSystem
	}

	// Compute proof hash
	proofData, _ := json.Marshal(proof)
	proofHash := sha256.Sum256(proofData)
	proof.ProofHash = hex.EncodeToString(proofHash[:])

	return proof, nil
}

// VerificationProof is a portable proof of verification
type VerificationProof struct {
	SealID           string    `json:"seal_id"`
	ChainID          string    `json:"chain_id"`
	BlockHeight      int64     `json:"block_height"`
	Timestamp        time.Time `json:"timestamp"`
	Valid            bool      `json:"valid"`
	ModelCommitment  string    `json:"model_commitment"`
	InputCommitment  string    `json:"input_commitment"`
	OutputCommitment string    `json:"output_commitment"`
	ValidatorSet     []string  `json:"validator_set"`
	ZKProofHash      string    `json:"zk_proof_hash,omitempty"`
	ZKProofSystem    string    `json:"zk_proof_system,omitempty"`
	ProofHash        string    `json:"proof_hash"`
}

// GetSealSummary returns a summary suitable for display
func (h *SDKHelper) GetSealSummary(ctx context.Context, sealID string) (*SealSummary, error) {
	seal, err := h.keeper.GetSeal(ctx, sealID)
	if err != nil {
		return nil, err
	}

	createdAt := ""
	if seal.Timestamp != nil {
		createdAt = seal.Timestamp.AsTime().Format(time.RFC3339)
	}

	summary := &SealSummary{
		ID:               seal.Id,
		Status:           seal.Status.String(),
		Purpose:          seal.Purpose,
		VerificationType: seal.GetVerificationType(),
		ModelHash:        truncateHash(seal.ModelCommitment),
		OutputHash:       truncateHash(seal.OutputCommitment),
		ValidatorCount:   len(seal.ValidatorSet),
		HasZKProof:       seal.ZkProof != nil,
		CreatedAt:        createdAt,
		BlockHeight:      seal.BlockHeight,
	}

	// Add compliance frameworks
	if seal.RegulatoryInfo != nil && seal.RegulatoryInfo.ComplianceFrameworks != nil {
		summary.ComplianceFrameworks = seal.RegulatoryInfo.ComplianceFrameworks
	}

	return summary, nil
}

// SealSummary provides a concise seal summary
type SealSummary struct {
	ID                   string   `json:"id"`
	Status               string   `json:"status"`
	Purpose              string   `json:"purpose"`
	VerificationType     string   `json:"verification_type"`
	ModelHash            string   `json:"model_hash"`
	OutputHash           string   `json:"output_hash"`
	ValidatorCount       int      `json:"validator_count"`
	HasZKProof           bool     `json:"has_zk_proof"`
	CreatedAt            string   `json:"created_at"`
	BlockHeight          int64    `json:"block_height"`
	ComplianceFrameworks []string `json:"compliance_frameworks,omitempty"`
}

// ListSealsByModel returns seals for a specific model
func (h *SDKHelper) ListSealsByModel(ctx context.Context, modelHash []byte, limit int) ([]*SealSummary, error) {
	// In production, this would use an index
	allSeals := h.keeper.GetAllSeals(ctx)

	summaries := make([]*SealSummary, 0)
	for _, seal := range allSeals {
		if bytes.Equal(seal.ModelCommitment, modelHash) {
			summary, _ := h.GetSealSummary(ctx, seal.Id)
			if summary != nil {
				summaries = append(summaries, summary)
			}
			if len(summaries) >= limit {
				break
			}
		}
	}

	return summaries, nil
}

// ListSealsByPurpose returns seals for a specific purpose
func (h *SDKHelper) ListSealsByPurpose(ctx context.Context, purpose string, limit int) ([]*SealSummary, error) {
	allSeals := h.keeper.GetAllSeals(ctx)

	summaries := make([]*SealSummary, 0)
	for _, seal := range allSeals {
		if seal.Purpose == purpose {
			summary, _ := h.GetSealSummary(ctx, seal.Id)
			if summary != nil {
				summaries = append(summaries, summary)
			}
			if len(summaries) >= limit {
				break
			}
		}
	}

	return summaries, nil
}

// ExportForExternalVerification exports a seal for verification by external systems
func (h *SDKHelper) ExportForExternalVerification(ctx context.Context, sealID string) (*ExternalVerificationPackage, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	seal, err := h.keeper.GetSeal(ctx, sealID)
	if err != nil {
		return nil, err
	}

	verification, err := h.verifier.VerifySeal(ctx, sealID)
	if err != nil {
		return nil, err
	}

	createdAt := time.Time{}
	if seal.Timestamp != nil {
		createdAt = seal.Timestamp.AsTime()
	}

	pkg := &ExternalVerificationPackage{
		Version:     "1.0",
		SealID:      seal.Id,
		ChainID:     sdkCtx.ChainID(),
		Valid:       verification.Valid,
		Commitments: ExternalCommitments{
			Model:  hex.EncodeToString(seal.ModelCommitment),
			Input:  hex.EncodeToString(seal.InputCommitment),
			Output: hex.EncodeToString(seal.OutputCommitment),
		},
		Verification: ExternalVerification{
			Type:           seal.GetVerificationType(),
			ValidatorCount: len(seal.ValidatorSet),
			Validators:     seal.ValidatorSet,
		},
		Timestamp:   createdAt,
		BlockHeight: seal.BlockHeight,
	}

	// Include zkML proof data if available
	if seal.ZkProof != nil {
		pkg.ZKProof = &ExternalZKProof{
			System:           seal.ZkProof.ProofSystem,
			VerifyingKeyHash: hex.EncodeToString(seal.ZkProof.VerifyingKeyHash),
			ProofHash:        hex.EncodeToString(sha256Hash(seal.ZkProof.ProofBytes)),
		}
	}

	// Compute package hash
	pkgData, _ := json.Marshal(pkg)
	pkgHash := sha256.Sum256(pkgData)
	pkg.PackageHash = hex.EncodeToString(pkgHash[:])

	return pkg, nil
}

// ExternalVerificationPackage is designed for external system integration
type ExternalVerificationPackage struct {
	Version      string               `json:"version"`
	SealID       string               `json:"seal_id"`
	ChainID      string               `json:"chain_id"`
	Valid        bool                 `json:"valid"`
	Commitments  ExternalCommitments  `json:"commitments"`
	Verification ExternalVerification `json:"verification"`
	ZKProof      *ExternalZKProof     `json:"zk_proof,omitempty"`
	Timestamp    time.Time            `json:"timestamp"`
	BlockHeight  int64                `json:"block_height"`
	PackageHash  string               `json:"package_hash"`
}

// ExternalCommitments contains hash commitments
type ExternalCommitments struct {
	Model  string `json:"model"`
	Input  string `json:"input"`
	Output string `json:"output"`
}

// ExternalVerification contains verification details
type ExternalVerification struct {
	Type           string   `json:"type"`
	ValidatorCount int      `json:"validator_count"`
	Validators     []string `json:"validators"`
}

// ExternalZKProof contains zkML proof info for external verification
type ExternalZKProof struct {
	System           string `json:"system"`
	VerifyingKeyHash string `json:"verifying_key_hash"`
	ProofHash        string `json:"proof_hash"`
}

// ComputeInputHash computes the hash of input data for verification
func (h *SDKHelper) ComputeInputHash(inputData []byte) string {
	hash := sha256.Sum256(inputData)
	return hex.EncodeToString(hash[:])
}

// ComputeModelHash computes the hash of model data
func (h *SDKHelper) ComputeModelHash(modelData []byte) string {
	hash := sha256.Sum256(modelData)
	return hex.EncodeToString(hash[:])
}

// VerifyFromBase64 verifies a seal from a base64-encoded export
func (h *SDKHelper) VerifyFromBase64(ctx context.Context, exportedData string) (*QuickVerifyResponse, error) {
	// Decode base64
	jsonData, err := base64.StdEncoding.DecodeString(exportedData)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 data: %w", err)
	}

	// Parse exported seal
	var exported ExportedSeal
	if err := json.Unmarshal(jsonData, &exported); err != nil {
		return nil, fmt.Errorf("invalid seal data: %w", err)
	}

	// Extract seal ID based on format
	var sealID string
	switch data := exported.Seal.(type) {
	case map[string]interface{}:
		if id, ok := data["id"].(string); ok {
			sealID = id
		} else if id, ok := data["seal_id"].(string); ok {
			sealID = id
		}
	}

	if sealID == "" {
		return nil, fmt.Errorf("could not extract seal ID from export")
	}

	// Verify the seal
	return h.QuickVerify(ctx, sealID)
}

// CreateSealReference creates a lightweight reference to a seal
func (h *SDKHelper) CreateSealReference(ctx context.Context, sealID string) (*SealReference, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	seal, err := h.keeper.GetSeal(ctx, sealID)
	if err != nil {
		return nil, err
	}

	createdAt := time.Time{}
	if seal.Timestamp != nil {
		createdAt = seal.Timestamp.AsTime()
	}

	ref := &SealReference{
		SealID:      seal.Id,
		ChainID:     sdkCtx.ChainID(),
		BlockHeight: seal.BlockHeight,
		Timestamp:   createdAt,
		Status:      seal.Status.String(),
		OutputHash:  hex.EncodeToString(seal.OutputCommitment),
	}

	// Compute reference hash
	refData, _ := json.Marshal(ref)
	refHash := sha256.Sum256(refData)
	ref.ReferenceHash = hex.EncodeToString(refHash[:])

	return ref, nil
}

// SealReference is a lightweight reference to a seal
type SealReference struct {
	SealID        string    `json:"seal_id"`
	ChainID       string    `json:"chain_id"`
	BlockHeight   int64     `json:"block_height"`
	Timestamp     time.Time `json:"timestamp"`
	Status        string    `json:"status"`
	OutputHash    string    `json:"output_hash"`
	ReferenceHash string    `json:"reference_hash"`
}

// BatchVerify verifies multiple seals at once
func (h *SDKHelper) BatchVerify(ctx context.Context, sealIDs []string) ([]*QuickVerifyResponse, error) {
	responses := make([]*QuickVerifyResponse, 0, len(sealIDs))

	for _, sealID := range sealIDs {
		resp, err := h.QuickVerify(ctx, sealID)
		if err != nil {
			h.logger.Warn("Failed to verify seal in batch",
				"seal_id", sealID,
				"error", err,
			)
			responses = append(responses, &QuickVerifyResponse{
				SealID:   sealID,
				IsValid:  false,
				Warnings: []string{err.Error()},
			})
		} else {
			responses = append(responses, resp)
		}
	}

	return responses, nil
}

// GetComplianceInfo returns compliance information for a seal
func (h *SDKHelper) GetComplianceInfo(ctx context.Context, sealID string) (*ComplianceInfo, error) {
	seal, err := h.keeper.GetSeal(ctx, sealID)
	if err != nil {
		return nil, err
	}

	if seal.RegulatoryInfo == nil {
		return &ComplianceInfo{
			SealID:             seal.Id,
			Frameworks:         nil,
			DataClassification: "",
			JurisdictionID:     "",
			RetentionPeriod:    "",
			AuditRequired:      false,
		}, nil
	}

	retention := ""
	if seal.RegulatoryInfo.RetentionPeriod != nil {
		retention = seal.RegulatoryInfo.RetentionPeriod.AsDuration().String()
	}

	info := &ComplianceInfo{
		SealID:             seal.Id,
		Frameworks:         seal.RegulatoryInfo.ComplianceFrameworks,
		DataClassification: seal.RegulatoryInfo.DataClassification,
		JurisdictionID:     strings.Join(seal.RegulatoryInfo.JurisdictionRestrictions, ","),
		RetentionPeriod:    retention,
		AuditRequired:      seal.RegulatoryInfo.AuditRequired,
	}

	return info, nil
}

// ComplianceInfo contains compliance information
type ComplianceInfo struct {
	SealID             string   `json:"seal_id"`
	Frameworks         []string `json:"frameworks"`
	DataClassification string   `json:"data_classification"`
	JurisdictionID     string   `json:"jurisdiction_id"`
	RetentionPeriod    string   `json:"retention_period"`
	AuditRequired      bool     `json:"audit_required"`
}

// truncateHash creates a shortened hash for display
func truncateHash(hash []byte) string {
	fullHash := hex.EncodeToString(hash)
	if len(fullHash) > 16 {
		return fullHash[:8] + "..." + fullHash[len(fullHash)-8:]
	}
	return fullHash
}
