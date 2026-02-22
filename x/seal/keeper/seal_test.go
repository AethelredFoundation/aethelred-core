package keeper_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"cosmossdk.io/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aethelred/aethelred/x/seal/keeper"
	"github.com/aethelred/aethelred/x/seal/types"
)

// MockContext provides a mock SDK context for testing
type MockContext struct {
	context.Context
	height  int64
	chainID string
}

func NewMockContext() *MockContext {
	return &MockContext{
		Context: context.Background(),
		height:  100,
		chainID: "aethelred-test-1",
	}
}

func (m *MockContext) BlockHeight() int64 {
	return m.height
}

func (m *MockContext) ChainID() string {
	return m.chainID
}

// TestSealCreation tests basic seal creation
func TestSealCreation(t *testing.T) {
	k := keeper.NewKeeper(nil, nil, "")

	// Create seal
	modelHash := sha256.Sum256([]byte("test-model"))
	inputHash := sha256.Sum256([]byte("test-input"))
	outputHash := sha256.Sum256([]byte("test-output"))

	seal := &types.DigitalSeal{
		ModelCommitment:  modelHash[:],
		InputCommitment:  inputHash[:],
		OutputCommitment: outputHash[:],
		RequestedBy:      testAccAddress(1),
		Purpose:          "credit_scoring",
		Status:           types.SealStatusPending,
		Timestamp:        timestamppb.Now(),
		BlockHeight:      100,
		ValidatorSet:     []string{"val1", "val2", "val3"},
		TeeAttestations:  make([]*types.TEEAttestation, 0),
		RegulatoryInfo: &types.RegulatoryInfo{
			ComplianceFrameworks: []string{"FCRA", "Basel_III"},
			DataClassification:   "confidential",
			AuditRequired:        true,
		},
	}

	// Generate ID
	seal.Id = seal.GenerateID()

	// Validate
	if err := seal.Validate(); err != nil {
		t.Errorf("Seal validation failed: %v", err)
	}

	// Store seal
	ctx := context.Background()
	if err := k.SetSeal(ctx, seal); err != nil {
		t.Errorf("Failed to store seal: %v", err)
	}

	// Retrieve seal
	retrieved, err := k.GetSeal(ctx, seal.Id)
	if err != nil {
		t.Errorf("Failed to retrieve seal: %v", err)
	}

	if retrieved.Id != seal.Id {
		t.Errorf("Seal ID mismatch: got %s, want %s", retrieved.Id, seal.Id)
	}

	if !bytes.Equal(retrieved.OutputCommitment, seal.OutputCommitment) {
		t.Error("Output commitment mismatch")
	}
}

// TestEnhancedSealCreation tests enhanced seal creation
func TestEnhancedSealCreation(t *testing.T) {
	modelHash := sha256.Sum256([]byte("test-model"))
	inputHash := sha256.Sum256([]byte("test-input"))
	outputHash := sha256.Sum256([]byte("test-output"))

	consensusInfo := &types.ConsensusInfo{
		Height:                  100,
		Round:                   1,
		TotalValidators:         5,
		ParticipatingValidators: 5,
		AgreementCount:          4,
		ConsensusThreshold:      67,
		Timestamp:               time.Now().UTC(),
	}

	verificationBundle := &types.VerificationBundle{
		VerificationType:     "tee",
		AggregatedOutputHash: outputHash[:],
		TEEVerifications: []types.TEEVerification{
			{
				ValidatorAddress: "val1",
				Platform:         "aws-nitro",
				EnclaveID:        "enclave-1",
				OutputHash:       outputHash[:],
				Timestamp:        time.Now().UTC(),
			},
		},
	}
	verificationBundle.BundleHash = sha256Hash([]byte("bundle"))

	seal := types.NewEnhancedDigitalSeal(
		"job-123",
		modelHash[:],
		inputHash[:],
		outputHash[:],
		consensusInfo,
		verificationBundle,
		testAccAddress(2),
		"credit_scoring",
		"aethelred-test-1",
	)

	// Validate
	if err := seal.ValidateEnhanced(); err != nil {
		t.Errorf("Enhanced seal validation failed: %v", err)
	}

	// Check version
	if seal.Version != types.CurrentSealVersion {
		t.Errorf("Version mismatch: got %d, want %d", seal.Version, types.CurrentSealVersion)
	}

	// Check job ID
	if seal.JobID != "job-123" {
		t.Errorf("Job ID mismatch: got %s, want job-123", seal.JobID)
	}

	// Check audit trail
	if len(seal.AuditTrail) != 1 {
		t.Errorf("Expected 1 audit entry, got %d", len(seal.AuditTrail))
	}

	if seal.AuditTrail[0].EventType != types.AuditEventCreated {
		t.Errorf("Expected created event, got %s", seal.AuditTrail[0].EventType)
	}
}

// TestSealActivation tests seal activation
func TestSealActivation(t *testing.T) {
	seal := createTestEnhancedSeal()

	// Initially pending
	if seal.Status != types.SealStatusPending {
		t.Errorf("Expected pending status, got %s", seal.Status)
	}

	// Activate
	seal.Activate("system", 101)

	if seal.Status != types.SealStatusActive {
		t.Errorf("Expected active status, got %s", seal.Status)
	}

	// Check audit trail
	if len(seal.AuditTrail) != 2 {
		t.Errorf("Expected 2 audit entries, got %d", len(seal.AuditTrail))
	}

	if seal.AuditTrail[1].EventType != types.AuditEventActivated {
		t.Errorf("Expected activated event, got %s", seal.AuditTrail[1].EventType)
	}
}

// TestSealRevocation tests seal revocation
func TestSealRevocation(t *testing.T) {
	seal := createTestEnhancedSeal()
	seal.Activate("system", 101)

	// Revoke
	seal.Revoke("admin", "Invalid model detected", 102)

	if seal.Status != types.SealStatusRevoked {
		t.Errorf("Expected revoked status, got %s", seal.Status)
	}

	// Check audit trail
	if len(seal.AuditTrail) != 3 {
		t.Errorf("Expected 3 audit entries, got %d", len(seal.AuditTrail))
	}

	if seal.AuditTrail[2].EventType != types.AuditEventRevoked {
		t.Errorf("Expected revoked event, got %s", seal.AuditTrail[2].EventType)
	}
}

// TestOutputConsistency tests verification output consistency
func TestOutputConsistency(t *testing.T) {
	seal := createTestEnhancedSeal()

	// All validators should agree
	if !seal.VerifyOutputConsistency() {
		t.Error("Output consistency check failed when it should pass")
	}

	// Add mismatching output
	seal.VerificationBundle.TEEVerifications = append(seal.VerificationBundle.TEEVerifications, types.TEEVerification{
		ValidatorAddress: "val2",
		OutputHash:       sha256Hash([]byte("different-output")),
		Timestamp:        time.Now().UTC(),
	})

	if seal.VerifyOutputConsistency() {
		t.Error("Output consistency check passed when it should fail")
	}
}

// TestSealSerialization tests JSON serialization
func TestSealSerialization(t *testing.T) {
	seal := createTestEnhancedSeal()

	// Serialize
	jsonData, err := seal.ToJSON()
	if err != nil {
		t.Errorf("Failed to serialize seal: %v", err)
	}

	// Deserialize
	restored, err := types.FromJSON(jsonData)
	if err != nil {
		t.Errorf("Failed to deserialize seal: %v", err)
	}

	if restored.Id != seal.Id {
		t.Errorf("ID mismatch after deserialization")
	}

	if restored.JobID != seal.JobID {
		t.Errorf("JobID mismatch after deserialization")
	}
}

// TestSealVerifier tests seal verification
func TestSealVerifier(t *testing.T) {
	k := keeper.NewKeeper(nil, nil, "")
	verifier := keeper.NewSealVerifier(log.NewNopLogger(), &k, keeper.DefaultVerifierConfig())

	ctx := context.Background()

	// Create and store a valid seal
	seal := createTestDigitalSeal()
	seal.Status = types.SealStatusActive
	if err := k.SetSeal(ctx, seal); err != nil {
		t.Fatalf("Failed to store seal: %v", err)
	}

	// Verify seal
	result, err := verifier.VerifySeal(ctx, seal.Id)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Expected valid seal, got invalid: %s", result.Summary)
	}
}

// TestSealVerifierRevokedSeal tests verification of revoked seal
func TestSealVerifierRevokedSeal(t *testing.T) {
	k := keeper.NewKeeper(nil, nil, "")
	verifier := keeper.NewSealVerifier(log.NewNopLogger(), &k, keeper.DefaultVerifierConfig())

	ctx := context.Background()

	// Create and store a revoked seal
	seal := createTestDigitalSeal()
	seal.Status = types.SealStatusRevoked
	if err := k.SetSeal(ctx, seal); err != nil {
		t.Fatalf("Failed to store seal: %v", err)
	}

	// Verify seal
	result, err := verifier.VerifySeal(ctx, seal.Id)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}

	if result.Valid {
		t.Error("Expected invalid result for revoked seal")
	}
}

// TestRevocationManager tests revocation operations
func TestRevocationManager(t *testing.T) {
	k := keeper.NewKeeper(nil, nil, "")
	rm := keeper.NewRevocationManager(log.NewNopLogger(), &k, keeper.DefaultRevocationConfig())

	// Register authority
	authority := keeper.RevocationAuthority{
		Address: testAccAddress(3),
		Name:    "Test Admin",
		Level:   keeper.AuthorityLevelAdmin,
		Active:  true,
	}

	if err := rm.RegisterAuthority(authority); err != nil {
		t.Errorf("Failed to register authority: %v", err)
	}

	// Create and store a seal
	ctx := sdkTestContext()
	seal := createTestDigitalSeal()
	seal.Status = types.SealStatusActive
	if err := k.SetSeal(ctx, seal); err != nil {
		t.Fatalf("Failed to store seal: %v", err)
	}

	// Revoke seal
	result, err := rm.RevokeSeal(
		ctx,
		seal.Id,
		authority.Address,
		keeper.RevocationReasonUserRequest,
		"Test revocation",
	)

	if err != nil {
		t.Errorf("Revocation failed: %v", err)
	}

	if !result.Success {
		t.Error("Expected successful revocation")
	}

	// Verify seal is revoked
	revokedSeal, _ := k.GetSeal(ctx, seal.Id)
	if revokedSeal.Status != types.SealStatusRevoked {
		t.Errorf("Seal should be revoked, got %s", revokedSeal.Status)
	}
}

// TestDisputeFiling tests filing a dispute
func TestDisputeFiling(t *testing.T) {
	k := keeper.NewKeeper(nil, nil, "")
	rm := keeper.NewRevocationManager(log.NewNopLogger(), &k, keeper.DefaultRevocationConfig())

	ctx := sdkTestContext()

	dispute, err := rm.FileDispute(ctx, "req-123", testAccAddress(4), "Revocation is unjustified")
	if err != nil {
		t.Errorf("Failed to file dispute: %v", err)
	}

	if dispute.Status != keeper.DisputeStatusOpen {
		t.Errorf("Expected open status, got %s", dispute.Status)
	}

	if dispute.RequestID != "req-123" {
		t.Errorf("Request ID mismatch")
	}
}

// TestSealIndex tests indexing functionality
func TestSealIndex(t *testing.T) {
	idx := keeper.NewSealIndex()

	// Create test seals
	seal1 := createTestDigitalSeal()
	seal1.Id = "seal-1"
	seal1.Purpose = "credit_scoring"
	seal1.RequestedBy = "user1"
	seal1.RegulatoryInfo.ComplianceFrameworks = []string{"FCRA"}

	seal2 := createTestDigitalSeal()
	seal2.Id = "seal-2"
	seal2.Purpose = "fraud_detection"
	seal2.RequestedBy = "user1"
	seal2.RegulatoryInfo.ComplianceFrameworks = []string{"Basel_III"}

	seal3 := createTestDigitalSeal()
	seal3.Id = "seal-3"
	seal3.Purpose = "credit_scoring"
	seal3.RequestedBy = "user2"
	seal3.RegulatoryInfo.ComplianceFrameworks = []string{"FCRA", "GDPR"}

	// Index seals
	idx.IndexSeal(seal1)
	idx.IndexSeal(seal2)
	idx.IndexSeal(seal3)

	// Test by purpose
	creditSeals := idx.GetByPurpose("credit_scoring")
	if len(creditSeals) != 2 {
		t.Errorf("Expected 2 credit scoring seals, got %d", len(creditSeals))
	}

	// Test by requester
	user1Seals := idx.GetByRequester("user1")
	if len(user1Seals) != 2 {
		t.Errorf("Expected 2 seals for user1, got %d", len(user1Seals))
	}

	// Test by compliance
	fcraSeals := idx.GetByComplianceFramework("FCRA")
	if len(fcraSeals) != 2 {
		t.Errorf("Expected 2 FCRA seals, got %d", len(fcraSeals))
	}

	// Test stats
	stats := idx.GetStats()
	if stats.TotalSeals != 3 {
		t.Errorf("Expected 3 total seals, got %d", stats.TotalSeals)
	}
}

// TestSealQuery tests query execution
func TestSealQuery(t *testing.T) {
	idx := keeper.NewSealIndex()

	// Create and index test seals
	for i := 0; i < 10; i++ {
		seal := createTestDigitalSeal()
		seal.Id = "seal-" + string(rune('a'+i))
		seal.Purpose = "credit_scoring"
		seal.BlockHeight = int64(100 + i)
		idx.IndexSeal(seal)
	}

	// Query with limit
	query := keeper.SealQuery{
		Purpose: "credit_scoring",
		Limit:   5,
	}

	results := idx.ExecuteQuery(query)
	if len(results) != 5 {
		t.Errorf("Expected 5 results, got %d", len(results))
	}

	// Query with offset
	query = keeper.SealQuery{
		Purpose: "credit_scoring",
		Limit:   5,
		Offset:  3,
	}

	results = idx.ExecuteQuery(query)
	if len(results) != 5 {
		t.Errorf("Expected 5 results with offset, got %d", len(results))
	}
}

// TestSDKHelper tests SDK helper functions
func TestSDKHelper(t *testing.T) {
	k := keeper.NewKeeper(nil, nil, "")
	verifier := keeper.NewSealVerifier(log.NewNopLogger(), &k, keeper.DefaultVerifierConfig())
	exporter := keeper.NewSealExporter(log.NewNopLogger(), &k, verifier)
	helper := keeper.NewSDKHelper(log.NewNopLogger(), &k, verifier, exporter)

	ctx := sdkTestContext()

	// Create and store a seal
	seal := createTestDigitalSeal()
	seal.Status = types.SealStatusActive
	if err := k.SetSeal(ctx, seal); err != nil {
		t.Fatalf("Failed to store seal: %v", err)
	}

	// Test QuickVerify
	response, err := helper.QuickVerify(ctx, seal.Id)
	if err != nil {
		t.Errorf("QuickVerify failed: %v", err)
	}

	if !response.IsValid {
		t.Error("Expected valid seal")
	}

	// Test GetSealSummary
	summary, err := helper.GetSealSummary(ctx, seal.Id)
	if err != nil {
		t.Errorf("GetSealSummary failed: %v", err)
	}

	if summary.ID != seal.Id {
		t.Error("Summary ID mismatch")
	}

	// Test VerifyOutputHash
	matches, err := helper.VerifyOutputHash(ctx, seal.Id, seal.OutputCommitment)
	if err != nil {
		t.Errorf("VerifyOutputHash failed: %v", err)
	}

	if !matches {
		t.Error("Output hash should match")
	}

	// Test with wrong hash
	wrongHash := sha256Hash([]byte("wrong"))
	matches, _ = helper.VerifyOutputHash(ctx, seal.Id, wrongHash)
	if matches {
		t.Error("Output hash should not match")
	}
}

// TestBatchVerify tests batch verification
func TestBatchVerify(t *testing.T) {
	k := keeper.NewKeeper(nil, nil, "")
	verifier := keeper.NewSealVerifier(log.NewNopLogger(), &k, keeper.DefaultVerifierConfig())
	exporter := keeper.NewSealExporter(log.NewNopLogger(), &k, verifier)
	helper := keeper.NewSDKHelper(log.NewNopLogger(), &k, verifier, exporter)

	ctx := sdkTestContext()

	// Create and store multiple seals
	sealIDs := make([]string, 5)
	for i := 0; i < 5; i++ {
		seal := createTestDigitalSeal()
		seal.Status = types.SealStatusActive
		if err := k.SetSeal(ctx, seal); err != nil {
			t.Fatalf("Failed to store seal: %v", err)
		}
		sealIDs[i] = seal.Id
	}

	// Batch verify
	responses, err := helper.BatchVerify(ctx, sealIDs)
	if err != nil {
		t.Errorf("BatchVerify failed: %v", err)
	}

	if len(responses) != 5 {
		t.Errorf("Expected 5 responses, got %d", len(responses))
	}

	// All should be valid
	for i, resp := range responses {
		if !resp.IsValid {
			t.Errorf("Seal %d should be valid", i)
		}
	}
}

// TestSealExporter tests seal export
func TestSealExporter(t *testing.T) {
	k := keeper.NewKeeper(nil, nil, "")
	verifier := keeper.NewSealVerifier(log.NewNopLogger(), &k, keeper.DefaultVerifierConfig())
	exporter := keeper.NewSealExporter(log.NewNopLogger(), &k, verifier)

	ctx := sdkTestContext()

	// Create and store a seal
	seal := createTestDigitalSeal()
	seal.Status = types.SealStatusActive
	if err := k.SetSeal(ctx, seal); err != nil {
		t.Fatalf("Failed to store seal: %v", err)
	}

	// Test JSON export
	options := keeper.ExportOptions{
		Format:             keeper.ExportFormatJSON,
		IncludeProofs:      true,
		VerifyBeforeExport: false,
	}

	exported, err := exporter.Export(ctx, seal.Id, options)
	if err != nil {
		t.Errorf("Export failed: %v", err)
	}

	if exported.Format != keeper.ExportFormatJSON {
		t.Error("Format mismatch")
	}

	// Test compact export
	options.Format = keeper.ExportFormatCompact
	exported, err = exporter.Export(ctx, seal.Id, options)
	if err != nil {
		t.Errorf("Compact export failed: %v", err)
	}

	// Test base64 export
	base64Data, err := exporter.ExportToBase64(ctx, seal.Id, options)
	if err != nil {
		t.Errorf("Base64 export failed: %v", err)
	}

	if len(base64Data) == 0 {
		t.Error("Base64 data should not be empty")
	}

	// Test import from base64
	imported, err := exporter.ImportFromBase64(base64Data)
	if err != nil {
		t.Errorf("Import from base64 failed: %v", err)
	}

	if imported == nil {
		t.Error("Imported data should not be nil")
	}
}

// TestVerificationSummary tests verification summary generation
func TestVerificationSummary(t *testing.T) {
	seal := createTestEnhancedSeal()
	seal.Status = types.SealStatusActive

	summary := seal.GetVerificationSummary()

	if summary.SealID != seal.Id {
		t.Error("Seal ID mismatch in summary")
	}

	if !summary.IsValid {
		t.Error("Summary should show valid")
	}

	if summary.VerificationType != "tee" {
		t.Errorf("Expected tee verification type, got %s", summary.VerificationType)
	}

	// Check consensus
	if !summary.ConsensusReached {
		t.Error("Consensus should be reached")
	}
}

// Helper functions

func createTestDigitalSeal() *types.DigitalSeal {
	modelHash := sha256.Sum256([]byte("test-model"))
	inputHash := sha256.Sum256([]byte("test-input"))
	outputHash := sha256.Sum256([]byte("test-output"))

	seal := &types.DigitalSeal{
		ModelCommitment:  modelHash[:],
		InputCommitment:  inputHash[:],
		OutputCommitment: outputHash[:],
		RequestedBy:      testAccAddress(1),
		Purpose:          "credit_scoring",
		Status:           types.SealStatusPending,
		Timestamp:        timestamppb.Now(),
		BlockHeight:      100,
		ValidatorSet:     []string{"val1", "val2", "val3"},
		TeeAttestations: []*types.TEEAttestation{
			{
				ValidatorAddress: "val1",
				Platform:         "aws-nitro",
				EnclaveId:        "enclave-1",
				Measurement:      sha256Hash([]byte("measurement")),
				Quote:            []byte("quote-data"),
				Timestamp:        timestamppb.Now(),
			},
		},
		RegulatoryInfo: &types.RegulatoryInfo{
			ComplianceFrameworks: []string{"FCRA", "Basel_III"},
			DataClassification:   "confidential",
			AuditRequired:        true,
			RetentionPeriod:      durationpb.New(7 * 365 * 24 * time.Hour),
			JurisdictionRestrictions: []string{"US"},
		},
	}

	seal.Id = seal.GenerateID()
	return seal
}

func createTestEnhancedSeal() *types.EnhancedDigitalSeal {
	modelHash := sha256.Sum256([]byte("test-model"))
	inputHash := sha256.Sum256([]byte("test-input"))
	outputHash := sha256.Sum256([]byte("test-output"))

	consensusInfo := &types.ConsensusInfo{
		Height:                  100,
		Round:                   1,
		TotalValidators:         5,
		ParticipatingValidators: 5,
		AgreementCount:          4,
		ConsensusThreshold:      67,
		Timestamp:               time.Now().UTC(),
	}

	verificationBundle := &types.VerificationBundle{
		VerificationType:     "tee",
		AggregatedOutputHash: outputHash[:],
		TEEVerifications: []types.TEEVerification{
			{
				ValidatorAddress: "val1",
				Platform:         "aws-nitro",
				EnclaveID:        "enclave-1",
				OutputHash:       outputHash[:],
				Timestamp:        time.Now().UTC(),
			},
		},
	}
	verificationBundle.BundleHash = sha256Hash([]byte("bundle"))

	return types.NewEnhancedDigitalSeal(
		"job-123",
		modelHash[:],
		inputHash[:],
		outputHash[:],
		consensusInfo,
		verificationBundle,
		testAccAddress(2),
		"credit_scoring",
		"aethelred-test-1",
	)
}

func sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func testAccAddress(seed byte) string {
	addr := bytes.Repeat([]byte{seed}, 20)
	return sdk.AccAddress(addr).String()
}

func sdkTestContext() context.Context {
	header := tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  100,
		Time:    time.Now().UTC(),
	}
	sdkCtx := sdk.NewContext(nil, header, false, log.NewNopLogger())
	return sdk.WrapSDKContext(sdkCtx)
}
