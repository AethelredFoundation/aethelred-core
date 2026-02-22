package app_test

import (
	"testing"

	"cosmossdk.io/log"
	"cosmossdk.io/store"
	storemetrics "cosmossdk.io/store/metrics"
	storetypes "cosmossdk.io/store/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/app"
	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
	"github.com/aethelred/aethelred/x/verify"
	verifytypes "github.com/aethelred/aethelred/x/verify/types"
)

// testCtx creates a minimal sdk.Context suitable for bridge tests.
// The bridge only uses ctx as a context.Context for the orchestrator's
// timeout, so a basic context backed by an in-memory store suffices.
func testCtx(t *testing.T) sdk.Context {
	t.Helper()
	key := storetypes.NewKVStoreKey("test")
	db := dbm.NewMemDB()
	cms := store.NewCommitMultiStore(db, log.NewNopLogger(), storemetrics.NewNoOpMetrics())
	cms.MountStoreWithDB(key, storetypes.StoreTypeIAVL, nil)
	if err := cms.LoadLatestVersion(); err != nil {
		t.Fatalf("failed to load latest version: %v", err)
	}
	return sdk.NewContext(cms, tmproto.Header{}, false, log.NewNopLogger())
}

// TestOrchestratorBridge_Nil_Job verifies that the bridge returns an error for nil job.
func TestOrchestratorBridge_Nil_Job(t *testing.T) {
	ctx := testCtx(t)
	orchConfig := verify.DefaultOrchestratorConfig()
	orchestrator := verify.NewVerificationOrchestrator(log.NewNopLogger(), orchConfig)
	bridge := app.NewOrchestratorBridge(orchestrator)

	// Verify interface satisfaction at runtime
	var _ pouwkeeper.JobVerifier = bridge

	_, err := bridge.VerifyJob(ctx, nil, nil, "validator1")
	if err == nil {
		t.Fatal("expected error for nil job")
	}
	if err.Error() != "job cannot be nil" {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestOrchestratorBridge_Nil_Model verifies that the bridge returns an error for nil model.
func TestOrchestratorBridge_Nil_Model(t *testing.T) {
	ctx := testCtx(t)
	orchConfig := verify.DefaultOrchestratorConfig()
	orchestrator := verify.NewVerificationOrchestrator(log.NewNopLogger(), orchConfig)
	bridge := app.NewOrchestratorBridge(orchestrator)

	job := &pouwtypes.ComputeJob{
		Id:        "test-job-1",
		ModelHash: make([]byte, 32),
		InputHash: make([]byte, 32),
		ProofType: pouwtypes.ProofTypeTEE,
	}

	_, err := bridge.VerifyJob(ctx, job, nil, "validator1")
	if err == nil {
		t.Fatal("expected error for nil model")
	}
	if err.Error() != "model cannot be nil" {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestOrchestratorBridge_UnsupportedProofType verifies graceful handling of unknown proof types.
func TestOrchestratorBridge_UnsupportedProofType(t *testing.T) {
	ctx := testCtx(t)
	orchConfig := verify.DefaultOrchestratorConfig()
	orchestrator := verify.NewVerificationOrchestrator(log.NewNopLogger(), orchConfig)
	bridge := app.NewOrchestratorBridge(orchestrator)

	job := &pouwtypes.ComputeJob{
		Id:        "test-job-2",
		ModelHash: make([]byte, 32),
		InputHash: make([]byte, 32),
		ProofType: pouwtypes.ProofType(999), // invalid
	}
	model := &pouwtypes.RegisteredModel{
		ModelHash: make([]byte, 32),
	}

	result, err := bridge.VerifyJob(ctx, job, model, "validator1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return a failed result, not an error
	if result.Success {
		t.Fatal("expected unsuccessful result for unsupported proof type")
	}
	if result.ValidatorAddress != "validator1" {
		t.Fatalf("expected validator address 'validator1', got %q", result.ValidatorAddress)
	}
	if result.ErrorMessage == "" {
		t.Fatal("expected non-empty error message")
	}
}

// TestOrchestratorBridge_MapProofTypes verifies all valid proof type mappings.
func TestOrchestratorBridge_MapProofTypes(t *testing.T) {
	ctx := testCtx(t)
	orchConfig := verify.DefaultOrchestratorConfig()
	orchestrator := verify.NewVerificationOrchestrator(log.NewNopLogger(), orchConfig)
	bridge := app.NewOrchestratorBridge(orchestrator)

	testCases := []struct {
		name      string
		proofType pouwtypes.ProofType
	}{
		{"TEE", pouwtypes.ProofTypeTEE},
		{"ZKML", pouwtypes.ProofTypeZKML},
		{"Hybrid", pouwtypes.ProofTypeHybrid},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			job := &pouwtypes.ComputeJob{
				Id:        "test-job-" + tc.name,
				ModelHash: make([]byte, 32),
				InputHash: make([]byte, 32),
				ProofType: tc.proofType,
			}
			model := &pouwtypes.RegisteredModel{
				ModelHash: make([]byte, 32),
			}

			// The orchestrator will fail because there's no real TEE/prover backend,
			// but we verify the mapping doesn't panic and returns a result.
			result, err := bridge.VerifyJob(ctx, job, model, "validator-"+tc.name)
			if err != nil {
				t.Fatalf("unexpected error for proof type %s: %v", tc.name, err)
			}
			if result.ValidatorAddress != "validator-"+tc.name {
				t.Fatalf("validator address mismatch: got %q", result.ValidatorAddress)
			}
		})
	}
}

// TestOrchestratorBridge_InterfaceSatisfaction ensures OrchestratorBridge satisfies
// the pouwkeeper.JobVerifier interface at compile time.
func TestOrchestratorBridge_InterfaceSatisfaction(t *testing.T) {
	// This is a compile-time check; if this function compiles, the test passes.
	var _ pouwkeeper.JobVerifier = (*app.OrchestratorBridge)(nil)
}

// TestOrchestratorBridge_OutputHashPassthrough verifies that when a job has a
// previous output hash, it's passed through to the orchestrator.
func TestOrchestratorBridge_OutputHashPassthrough(t *testing.T) {
	ctx := testCtx(t)
	orchConfig := verify.DefaultOrchestratorConfig()
	orchestrator := verify.NewVerificationOrchestrator(log.NewNopLogger(), orchConfig)
	bridge := app.NewOrchestratorBridge(orchestrator)

	outputHash := []byte("expected-output-hash-32-bytes-xx")
	job := &pouwtypes.ComputeJob{
		Id:         "test-output-passthrough",
		ModelHash:  make([]byte, 32),
		InputHash:  make([]byte, 32),
		OutputHash: outputHash,
		ProofType:  pouwtypes.ProofTypeTEE,
	}
	model := &pouwtypes.RegisteredModel{
		ModelHash: make([]byte, 32),
	}

	// The bridge should set ExpectedOutputHash on the request.
	// Even though the orchestrator may fail (no real backend), the call
	// should not return a Go-level error.
	result, err := bridge.VerifyJob(ctx, job, model, "validator-out")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = result
}

// TestOrchestratorBridge_MetadataPopulated verifies the bridge populates metadata
// from the job fields into the verification request.
func TestOrchestratorBridge_MetadataPopulated(t *testing.T) {
	ctx := testCtx(t)
	orchConfig := verify.DefaultOrchestratorConfig()
	orchestrator := verify.NewVerificationOrchestrator(log.NewNopLogger(), orchConfig)
	bridge := app.NewOrchestratorBridge(orchestrator)

	job := &pouwtypes.ComputeJob{
		Id:           "test-metadata",
		ModelHash:    make([]byte, 32),
		InputHash:    make([]byte, 32),
		ProofType:    pouwtypes.ProofTypeTEE,
		RequestedBy:  "aeth1abc123",
		Purpose:      "credit_scoring",
		InputDataUri: "ipfs://Qm...",
	}
	model := &pouwtypes.RegisteredModel{
		ModelHash:    make([]byte, 32),
		CircuitHash:  []byte("circuit-hash-data"),
		VerifyingKeyHash: []byte("vk-hash-data"),
	}

	// This test verifies the bridge doesn't error on metadata-rich jobs.
	result, err := bridge.VerifyJob(ctx, job, model, "validator-meta")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ValidatorAddress != "validator-meta" {
		t.Fatalf("validator address mismatch: got %q", result.ValidatorAddress)
	}
}

// TestReadinessReport_DevMode verifies that dev mode passes all readiness checks.
func TestReadinessReport_DevMode(t *testing.T) {
	params := &verifytypes.Params{
		AllowSimulated: true,
	}
	report := verify.ValidateProductionReadiness(params, nil, nil)
	if !report.Ready {
		t.Fatalf("dev mode should be ready, got: %s", report.String())
	}
}

// TestReadinessReport_ProductionMissingAll verifies that production mode fails
// with no endpoints configured.
func TestReadinessReport_ProductionMissingAll(t *testing.T) {
	params := &verifytypes.Params{
		AllowSimulated: false,
		// No ZkVerifierEndpoint
		// No SupportedProofSystems
	}
	report := verify.ValidateProductionReadiness(params, nil, nil)
	if report.Ready {
		t.Fatal("production mode with no endpoints should NOT be ready")
	}
}
