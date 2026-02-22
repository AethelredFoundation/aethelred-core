package keeper_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// =============================================================================
// WEEK 40: Validator Onboarding Full Rollout Tests
//
// These tests verify:
//   1. Onboarding application validation (6 tests)
//   2. Capability verification (5 tests)
//   3. Onboarding checklist (5 tests)
//   4. Readiness scoring (5 tests)
//   5. Onboarding dashboard (3 tests)
//   6. Batch processing (4 tests)
//
// Total: 28 tests
// =============================================================================

// =============================================================================
// Helper: valid test application
// =============================================================================

func validTestApplication() keeper.OnboardingApplication {
	return keeper.OnboardingApplication{
		ValidatorAddr:     "aethelval1abc123",
		Moniker:           "test-validator",
		OperatorContact:   "ops@test.com",
		AppliedAt:         time.Now().UTC(),
		TEEPlatform:       "nitro",
		TEEVersion:        "1.0",
		ZKMLBackend:       "ezkl",
		MaxConcurrentJobs: 5,
		NodeVersion:       "v1.0.0",
		ChainID:           "aethelred-test-1",
		SupportsTEE:       true,
		SupportsZKML:      true,
		SupportsHybrid:    true,
	}
}

// =============================================================================
// Section 1: Application Validation
// =============================================================================

func TestValidateApplication_Valid(t *testing.T) {
	app := validTestApplication()
	require.NoError(t, keeper.ValidateApplication(app))
}

func TestValidateApplication_EmptyAddress(t *testing.T) {
	app := validTestApplication()
	app.ValidatorAddr = ""
	err := keeper.ValidateApplication(app)
	require.Error(t, err)
	require.Contains(t, err.Error(), "address")
}

func TestValidateApplication_EmptyMoniker(t *testing.T) {
	app := validTestApplication()
	app.Moniker = ""
	err := keeper.ValidateApplication(app)
	require.Error(t, err)
	require.Contains(t, err.Error(), "moniker")
}

func TestValidateApplication_ZeroConcurrency(t *testing.T) {
	app := validTestApplication()
	app.MaxConcurrentJobs = 0
	err := keeper.ValidateApplication(app)
	require.Error(t, err)
	require.Contains(t, err.Error(), "max_concurrent_jobs")
}

func TestValidateApplication_NoProofTypes(t *testing.T) {
	app := validTestApplication()
	app.SupportsTEE = false
	app.SupportsZKML = false
	app.SupportsHybrid = false
	err := keeper.ValidateApplication(app)
	require.Error(t, err)
	require.Contains(t, err.Error(), "proof type")
}

func TestValidateApplication_TEEWithoutPlatform(t *testing.T) {
	app := validTestApplication()
	app.TEEPlatform = ""
	app.SupportsTEE = true
	err := keeper.ValidateApplication(app)
	require.Error(t, err)
	require.Contains(t, err.Error(), "TEE platform")
}

// =============================================================================
// Section 2: Capability Verification
// =============================================================================

func TestVerifyCapabilities_ValidApplication(t *testing.T) {
	app := validTestApplication()
	checks := keeper.VerifyCapabilities(app)

	require.NotEmpty(t, checks)
	require.True(t, keeper.AllRequiredCapabilitiesPass(checks),
		"valid application should pass all required capability checks")
}

func TestVerifyCapabilities_InvalidTEEPlatform(t *testing.T) {
	app := validTestApplication()
	app.TEEPlatform = "invalid_platform"
	checks := keeper.VerifyCapabilities(app)

	hasTEEFail := false
	for _, c := range checks {
		if c.Check == "tee_platform_valid" && !c.Passed {
			hasTEEFail = true
		}
	}
	require.True(t, hasTEEFail, "invalid TEE platform should fail check")
}

func TestVerifyCapabilities_HybridWithoutTEE(t *testing.T) {
	app := validTestApplication()
	app.SupportsTEE = false
	app.SupportsHybrid = true
	app.TEEPlatform = ""
	checks := keeper.VerifyCapabilities(app)

	hasHybridFail := false
	for _, c := range checks {
		if c.Check == "hybrid_prerequisites" && !c.Passed {
			hasHybridFail = true
		}
	}
	require.True(t, hasHybridFail, "hybrid without TEE should fail prerequisite check")
}

func TestVerifyCapabilities_ExcessiveConcurrency(t *testing.T) {
	app := validTestApplication()
	app.MaxConcurrentJobs = 100 // > 50 limit
	checks := keeper.VerifyCapabilities(app)

	hasCapFail := false
	for _, c := range checks {
		if c.Check == "concurrent_jobs_valid" && !c.Passed {
			hasCapFail = true
		}
	}
	require.True(t, hasCapFail, "excessive concurrency should fail check")
}

func TestVerifyCapabilities_AllChecksHaveFields(t *testing.T) {
	app := validTestApplication()
	checks := keeper.VerifyCapabilities(app)

	for _, c := range checks {
		require.NotEmpty(t, c.Category, "check must have category")
		require.NotEmpty(t, c.Check, "check must have name")
		require.NotEmpty(t, c.Details, "check must have details")
	}
}

// =============================================================================
// Section 3: Onboarding Checklist
// =============================================================================

func TestOnboardingChecklist_ValidApplication(t *testing.T) {
	k, ctx := newTestKeeper(t)
	app := validTestApplication()

	items := keeper.RunOnboardingChecklist(ctx, k, app)

	require.NotEmpty(t, items)
	require.GreaterOrEqual(t, len(items), 6, "must have at least 6 checklist items")
}

func TestOnboardingChecklist_AllPassForValid(t *testing.T) {
	k, ctx := newTestKeeper(t)
	app := validTestApplication()

	items := keeper.RunOnboardingChecklist(ctx, k, app)

	// All required items should pass for a valid application
	for _, item := range items {
		if item.Required {
			require.True(t, item.Passed,
				"required item %s should pass for valid application: %s", item.ID, item.Details)
		}
	}
}

func TestOnboardingChecklist_DuplicateRejects(t *testing.T) {
	k, ctx := newTestKeeper(t)
	app := validTestApplication()

	// Pre-register the validator
	stats := types.ValidatorStats{
		ValidatorAddress:   app.ValidatorAddr,
		ReputationScore:    50,
		TotalJobsProcessed: 0,
	}
	require.NoError(t, k.ValidatorStats.Set(ctx, app.ValidatorAddr, stats))

	items := keeper.RunOnboardingChecklist(ctx, k, app)

	// OB-02 should fail (already registered)
	for _, item := range items {
		if item.ID == "OB-02" {
			require.False(t, item.Passed,
				"OB-02 should fail for already-registered validator")
			return
		}
	}
	t.Fatal("OB-02 not found in checklist")
}

func TestOnboardingChecklist_AllHaveRequiredFields(t *testing.T) {
	k, ctx := newTestKeeper(t)
	app := validTestApplication()

	items := keeper.RunOnboardingChecklist(ctx, k, app)

	for _, item := range items {
		require.NotEmpty(t, item.ID, "item must have ID")
		require.NotEmpty(t, item.Category, "item %s must have category", item.ID)
		require.NotEmpty(t, item.Description, "item %s must have description", item.ID)
	}
}

func TestOnboardingChecklist_CoversCriticalAreas(t *testing.T) {
	k, ctx := newTestKeeper(t)
	app := validTestApplication()

	items := keeper.RunOnboardingChecklist(ctx, k, app)

	categories := make(map[string]bool)
	for _, item := range items {
		categories[item.Category] = true
	}

	require.True(t, categories["application"], "must check application")
	require.True(t, categories["registration"], "must check registration")
	require.True(t, categories["capability"], "must check capability")
	require.True(t, categories["chain_health"], "must check chain health")
}

// =============================================================================
// Section 4: Readiness Scoring
// =============================================================================

func TestReadinessScore_PerfectApplication(t *testing.T) {
	app := validTestApplication()
	checks := []keeper.OnboardingCheckItem{
		{ID: "OB-01", Passed: true, Required: true},
		{ID: "OB-02", Passed: true, Required: true},
		{ID: "OB-03", Passed: true, Required: true},
		{ID: "OB-04", Passed: true, Required: false},
		{ID: "OB-05", Passed: true, Required: true},
		{ID: "OB-06", Passed: true, Required: true},
	}

	score := keeper.ComputeOnboardingReadiness(app, checks)

	require.Equal(t, 100, score, "perfect application should score 100")
}

func TestReadinessScore_PartialCapabilities(t *testing.T) {
	app := validTestApplication()
	app.SupportsZKML = false
	app.SupportsHybrid = false
	app.ZKMLBackend = ""

	checks := []keeper.OnboardingCheckItem{
		{ID: "OB-01", Passed: true, Required: true},
		{ID: "OB-02", Passed: true, Required: true},
	}

	score := keeper.ComputeOnboardingReadiness(app, checks)

	require.Greater(t, score, 0)
	require.Less(t, score, 100, "partial capabilities should score < 100")
}

func TestReadinessScore_FailedChecks(t *testing.T) {
	app := validTestApplication()

	checks := []keeper.OnboardingCheckItem{
		{ID: "OB-01", Passed: true, Required: true},
		{ID: "OB-02", Passed: false, Required: true},
		{ID: "OB-03", Passed: false, Required: true},
	}

	score := keeper.ComputeOnboardingReadiness(app, checks)

	require.Less(t, score, 80, "failed checks should reduce score below threshold")
}

func TestReadinessScore_AutoApproveThreshold(t *testing.T) {
	app := validTestApplication()
	checks := []keeper.OnboardingCheckItem{
		{ID: "OB-01", Passed: true, Required: true},
		{ID: "OB-02", Passed: true, Required: true},
		{ID: "OB-03", Passed: true, Required: true},
		{ID: "OB-04", Passed: true, Required: false},
	}

	score := keeper.ComputeOnboardingReadiness(app, checks)
	approved := keeper.ShouldAutoApprove(score, checks)

	require.True(t, approved, "high-scoring application should auto-approve")
}

func TestReadinessScore_NoAutoApproveWithFailedRequired(t *testing.T) {
	checks := []keeper.OnboardingCheckItem{
		{ID: "OB-01", Passed: true, Required: true},
		{ID: "OB-02", Passed: false, Required: true},
	}

	// Even with high score, failed required items prevent approval
	approved := keeper.ShouldAutoApprove(90, checks)
	require.False(t, approved, "failed required check should prevent auto-approval")
}

// =============================================================================
// Section 5: Onboarding Dashboard
// =============================================================================

func TestOnboardingDashboard_EmptyState(t *testing.T) {
	k, ctx := newTestKeeper(t)

	dash := keeper.BuildOnboardingDashboard(ctx, k)

	require.NotNil(t, dash)
	require.Equal(t, ctx.ChainID(), dash.ChainID)
	require.Equal(t, 0, dash.TotalValidators)
	require.Equal(t, 0, dash.ActiveValidators)
}

func TestOnboardingDashboard_WithValidators(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Add validators with stats
	for i := 0; i < 3; i++ {
		addr := fmt.Sprintf("val-%d", i)
		stats := types.ValidatorStats{
			ValidatorAddress:   addr,
			ReputationScore:    80,
			TotalJobsProcessed: 50,
		}
		require.NoError(t, k.ValidatorStats.Set(ctx, addr, stats))
	}

	dash := keeper.BuildOnboardingDashboard(ctx, k)

	require.Equal(t, 3, dash.TotalValidators)
	require.InDelta(t, 80.0, dash.AvgReputation, 0.1)
}

func TestOnboardingDashboard_RenderReport(t *testing.T) {
	k, ctx := newTestKeeper(t)

	rendered := keeper.RenderOnboardingReport(ctx, k)

	require.Contains(t, rendered, "VALIDATOR ONBOARDING DASHBOARD")
	require.Contains(t, rendered, "VALIDATOR SET")
	require.Contains(t, rendered, "CAPABILITY COVERAGE")
	require.Contains(t, rendered, "READINESS ASSESSMENT")

	t.Log(rendered)
}

// =============================================================================
// Section 6: Batch Processing
// =============================================================================

func TestBatchOnboarding_AllApproved(t *testing.T) {
	k, ctx := newTestKeeper(t)

	apps := []keeper.OnboardingApplication{
		func() keeper.OnboardingApplication {
			a := validTestApplication()
			a.ValidatorAddr = "val-1"
			a.Moniker = "validator-1"
			return a
		}(),
		func() keeper.OnboardingApplication {
			a := validTestApplication()
			a.ValidatorAddr = "val-2"
			a.Moniker = "validator-2"
			return a
		}(),
	}

	summary := keeper.ProcessApplicationBatch(ctx, k, apps)

	require.Equal(t, 2, summary.Total)
	require.Equal(t, 2, summary.Approved, "all valid applications should be approved")
	require.Equal(t, 0, summary.Rejected)
}

func TestBatchOnboarding_MixedResults(t *testing.T) {
	k, ctx := newTestKeeper(t)

	apps := []keeper.OnboardingApplication{
		func() keeper.OnboardingApplication {
			a := validTestApplication()
			a.ValidatorAddr = "val-good"
			a.Moniker = "good-validator"
			return a
		}(),
		func() keeper.OnboardingApplication {
			// Invalid: no proof types
			return keeper.OnboardingApplication{
				ValidatorAddr:     "val-bad",
				Moniker:           "bad-validator",
				MaxConcurrentJobs: 5,
				NodeVersion:       "v1.0.0",
				SupportsTEE:       false,
				SupportsZKML:      false,
				SupportsHybrid:    false,
			}
		}(),
	}

	summary := keeper.ProcessApplicationBatch(ctx, k, apps)

	require.Equal(t, 2, summary.Total)
	require.Equal(t, 1, summary.Approved)
	require.Equal(t, 1, summary.Rejected)
}

func TestBatchOnboarding_SortedByReadiness(t *testing.T) {
	k, ctx := newTestKeeper(t)

	apps := []keeper.OnboardingApplication{
		func() keeper.OnboardingApplication {
			a := validTestApplication()
			a.ValidatorAddr = "val-partial"
			a.Moniker = "partial"
			a.SupportsZKML = false
			a.SupportsHybrid = false
			a.ZKMLBackend = ""
			return a
		}(),
		func() keeper.OnboardingApplication {
			a := validTestApplication()
			a.ValidatorAddr = "val-full"
			a.Moniker = "full"
			return a
		}(),
	}

	summary := keeper.ProcessApplicationBatch(ctx, k, apps)

	require.Equal(t, 2, summary.Total)
	require.GreaterOrEqual(t, len(summary.Results), 2)
	// Results should be sorted by readiness score descending
	require.GreaterOrEqual(t, summary.Results[0].ReadinessScore, summary.Results[1].ReadinessScore,
		"results should be sorted by readiness score descending")
}

func TestBatchOnboarding_EmptyBatch(t *testing.T) {
	k, ctx := newTestKeeper(t)

	summary := keeper.ProcessApplicationBatch(ctx, k, nil)

	require.Equal(t, 0, summary.Total)
	require.Equal(t, 0, summary.Approved)
	require.Equal(t, 0, summary.Rejected)
}
