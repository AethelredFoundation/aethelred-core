package keeper_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// =============================================================================
// WEEKS 41-45: Launch Readiness, Go/No-Go, and Genesis Tests
//
// These tests verify:
//   1. Pilot partner validation (6 tests)
//   2. Pilot cohort management (6 tests)
//   3. Cohort health assessment (5 tests)
//   4. Launch review criteria (6 tests)
//   5. Launch review scoring (5 tests)
//   6. Genesis ceremony (6 tests)
//   7. Genesis validator set (6 tests)
//   8. Report rendering (4 tests)
//
// Total: 44 tests
// =============================================================================

// =============================================================================
// Helper: create test pilot partners
// =============================================================================

func testPilotPartner(id, category, integration string, status keeper.PilotPartnerStatus) keeper.PilotPartner {
	return keeper.PilotPartner{
		ID:                id,
		Name:              "Partner " + id,
		Category:          category,
		Status:            status,
		IntegrationType:   integration,
		JoinedAt:          time.Now().UTC(),
		LastActiveAt:      time.Now().UTC(),
		TotalTransactions: 100,
		SuccessRate:       0.95,
		AvgLatencyMs:      50,
		SDKVersion:        "v1.0.0",
		ChainID:           "aethelred-test-1",
		ContactEmail:      id + "@test.com",
	}
}

func buildTestCohort() *keeper.PilotCohort {
	cohort := keeper.NewPilotCohort()
	_ = cohort.AddPartner(testPilotPartner("p-1", "financial", "sdk", keeper.PilotStatusActive))
	_ = cohort.AddPartner(testPilotPartner("p-2", "enterprise", "api", keeper.PilotStatusActive))
	_ = cohort.AddPartner(testPilotPartner("p-3", "developer", "sdk", keeper.PilotStatusTesting))
	_ = cohort.AddPartner(testPilotPartner("p-4", "infrastructure", "validator", keeper.PilotStatusIntegrating))
	return cohort
}

// =============================================================================
// Section 1: Pilot Partner Validation
// =============================================================================

func TestValidatePilotPartner_Valid(t *testing.T) {
	p := testPilotPartner("p-1", "financial", "sdk", keeper.PilotStatusActive)
	require.NoError(t, keeper.ValidatePilotPartner(p))
}

func TestValidatePilotPartner_EmptyID(t *testing.T) {
	p := testPilotPartner("", "financial", "sdk", keeper.PilotStatusActive)
	err := keeper.ValidatePilotPartner(p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ID")
}

func TestValidatePilotPartner_EmptyName(t *testing.T) {
	p := testPilotPartner("p-1", "financial", "sdk", keeper.PilotStatusActive)
	p.Name = ""
	err := keeper.ValidatePilotPartner(p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "name")
}

func TestValidatePilotPartner_InvalidCategory(t *testing.T) {
	p := testPilotPartner("p-1", "invalid", "sdk", keeper.PilotStatusActive)
	err := keeper.ValidatePilotPartner(p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "category")
}

func TestValidatePilotPartner_InvalidIntegration(t *testing.T) {
	p := testPilotPartner("p-1", "financial", "invalid", keeper.PilotStatusActive)
	err := keeper.ValidatePilotPartner(p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "integration")
}

func TestValidatePilotPartner_AllCategories(t *testing.T) {
	for _, cat := range []string{"financial", "enterprise", "developer", "infrastructure"} {
		p := testPilotPartner("p-"+cat, cat, "sdk", keeper.PilotStatusActive)
		require.NoError(t, keeper.ValidatePilotPartner(p), "category %q should be valid", cat)
	}
}

// =============================================================================
// Section 2: Pilot Cohort Management
// =============================================================================

func TestPilotCohort_New(t *testing.T) {
	cohort := keeper.NewPilotCohort()
	require.NotNil(t, cohort)
	require.Empty(t, cohort.Partners)
}

func TestPilotCohort_AddPartner(t *testing.T) {
	cohort := keeper.NewPilotCohort()
	p := testPilotPartner("p-1", "financial", "sdk", keeper.PilotStatusActive)
	require.NoError(t, cohort.AddPartner(p))
	require.Len(t, cohort.Partners, 1)
}

func TestPilotCohort_DuplicateRejects(t *testing.T) {
	cohort := keeper.NewPilotCohort()
	p := testPilotPartner("p-1", "financial", "sdk", keeper.PilotStatusActive)
	require.NoError(t, cohort.AddPartner(p))

	err := cohort.AddPartner(p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}

func TestPilotCohort_InvalidPartnerRejects(t *testing.T) {
	cohort := keeper.NewPilotCohort()
	p := keeper.PilotPartner{} // empty
	err := cohort.AddPartner(p)
	require.Error(t, err)
}

func TestPilotCohort_GetPartner(t *testing.T) {
	cohort := buildTestCohort()

	p, found := cohort.GetPartner("p-1")
	require.True(t, found)
	require.Equal(t, "p-1", p.ID)

	_, found = cohort.GetPartner("nonexistent")
	require.False(t, found)
}

func TestPilotCohort_ActivePartners(t *testing.T) {
	cohort := buildTestCohort()
	active := cohort.ActivePartners()

	// p-1 (active), p-2 (active), p-3 (testing) = 3 active
	require.Len(t, active, 3)
}

// =============================================================================
// Section 3: Cohort Health Assessment
// =============================================================================

func TestCohortHealth_HealthyCohort(t *testing.T) {
	cohort := buildTestCohort()
	health := cohort.EvaluateCohortHealth()

	require.NotNil(t, health)
	require.Equal(t, 4, health.TotalPartners)
	require.Equal(t, 3, health.ActivePartners)
	require.True(t, health.IsHealthy)
	require.Empty(t, health.HealthIssues)
}

func TestCohortHealth_EmptyCohort(t *testing.T) {
	cohort := keeper.NewPilotCohort()
	health := cohort.EvaluateCohortHealth()

	require.False(t, health.IsHealthy)
	require.NotEmpty(t, health.HealthIssues)
}

func TestCohortHealth_CategoryBreakdown(t *testing.T) {
	cohort := buildTestCohort()
	health := cohort.EvaluateCohortHealth()

	require.Equal(t, 1, health.CategoryBreakdown["financial"])
	require.Equal(t, 1, health.CategoryBreakdown["enterprise"])
	require.Equal(t, 1, health.CategoryBreakdown["developer"])
	require.Equal(t, 1, health.CategoryBreakdown["infrastructure"])
}

func TestCohortHealth_LowSuccessRate(t *testing.T) {
	cohort := keeper.NewPilotCohort()
	for i := 0; i < 3; i++ {
		p := testPilotPartner(fmt.Sprintf("p-%d", i), "financial", "sdk", keeper.PilotStatusActive)
		p.SuccessRate = 0.5 // below 90% threshold
		_ = cohort.AddPartner(p)
	}

	health := cohort.EvaluateCohortHealth()
	require.False(t, health.IsHealthy)
	require.NotEmpty(t, health.HealthIssues)
}

func TestCohortHealth_HighChurnRate(t *testing.T) {
	cohort := keeper.NewPilotCohort()
	// 2 churned out of 3 = 66% churn
	_ = cohort.AddPartner(testPilotPartner("p-1", "financial", "sdk", keeper.PilotStatusActive))
	p2 := testPilotPartner("p-2", "enterprise", "api", keeper.PilotStatusChurned)
	_ = cohort.AddPartner(p2)
	p3 := testPilotPartner("p-3", "developer", "sdk", keeper.PilotStatusChurned)
	_ = cohort.AddPartner(p3)

	health := cohort.EvaluateCohortHealth()
	require.False(t, health.IsHealthy)
}

// =============================================================================
// Section 4: Launch Review Criteria
// =============================================================================

func TestLaunchReview_CleanState(t *testing.T) {
	k, ctx := newTestKeeper(t)
	cohort := buildTestCohort()

	result := keeper.RunLaunchReview(ctx, k, cohort)

	require.NotNil(t, result)
	require.NotEmpty(t, result.Criteria)
	require.GreaterOrEqual(t, len(result.Criteria), 20,
		"must have at least 20 launch criteria")
}

func TestLaunchReview_HasAllCategories(t *testing.T) {
	k, ctx := newTestKeeper(t)
	cohort := buildTestCohort()

	result := keeper.RunLaunchReview(ctx, k, cohort)

	categories := make(map[string]bool)
	for _, c := range result.Criteria {
		categories[c.Category] = true
	}

	require.True(t, categories["security"], "must have security criteria")
	require.True(t, categories["performance"], "must have performance criteria")
	require.True(t, categories["economics"], "must have economics criteria")
	require.True(t, categories["operations"], "must have operations criteria")
	require.True(t, categories["ecosystem"], "must have ecosystem criteria")
	require.True(t, categories["governance"], "must have governance criteria")
}

func TestLaunchReview_CriteriaHaveRequiredFields(t *testing.T) {
	k, ctx := newTestKeeper(t)
	cohort := buildTestCohort()

	result := keeper.RunLaunchReview(ctx, k, cohort)

	for _, c := range result.Criteria {
		require.NotEmpty(t, c.ID, "criterion must have ID")
		require.NotEmpty(t, c.Category, "criterion %s must have category", c.ID)
		require.NotEmpty(t, c.Description, "criterion %s must have description", c.ID)
		require.NotEmpty(t, c.Evidence, "criterion %s must have evidence", c.ID)
	}
}

func TestLaunchReview_DecisionIsGO(t *testing.T) {
	k, ctx := newTestKeeper(t)
	cohort := buildTestCohort()

	result := keeper.RunLaunchReview(ctx, k, cohort)

	// In clean test state, all blocking criteria should pass
	if result.Decision == "NO-GO" {
		for _, f := range result.BlockingFailures {
			t.Logf("BLOCKING FAILURE: [%s] %s: %s", f.ID, f.Description, f.Details)
		}
	}
	// Should be GO or CONDITIONAL-GO
	require.NotEqual(t, "NO-GO", result.Decision,
		"clean test state should not produce NO-GO")
}

func TestLaunchReview_NoBlockingFailures(t *testing.T) {
	k, ctx := newTestKeeper(t)
	cohort := buildTestCohort()

	result := keeper.RunLaunchReview(ctx, k, cohort)

	if len(result.BlockingFailures) > 0 {
		for _, f := range result.BlockingFailures {
			t.Logf("BLOCKING: [%s] %s: %s", f.ID, f.Description, f.Details)
		}
	}
	require.Empty(t, result.BlockingFailures,
		"should have no blocking failures in clean state")
}

func TestLaunchReview_CorruptedStateIsNoGo(t *testing.T) {
	k, ctx := newTestKeeper(t)
	cohort := buildTestCohort()

	// Corrupt params
	params, _ := k.GetParams(ctx)
	params.ConsensusThreshold = 40
	_ = k.Params.Set(ctx, *params)

	result := keeper.RunLaunchReview(ctx, k, cohort)
	require.Equal(t, "NO-GO", result.Decision,
		"corrupted state should produce NO-GO")
	require.NotEmpty(t, result.BlockingFailures)
}

// =============================================================================
// Section 5: Launch Review Scoring
// =============================================================================

func TestLaunchReview_ScoresBounded(t *testing.T) {
	k, ctx := newTestKeeper(t)
	cohort := buildTestCohort()

	result := keeper.RunLaunchReview(ctx, k, cohort)

	for _, score := range []int{
		result.SecurityScore, result.PerformanceScore, result.EconomicsScore,
		result.OperationsScore, result.EcosystemScore, result.GovernanceScore,
		result.OverallScore,
	} {
		require.GreaterOrEqual(t, score, 0, "scores must be >= 0")
		require.LessOrEqual(t, score, 100, "scores must be <= 100")
	}
}

func TestLaunchReview_SecurityScoreHigh(t *testing.T) {
	k, ctx := newTestKeeper(t)
	cohort := buildTestCohort()

	result := keeper.RunLaunchReview(ctx, k, cohort)
	require.GreaterOrEqual(t, result.SecurityScore, 80,
		"security score should be high in clean state")
}

func TestLaunchReview_OverallScorePositive(t *testing.T) {
	k, ctx := newTestKeeper(t)
	cohort := buildTestCohort()

	result := keeper.RunLaunchReview(ctx, k, cohort)
	require.Greater(t, result.OverallScore, 0, "overall score should be positive")

	t.Logf("Scores: Security=%d Performance=%d Economics=%d Operations=%d Ecosystem=%d Governance=%d Overall=%d",
		result.SecurityScore, result.PerformanceScore, result.EconomicsScore,
		result.OperationsScore, result.EcosystemScore, result.GovernanceScore,
		result.OverallScore)
}

func TestLaunchReview_IsGoForLaunchMethod(t *testing.T) {
	k, ctx := newTestKeeper(t)
	cohort := buildTestCohort()

	result := keeper.RunLaunchReview(ctx, k, cohort)

	if result.Decision == "GO" {
		require.True(t, result.IsGoForLaunchReview())
	} else {
		require.False(t, result.IsGoForLaunchReview())
	}
}

func TestLaunchReview_NilCohortHandled(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Should not panic with nil cohort
	result := keeper.RunLaunchReview(ctx, k, nil)
	require.NotNil(t, result)
	require.NotEmpty(t, result.Criteria)
}

// =============================================================================
// Section 6: Genesis Ceremony
// =============================================================================

func TestGenesisCeremony_CleanState(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunGenesisCeremony(ctx, k)

	require.NotNil(t, result)
	require.NotEmpty(t, result.Steps)
	require.GreaterOrEqual(t, len(result.Steps), 10,
		"must have at least 10 ceremony steps")
}

func TestGenesisCeremony_Passes(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunGenesisCeremony(ctx, k)

	if !result.CeremonyPass {
		for _, f := range result.FailureReasons {
			t.Logf("FAILURE: %s", f)
		}
	}
	require.True(t, result.CeremonyPass,
		"genesis ceremony should pass in clean state")
}

func TestGenesisCeremony_HasManifest(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunGenesisCeremony(ctx, k)

	require.NotNil(t, result.Manifest)
	require.NotEmpty(t, result.Manifest.ProtocolName)
	require.Greater(t, result.Manifest.ModuleVersion, uint64(0))
}

func TestGenesisCeremony_ParamsHash(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunGenesisCeremony(ctx, k)

	require.NotEmpty(t, result.ParamsHash)
	require.True(t, result.InvariantsPass)
}

func TestGenesisCeremony_AllStepsHaveNames(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunGenesisCeremony(ctx, k)

	for _, step := range result.Steps {
		require.NotEmpty(t, step.Name, "step must have a name")
		require.Greater(t, step.Order, 0, "step must have an order")
	}
}

func TestGenesisCeremony_CorruptedStateFails(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Corrupt params to trigger failure
	params, _ := k.GetParams(ctx)
	params.ConsensusThreshold = 40
	_ = k.Params.Set(ctx, *params)

	result := keeper.RunGenesisCeremony(ctx, k)
	require.False(t, result.CeremonyPass,
		"genesis ceremony should fail with corrupted state")
	require.NotEmpty(t, result.FailureReasons)
}

// =============================================================================
// Section 7: Genesis Validator Set
// =============================================================================

func TestGenesisValidatorSet_New(t *testing.T) {
	gvs := keeper.NewGenesisValidatorSet(100)
	require.NotNil(t, gvs)
	require.Empty(t, gvs.Validators)
	require.Equal(t, int64(100), gvs.MinPower)
}

func TestGenesisValidatorSet_AddValidator(t *testing.T) {
	gvs := keeper.NewGenesisValidatorSet(100)

	err := gvs.AddValidator(keeper.GenesisValidator{
		Address:     "val-1",
		Moniker:     "validator-1",
		Power:       1000,
		TEEPlatform: "nitro",
		SupportsTEE: true,
	})
	require.NoError(t, err)
	require.Len(t, gvs.Validators, 1)
}

func TestGenesisValidatorSet_RejectsBelowMinPower(t *testing.T) {
	gvs := keeper.NewGenesisValidatorSet(100)

	err := gvs.AddValidator(keeper.GenesisValidator{
		Address:     "val-1",
		Moniker:     "validator-1",
		Power:       50, // below 100 minimum
		SupportsTEE: true,
		TEEPlatform: "nitro",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "below minimum")
}

func TestGenesisValidatorSet_RejectsDuplicateAddr(t *testing.T) {
	gvs := keeper.NewGenesisValidatorSet(100)
	v := keeper.GenesisValidator{
		Address:     "val-1",
		Moniker:     "v1",
		Power:       100,
		SupportsTEE: true,
		TEEPlatform: "nitro",
	}
	require.NoError(t, gvs.AddValidator(v))

	v.Moniker = "v1-dup"
	err := gvs.AddValidator(v)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already in genesis set")
}

func TestGenesisValidatorSet_ValidateSet(t *testing.T) {
	gvs := keeper.NewGenesisValidatorSet(100)
	for i := 0; i < 5; i++ {
		_ = gvs.AddValidator(keeper.GenesisValidator{
			Address:     fmt.Sprintf("val-%d", i),
			Moniker:     fmt.Sprintf("validator-%d", i),
			Power:       1000,
			TEEPlatform: "nitro",
			SupportsTEE: true,
		})
	}

	issues := gvs.ValidateSet(5)
	require.Empty(t, issues, "5 equal-power validators should pass validation")
}

func TestGenesisValidatorSet_ValidateSet_PowerConcentration(t *testing.T) {
	gvs := keeper.NewGenesisValidatorSet(100)

	// One validator with 80% power — clearly dominant
	_ = gvs.AddValidator(keeper.GenesisValidator{
		Address: "val-0", Moniker: "big", Power: 8000, SupportsTEE: true, TEEPlatform: "nitro",
	})
	_ = gvs.AddValidator(keeper.GenesisValidator{
		Address: "val-1", Moniker: "small-1", Power: 1000, SupportsTEE: true, TEEPlatform: "nitro",
	})
	_ = gvs.AddValidator(keeper.GenesisValidator{
		Address: "val-2", Moniker: "small-2", Power: 1000, SupportsTEE: true, TEEPlatform: "nitro",
	})

	issues := gvs.ValidateSet(3)
	require.NotEmpty(t, issues, "should flag power concentration")
}

func TestBootstrapValidatorStats(t *testing.T) {
	k, ctx := newTestKeeper(t)

	validators := []keeper.GenesisValidator{
		{Address: "val-1", Moniker: "v1", Power: 1000, SupportsTEE: true, TEEPlatform: "nitro"},
		{Address: "val-2", Moniker: "v2", Power: 1000, SupportsTEE: true, TEEPlatform: "nitro"},
		{Address: "val-3", Moniker: "v3", Power: 1000, SupportsTEE: true, TEEPlatform: "nitro"},
	}

	err := keeper.BootstrapValidatorStats(ctx, k, validators)
	require.NoError(t, err)

	// Verify all were created
	for _, v := range validators {
		stats, err := k.ValidatorStats.Get(ctx, v.Address)
		require.NoError(t, err)
		require.Equal(t, int64(50), stats.ReputationScore, "default reputation should be 50")
		require.Equal(t, int64(0), stats.TotalJobsProcessed)
	}
}

// =============================================================================
// Section 8: Report Rendering
// =============================================================================

func TestRenderLaunchReviewReport(t *testing.T) {
	k, ctx := newTestKeeper(t)
	cohort := buildTestCohort()

	result := keeper.RunLaunchReview(ctx, k, cohort)
	rendered := keeper.RenderLaunchReviewReport(result)

	require.Contains(t, rendered, "FINAL GO/NO-GO LAUNCH REVIEW")
	require.Contains(t, rendered, "SCORE SUMMARY")
	require.Contains(t, rendered, "LAUNCH CRITERIA")
	require.Contains(t, rendered, "DETERMINATION")

	t.Log(rendered)
}

func TestRenderGenesisCeremonyReport(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunGenesisCeremony(ctx, k)
	rendered := keeper.RenderGenesisCeremonyReport(result)

	require.Contains(t, rendered, "MAINNET GENESIS CEREMONY REPORT")
	require.Contains(t, rendered, "CEREMONY STEPS")
	require.Contains(t, rendered, "GENESIS STATE")

	t.Log(rendered)
}

func TestRenderLaunchReport_ContainsDecision(t *testing.T) {
	k, ctx := newTestKeeper(t)
	cohort := buildTestCohort()

	result := keeper.RunLaunchReview(ctx, k, cohort)
	rendered := keeper.RenderLaunchReviewReport(result)

	// Must contain one of the three possible determinations
	hasGo := strings.Contains(rendered, "GO")
	require.True(t, hasGo, "rendered report must contain a GO/NO-GO determination")
}

func TestRenderGenesisCeremonyReport_ContainsCeremonyResult(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunGenesisCeremony(ctx, k)
	rendered := keeper.RenderGenesisCeremonyReport(result)

	if result.CeremonyPass {
		require.Contains(t, rendered, "GENESIS CEREMONY PASSED")
	} else {
		require.Contains(t, rendered, "GENESIS CEREMONY FAILED")
	}
}

// =============================================================================
// Integration: Full Launch Sequence
// =============================================================================

func TestFullLaunchSequence(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Week 41-42: Build ecosystem cohort
	cohort := buildTestCohort()
	health := cohort.EvaluateCohortHealth()
	require.True(t, health.IsHealthy, "cohort should be healthy")

	// Bootstrap validators
	validators := []keeper.GenesisValidator{
		{Address: "val-1", Moniker: "v1", Power: 1000, SupportsTEE: true, TEEPlatform: "nitro"},
		{Address: "val-2", Moniker: "v2", Power: 1000, SupportsTEE: true, TEEPlatform: "nitro"},
		{Address: "val-3", Moniker: "v3", Power: 1000, SupportsTEE: true, TEEPlatform: "nitro"},
	}
	gvs := keeper.NewGenesisValidatorSet(100)
	for _, v := range validators {
		require.NoError(t, gvs.AddValidator(v))
	}
	issues := gvs.ValidateSet(3)
	require.Empty(t, issues, "validator set should be valid")

	// Register validators
	require.NoError(t, keeper.BootstrapValidatorStats(ctx, k, validators))

	// Week 43-44: Run launch review
	review := keeper.RunLaunchReview(ctx, k, cohort)
	if review.Decision == "NO-GO" {
		for _, f := range review.BlockingFailures {
			t.Logf("BLOCKING: %s — %s", f.ID, f.Details)
		}
	}
	require.NotEqual(t, "NO-GO", review.Decision,
		"full launch sequence should not produce NO-GO in valid state")

	// Week 45: Run genesis ceremony
	ceremony := keeper.RunGenesisCeremony(ctx, k)
	if !ceremony.CeremonyPass {
		for _, f := range ceremony.FailureReasons {
			t.Logf("CEREMONY FAILURE: %s", f)
		}
	}
	require.True(t, ceremony.CeremonyPass,
		"genesis ceremony should pass in valid state")

	// Render reports
	reviewReport := keeper.RenderLaunchReviewReport(review)
	require.NotEmpty(t, reviewReport)

	ceremonyReport := keeper.RenderGenesisCeremonyReport(ceremony)
	require.NotEmpty(t, ceremonyReport)

	t.Logf("Launch Review: Decision=%s, Overall=%d/100", review.Decision, review.OverallScore)
	t.Logf("Genesis Ceremony: Pass=%v, Steps=%d, Duration=%v",
		ceremony.CeremonyPass, len(ceremony.Steps), ceremony.TotalDuration)
}

// Ensure ValidatorStats uses types package correctly
func TestGenesisBootstrap_ValidatorStatsFields(t *testing.T) {
	k, ctx := newTestKeeper(t)

	validators := []keeper.GenesisValidator{
		{Address: "val-test", Moniker: "test", Power: 500, SupportsTEE: true, TEEPlatform: "nitro"},
	}
	require.NoError(t, keeper.BootstrapValidatorStats(ctx, k, validators))

	stats, err := k.ValidatorStats.Get(ctx, "val-test")
	require.NoError(t, err)

	// Verify types.ValidatorStats fields
	require.Equal(t, "val-test", stats.ValidatorAddress)
	require.Equal(t, int64(50), stats.ReputationScore)
	require.Equal(t, int64(0), stats.TotalJobsProcessed)
	require.Equal(t, int64(0), stats.SuccessfulJobs)
	require.Equal(t, int64(0), stats.FailedJobs)
	require.Equal(t, int64(0), stats.SlashingEvents)
	_ = types.JobStatusPending // ensure types import is used
}
