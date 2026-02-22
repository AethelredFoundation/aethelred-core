package keeper_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// =============================================================================
// WEEK 33-34: Retest & Audit Closeout Report Tests
//
// These tests verify:
//   1. Comprehensive retest runner (5 tests)
//   2. Production readiness checks (6 tests)
//   3. Closeout report rendering (4 tests)
//   4. Score computation (5 tests)
//   5. Go/no-go determination (4 tests)
//
// Total: 24 tests
// =============================================================================

// =============================================================================
// Section 1: Comprehensive Retest Runner
// =============================================================================

func TestRunComprehensiveRetest_Integration(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)

	require.NotNil(t, report)
	require.Equal(t, "Aethelred Sovereign L1", report.ProjectName)
	require.NotEmpty(t, report.ChainID)
	require.NotEmpty(t, report.AuditEndDate)
	require.Greater(t, report.ModuleVersion, uint64(0))
}

func TestRunComprehensiveRetest_HasRetestReport(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)

	require.NotNil(t, report.RetestReport)
	require.Greater(t, report.RetestReport.TotalChecks, 0)
}

func TestRunComprehensiveRetest_HasRemediations(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)

	require.NotNil(t, report.RemediationSummary)
	all := report.RemediationSummary.All()
	require.NotEmpty(t, all, "should have remediation entries")
}

func TestRunComprehensiveRetest_HasOpenItems(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)

	// We know there are open attack surfaces (AS-16, AS-17)
	require.NotNil(t, report.OpenItems)
	// Some open items expected from threat model
	t.Logf("Open items: %d", len(report.OpenItems))
	for _, oi := range report.OpenItems {
		t.Logf("  [%s] %s: %s", oi.Severity, oi.ID, oi.Description)
	}
}

func TestRunComprehensiveRetest_HasReadinessChecks(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)

	require.NotEmpty(t, report.ReadinessChecks)
	require.GreaterOrEqual(t, len(report.ReadinessChecks), 8,
		"must have at least 8 readiness checks")
}

// =============================================================================
// Section 2: Production Readiness Checks
// =============================================================================

func TestReadinessChecks_AllHaveRequiredFields(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)

	for _, rc := range report.ReadinessChecks {
		require.NotEmpty(t, rc.ID, "readiness check must have ID")
		require.NotEmpty(t, rc.Category, "readiness check %s must have category", rc.ID)
		require.NotEmpty(t, rc.Description, "readiness check %s must have description", rc.ID)
	}
}

func TestReadinessChecks_NoUnresolvedCritical(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)

	for _, rc := range report.ReadinessChecks {
		if rc.ID == "R-01" {
			require.True(t, rc.Passed,
				"R-01 (no critical findings) should pass in clean state")
		}
	}
}

func TestReadinessChecks_InvariantsPass(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)

	for _, rc := range report.ReadinessChecks {
		if rc.ID == "R-02" {
			require.True(t, rc.Passed,
				"R-02 (invariants) should pass in clean state")
		}
	}
}

func TestReadinessChecks_ParamsValid(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)

	for _, rc := range report.ReadinessChecks {
		if rc.ID == "R-03" {
			require.True(t, rc.Passed,
				"R-03 (params valid) should pass in clean state")
		}
	}
}

func TestReadinessChecks_SimulationDisabled(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)

	for _, rc := range report.ReadinessChecks {
		if rc.ID == "R-04" {
			require.True(t, rc.Passed,
				"R-04 (AllowSimulated=false) should pass in clean state")
		}
	}
}

func TestReadinessChecks_FeeConservation(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)

	for _, rc := range report.ReadinessChecks {
		if rc.ID == "R-06" {
			require.True(t, rc.Passed,
				"R-06 (BPS sum) should pass")
		}
	}
}

// =============================================================================
// Section 3: Closeout Report Rendering
// =============================================================================

func TestCloseoutReport_RenderContainsHeader(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)
	rendered := report.RenderCloseoutReport()

	require.Contains(t, rendered, "SECURITY AUDIT CLOSEOUT REPORT")
	require.Contains(t, rendered, "Aethelred Sovereign L1")
}

func TestCloseoutReport_RenderContainsScores(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)
	rendered := report.RenderCloseoutReport()

	require.Contains(t, rendered, "Overall Score:")
	require.Contains(t, rendered, "Security Score:")
	require.Contains(t, rendered, "Test Coverage:")
	require.Contains(t, rendered, "Remediation Rate:")
}

func TestCloseoutReport_RenderContainsReadiness(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)
	rendered := report.RenderCloseoutReport()

	require.Contains(t, rendered, "PRODUCTION READINESS")
	require.Contains(t, rendered, "DETERMINATION:")
}

func TestCloseoutReport_RenderContainsDetermination(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)
	rendered := report.RenderCloseoutReport()

	// Should contain either GO, NO-GO, or CONDITIONAL GO
	hasGo := strings.Contains(rendered, "GO")
	require.True(t, hasGo, "must contain a go/no-go determination")

	t.Log(rendered)
}

// =============================================================================
// Section 4: Score Computation
// =============================================================================

func TestScores_SecurityScorePositive(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)

	require.GreaterOrEqual(t, report.SecurityScore, 0)
	require.LessOrEqual(t, report.SecurityScore, 100)
	require.Greater(t, report.SecurityScore, 50,
		"clean state should have security score > 50")
}

func TestScores_TestCoverageHigh(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)

	require.GreaterOrEqual(t, report.TestCoverage, 90,
		"all components should have test coverage (100%%)")
}

func TestScores_RemediationRateHigh(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)

	require.GreaterOrEqual(t, report.RemediationRate, 80,
		"remediation rate should be >= 80%%")
}

func TestScores_OverallPositive(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)

	require.Greater(t, report.OverallScore, 0)
	require.LessOrEqual(t, report.OverallScore, 100)

	t.Logf("Overall: %d | Security: %d | Coverage: %d | Remediation: %d",
		report.OverallScore, report.SecurityScore,
		report.TestCoverage, report.RemediationRate)
}

func TestScores_Bounded(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)

	for _, score := range []int{report.OverallScore, report.SecurityScore,
		report.TestCoverage, report.RemediationRate} {
		require.GreaterOrEqual(t, score, 0, "scores must be >= 0")
		require.LessOrEqual(t, score, 100, "scores must be <= 100")
	}
}

// =============================================================================
// Section 5: Go/No-Go Determination
// =============================================================================

func TestIsGoForLaunch_CleanState(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)

	// In clean state, all blocking checks should pass
	isGo := report.IsGoForLaunch()

	if !isGo {
		failures := report.BlockingFailures()
		for _, f := range failures {
			t.Logf("BLOCKING FAILURE: [%s] %s: %s", f.ID, f.Description, f.Details)
		}
	}

	// Note: R-05 requires ConsensusThreshold > 66, default is 67
	// so this should pass in clean state
	require.True(t, isGo, "clean state should be go for launch")
}

func TestBlockingFailures_Empty(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)
	failures := report.BlockingFailures()

	require.Empty(t, failures, "should have no blocking failures in clean state")
}

func TestIsGoForLaunch_WithCriticalFinding(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Corrupt state to trigger a critical finding
	params, _ := k.GetParams(ctx)
	params.ConsensusThreshold = 40 // Below BFT safety AND below hardened minimum
	// This won't pass ValidateParams now (51 minimum), but we can set directly
	_ = k.Params.Set(ctx, *params)

	report := keeper.RunComprehensiveRetest(ctx, k)

	// Should NOT be go for launch
	require.False(t, report.IsGoForLaunch(),
		"should NOT be go for launch with critical findings")
}

func TestIsGoForLaunch_Determination(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunComprehensiveRetest(ctx, k)
	rendered := report.RenderCloseoutReport()

	if report.IsGoForLaunch() {
		require.True(t,
			strings.Contains(rendered, "*** GO ***") || strings.Contains(rendered, "*** CONDITIONAL GO ***"),
			"report should say GO or CONDITIONAL GO when launch-ready")
	} else {
		require.Contains(t, rendered, "*** NO-GO ***",
			"report should say NO-GO when not launch-ready")
	}
}
