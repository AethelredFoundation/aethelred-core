package keeper_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// =============================================================================
// WEEKS 46-52: Post-Launch Monitoring & Governance Activation Tests
//
// These tests verify:
//   1. Chain health monitor (7 tests)
//   2. Incident response framework (7 tests)
//   3. Governance activation (6 tests)
//   4. Chain maturity assessment (6 tests)
//   5. Report rendering (4 tests)
//   6. Integration: full post-launch flow (2 tests)
//
// Total: 32 tests
// =============================================================================

// =============================================================================
// Section 1: Chain Health Monitor
// =============================================================================

func TestChainHealthCheck_CleanState(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Seed minimum validators so the health check doesn't flag empty validator set
	for i := 0; i < 3; i++ {
		addr := fmt.Sprintf("health-val-%d", i)
		stats := types.ValidatorStats{
			ValidatorAddress: addr,
			ReputationScore:  70,
		}
		require.NoError(t, k.ValidatorStats.Set(ctx, addr, stats))
	}

	report := keeper.RunChainHealthCheck(ctx, k)

	require.NotNil(t, report)
	require.Equal(t, "aethelred-test-1", report.ChainID)
	require.True(t, report.IsHealthy())
	require.Equal(t, keeper.HealthGreen, report.OverallStatus)
}

func TestChainHealthCheck_HasSubsystems(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunChainHealthCheck(ctx, k)

	require.GreaterOrEqual(t, len(report.Subsystems), 5,
		"must check at least 5 subsystems")

	names := make(map[string]bool)
	for _, s := range report.Subsystems {
		names[s.Name] = true
	}
	require.True(t, names["parameters"], "must check parameters")
	require.True(t, names["invariants"], "must check invariants")
	require.True(t, names["job_queue"], "must check job queue")
	require.True(t, names["validator_set"], "must check validators")
	require.True(t, names["fee_distribution"], "must check fees")
}

func TestChainHealthCheck_SubsystemsHaveFields(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunChainHealthCheck(ctx, k)

	for _, s := range report.Subsystems {
		require.NotEmpty(t, s.Name, "subsystem must have name")
		require.NotEmpty(t, s.Status, "subsystem %s must have status", s.Name)
		require.NotEmpty(t, s.LastChecked, "subsystem %s must have last checked time", s.Name)
	}
}

func TestChainHealthCheck_NoAnomaliesCleanState(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Seed minimum validators so the validator_set check doesn't flag ANO-003
	for i := 0; i < 3; i++ {
		addr := fmt.Sprintf("health-val-%d", i)
		stats := types.ValidatorStats{
			ValidatorAddress: addr,
			ReputationScore:  70,
		}
		require.NoError(t, k.ValidatorStats.Set(ctx, addr, stats))
	}

	report := keeper.RunChainHealthCheck(ctx, k)

	require.Empty(t, report.Anomalies,
		"should have no anomalies with minimum validators seeded")
	require.Empty(t, report.CriticalAnomalies())
}

func TestChainHealthCheck_DetectsInvariantBreak(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Create an orphan to break invariant
	seedJobs(t, ctx, k, 3)
	job, err := k.Jobs.Get(ctx, "job-0")
	require.NoError(t, err)
	job.Status = types.JobStatusCompleted
	require.NoError(t, k.Jobs.Set(ctx, "job-0", job))

	report := keeper.RunChainHealthCheck(ctx, k)

	// Should detect orphan pending job
	require.False(t, report.IsHealthy())
	// At minimum should be yellow (consistency check failure)
	require.NotEqual(t, keeper.HealthGreen, report.OverallStatus)
}

func TestChainHealthCheck_DetectsLowReputation(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Add validators with low reputation
	for i := 0; i < 3; i++ {
		addr := fmt.Sprintf("val-%d", i)
		stats := types.ValidatorStats{
			ValidatorAddress: addr,
			ReputationScore:  20, // below 40 threshold
		}
		require.NoError(t, k.ValidatorStats.Set(ctx, addr, stats))
	}

	report := keeper.RunChainHealthCheck(ctx, k)

	// Should detect low reputation
	require.NotEmpty(t, report.Anomalies)
	found := false
	for _, a := range report.Anomalies {
		if a.Subsystem == "validator_set" && strings.Contains(a.Description, "reputation") {
			found = true
		}
	}
	require.True(t, found, "should detect low reputation anomaly")
}

func TestChainHealthCheck_MetricsPopulated(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.RunChainHealthCheck(ctx, k)

	require.True(t, report.InvariantsPass)
	require.True(t, report.ParamsValid)
	// In clean state, no validators, no jobs
	require.Equal(t, 0, report.ActiveValidators)
	require.Equal(t, uint64(0), report.TotalJobs)
}

// =============================================================================
// Section 2: Incident Response Framework
// =============================================================================

func TestIncidentTracker_New(t *testing.T) {
	tracker := keeper.NewIncidentTracker()
	require.NotNil(t, tracker)
	require.Empty(t, tracker.Incidents)
}

func TestIncidentTracker_CreateIncident(t *testing.T) {
	tracker := keeper.NewIncidentTracker()

	err := tracker.CreateIncident("INC-001", keeper.IncidentSev1,
		"Chain halt detected", "Consensus failure", "2026-01-01T00:00:00Z")
	require.NoError(t, err)
	require.Len(t, tracker.Incidents, 1)
	require.Equal(t, keeper.IncidentOpen, tracker.Incidents[0].Status)
}

func TestIncidentTracker_DuplicateRejects(t *testing.T) {
	tracker := keeper.NewIncidentTracker()

	_ = tracker.CreateIncident("INC-001", keeper.IncidentSev1, "Test", "Test", "2026-01-01T00:00:00Z")
	err := tracker.CreateIncident("INC-001", keeper.IncidentSev2, "Test2", "Test2", "2026-01-01T00:00:00Z")
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}

func TestIncidentTracker_UpdateStatus(t *testing.T) {
	tracker := keeper.NewIncidentTracker()
	_ = tracker.CreateIncident("INC-001", keeper.IncidentSev1, "Test", "Test", "2026-01-01T00:00:00Z")

	err := tracker.UpdateStatus("INC-001", keeper.IncidentInvestigating,
		"investigating root cause", "ops-team", "2026-01-01T01:00:00Z")
	require.NoError(t, err)

	inc, found := tracker.GetIncident("INC-001")
	require.True(t, found)
	require.Equal(t, keeper.IncidentInvestigating, inc.Status)
	require.Len(t, inc.Timeline, 2) // created + investigating
}

func TestIncidentTracker_ResolveIncident(t *testing.T) {
	tracker := keeper.NewIncidentTracker()
	_ = tracker.CreateIncident("INC-001", keeper.IncidentSev1, "Test", "Test", "2026-01-01T00:00:00Z")

	err := tracker.UpdateStatus("INC-001", keeper.IncidentResolved,
		"root cause fixed", "ops-team", "2026-01-01T02:00:00Z")
	require.NoError(t, err)

	open := tracker.OpenIncidents()
	require.Empty(t, open, "resolved incident should not be in open list")
}

func TestIncidentTracker_OpenIncidents(t *testing.T) {
	tracker := keeper.NewIncidentTracker()
	_ = tracker.CreateIncident("INC-001", keeper.IncidentSev1, "Open", "Open", "2026-01-01T00:00:00Z")
	_ = tracker.CreateIncident("INC-002", keeper.IncidentSev2, "Also Open", "Open", "2026-01-01T00:00:00Z")
	_ = tracker.CreateIncident("INC-003", keeper.IncidentSev3, "Resolved", "Resolved", "2026-01-01T00:00:00Z")
	_ = tracker.UpdateStatus("INC-003", keeper.IncidentResolved, "done", "ops", "2026-01-01T01:00:00Z")

	open := tracker.OpenIncidents()
	require.Len(t, open, 2)
}

func TestAutoDetectIncidents(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Create a health report with anomalies
	// Add low-reputation validators to trigger anomaly
	for i := 0; i < 3; i++ {
		addr := fmt.Sprintf("val-%d", i)
		stats := types.ValidatorStats{
			ValidatorAddress: addr,
			ReputationScore:  20,
		}
		require.NoError(t, k.ValidatorStats.Set(ctx, addr, stats))
	}

	report := keeper.RunChainHealthCheck(ctx, k)
	tracker := keeper.NewIncidentTracker()

	created := keeper.AutoDetectIncidents(report, tracker)
	require.Greater(t, created, 0, "should create incidents from anomalies")
	require.Equal(t, created, len(tracker.Incidents))
}

// =============================================================================
// Section 3: Governance Activation
// =============================================================================

func TestGovernanceConfig_Default(t *testing.T) {
	config := keeper.DefaultGovernanceConfig()

	require.Equal(t, keeper.GovPhaseBootstrap, config.Phase)
	require.Greater(t, config.VotingPeriodBlocks, int64(0))
	require.NoError(t, keeper.ValidateGovernanceConfig(config))
}

func TestGovernanceConfig_Active(t *testing.T) {
	config := keeper.ActiveGovernanceConfig()

	require.Equal(t, keeper.GovPhaseActive, config.Phase)
	require.Greater(t, config.VotingPeriodBlocks, keeper.DefaultGovernanceConfig().VotingPeriodBlocks)
	require.NoError(t, keeper.ValidateGovernanceConfig(config))
}

func TestGovernanceConfig_Validation(t *testing.T) {
	// Invalid voting period
	config := keeper.DefaultGovernanceConfig()
	config.VotingPeriodBlocks = 10
	require.Error(t, keeper.ValidateGovernanceConfig(config))

	// Invalid quorum
	config = keeper.DefaultGovernanceConfig()
	config.QuorumPercent = 5
	require.Error(t, keeper.ValidateGovernanceConfig(config))

	// Invalid threshold
	config = keeper.DefaultGovernanceConfig()
	config.ThresholdPercent = 30
	require.Error(t, keeper.ValidateGovernanceConfig(config))
}

func TestGovernanceReadiness_EarlyChain(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Block height 100 is way below MinBlocksForGovernance
	readiness := keeper.EvaluateGovernanceReadiness(ctx, k)

	require.NotNil(t, readiness)
	require.False(t, readiness.ReadyForActive,
		"early chain should not be ready for full governance")
	require.GreaterOrEqual(t, len(readiness.Criteria), 5,
		"must have at least 5 governance criteria")
}

func TestGovernanceReadiness_CriteriaHaveFields(t *testing.T) {
	k, ctx := newTestKeeper(t)

	readiness := keeper.EvaluateGovernanceReadiness(ctx, k)

	for _, c := range readiness.Criteria {
		require.NotEmpty(t, c.ID, "criterion must have ID")
		require.NotEmpty(t, c.Description, "criterion %s must have description", c.ID)
	}
}

func TestGovernanceReadiness_CorruptedStateFails(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Corrupt params
	params, _ := k.GetParams(ctx)
	params.ConsensusThreshold = 40
	_ = k.Params.Set(ctx, *params)

	readiness := keeper.EvaluateGovernanceReadiness(ctx, k)

	require.False(t, readiness.ReadyForActive,
		"corrupted state should not be ready for governance")
}

// =============================================================================
// Section 4: Chain Maturity Assessment
// =============================================================================

func TestMaturityAssessment_CleanState(t *testing.T) {
	k, ctx := newTestKeeper(t)

	assessment := keeper.AssessChainMaturity(ctx, k)

	require.NotNil(t, assessment)
	require.Equal(t, "aethelred-test-1", assessment.ChainID)
	require.Equal(t, keeper.MaturityLaunch, assessment.Level,
		"block height 100 should be launch phase")
}

func TestMaturityAssessment_ScoresBounded(t *testing.T) {
	k, ctx := newTestKeeper(t)

	assessment := keeper.AssessChainMaturity(ctx, k)

	for _, score := range []int{
		assessment.StabilityScore,
		assessment.DecentralizationScore,
		assessment.ActivityScore,
		assessment.OverallMaturity,
	} {
		require.GreaterOrEqual(t, score, 0, "scores must be >= 0")
		require.LessOrEqual(t, score, 100, "scores must be <= 100")
	}
}

func TestMaturityAssessment_StabilityScorePositive(t *testing.T) {
	k, ctx := newTestKeeper(t)

	assessment := keeper.AssessChainMaturity(ctx, k)

	// Clean state should have decent stability (invariants pass + params valid)
	require.GreaterOrEqual(t, assessment.StabilityScore, 70,
		"clean state should have stability score >= 70")
}

func TestMaturityAssessment_HasGraduationCriteria(t *testing.T) {
	k, ctx := newTestKeeper(t)

	assessment := keeper.AssessChainMaturity(ctx, k)

	require.NotEmpty(t, assessment.GraduationCriteria)
	require.GreaterOrEqual(t, len(assessment.GraduationCriteria), 5,
		"must have at least 5 graduation criteria")
}

func TestMaturityAssessment_NotGraduatedEarly(t *testing.T) {
	k, ctx := newTestKeeper(t)

	assessment := keeper.AssessChainMaturity(ctx, k)

	// Block 100 is way too early to graduate
	require.False(t, assessment.AllGraduationCriteriaPassed(),
		"chain should not graduate at block 100")
}

func TestMaturityAssessment_LockedParams(t *testing.T) {
	k, ctx := newTestKeeper(t)

	assessment := keeper.AssessChainMaturity(ctx, k)

	require.Greater(t, assessment.LockedParams, 0,
		"should have locked parameters")
	require.Greater(t, assessment.MutableParams, 0,
		"should have mutable parameters")
}

// =============================================================================
// Section 5: Report Rendering
// =============================================================================

func TestRenderChainHealthReport(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Seed minimum validators for a green health status
	for i := 0; i < 3; i++ {
		addr := fmt.Sprintf("health-val-%d", i)
		stats := types.ValidatorStats{
			ValidatorAddress: addr,
			ReputationScore:  70,
		}
		require.NoError(t, k.ValidatorStats.Set(ctx, addr, stats))
	}

	report := keeper.RunChainHealthCheck(ctx, k)
	rendered := keeper.RenderChainHealthReport(report)

	require.Contains(t, rendered, "CHAIN HEALTH MONITOR")
	require.Contains(t, rendered, "SUBSYSTEMS")
	require.Contains(t, rendered, "METRICS")
	require.Contains(t, rendered, "GREEN")

	t.Log(rendered)
}

func TestRenderMaturityAssessment(t *testing.T) {
	k, ctx := newTestKeeper(t)

	assessment := keeper.AssessChainMaturity(ctx, k)
	rendered := keeper.RenderMaturityAssessment(assessment)

	require.Contains(t, rendered, "CHAIN MATURITY ASSESSMENT")
	require.Contains(t, rendered, "SCORES")
	require.Contains(t, rendered, "GRADUATION CRITERIA")
	require.Contains(t, rendered, "GOVERNANCE")

	t.Log(rendered)
}

func TestRenderPostLaunchSummary(t *testing.T) {
	k, ctx := newTestKeeper(t)

	summary := keeper.RunPostLaunchSummary(ctx, k)
	rendered := keeper.RenderPostLaunchSummary(summary)

	require.Contains(t, rendered, "POST-LAUNCH STATUS SUMMARY")
	require.Contains(t, rendered, "KEY METRICS")

	t.Log(rendered)
}

func TestRenderChainHealthReport_WithAnomalies(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Add low-reputation validators
	for i := 0; i < 3; i++ {
		addr := fmt.Sprintf("val-%d", i)
		stats := types.ValidatorStats{
			ValidatorAddress: addr,
			ReputationScore:  20,
		}
		require.NoError(t, k.ValidatorStats.Set(ctx, addr, stats))
	}

	report := keeper.RunChainHealthCheck(ctx, k)
	rendered := keeper.RenderChainHealthReport(report)

	require.Contains(t, rendered, "ANOMALIES")
	t.Log(rendered)
}

// =============================================================================
// Section 6: Integration - Full Post-Launch Flow
// =============================================================================

func TestFullPostLaunchFlow(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Setup: Bootstrap some validators
	for i := 0; i < 5; i++ {
		addr := fmt.Sprintf("val-%d", i)
		stats := types.ValidatorStats{
			ValidatorAddress:   addr,
			ReputationScore:    80,
			TotalJobsProcessed: 100,
			SuccessfulJobs:     95,
			FailedJobs:         5,
		}
		require.NoError(t, k.ValidatorStats.Set(ctx, addr, stats))
	}

	// Week 46-48: Health monitoring
	health := keeper.RunChainHealthCheck(ctx, k)
	require.True(t, health.IsHealthy(), "chain should be healthy")

	// Incident tracking
	tracker := keeper.NewIncidentTracker()
	created := keeper.AutoDetectIncidents(health, tracker)
	require.Equal(t, 0, created, "no incidents from healthy state")

	// Week 49-52: Governance readiness
	governance := keeper.EvaluateGovernanceReadiness(ctx, k)
	require.NotNil(t, governance)
	// Block 100 is too early for full governance
	require.False(t, governance.ReadyForActive)

	// Chain maturity
	maturity := keeper.AssessChainMaturity(ctx, k)
	require.Equal(t, keeper.MaturityLaunch, maturity.Level)
	require.Greater(t, maturity.StabilityScore, 0)
	require.Greater(t, maturity.DecentralizationScore, 0)

	// Full summary
	summary := keeper.RunPostLaunchSummary(ctx, k)
	require.NotNil(t, summary)
	require.NotNil(t, summary.Health)
	require.NotNil(t, summary.Maturity)
	require.NotNil(t, summary.Governance)

	// Render all reports
	healthReport := keeper.RenderChainHealthReport(summary.Health)
	maturityReport := keeper.RenderMaturityAssessment(summary.Maturity)
	summaryReport := keeper.RenderPostLaunchSummary(summary)

	require.NotEmpty(t, healthReport)
	require.NotEmpty(t, maturityReport)
	require.NotEmpty(t, summaryReport)

	t.Logf("Health: %s", health.OverallStatus)
	t.Logf("Maturity: %s (score: %d/100)", maturity.Level, maturity.OverallMaturity)
	t.Logf("Governance: %s, ready=%v", governance.CurrentPhase, governance.ReadyForActive)
}

func TestGetMonitoringSummaryByValidators(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Add validators with different reputations
	reps := []int64{90, 50, 80, 30, 70}
	for i, rep := range reps {
		addr := fmt.Sprintf("val-%d", i)
		stats := types.ValidatorStats{
			ValidatorAddress: addr,
			ReputationScore:  rep,
		}
		require.NoError(t, k.ValidatorStats.Set(ctx, addr, stats))
	}

	validators := keeper.GetMonitoringSummaryByValidators(ctx, k)
	require.Len(t, validators, 5)

	// Should be sorted by reputation descending
	for i := 1; i < len(validators); i++ {
		require.GreaterOrEqual(t, validators[i-1].ReputationScore, validators[i].ReputationScore,
			"validators should be sorted by reputation descending")
	}
}
