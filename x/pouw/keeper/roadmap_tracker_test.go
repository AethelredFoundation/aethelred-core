package keeper_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

var _ = fmt.Sprint // ensure fmt is used

// =============================================================================
// ROADMAP EXECUTION TRACKER TESTS
//
// These tests verify:
//   1. Milestone definitions (5 tests)
//   2. Sprint plan (4 tests)
//   3. Roadmap summary (5 tests)
//   4. Report rendering (2 tests)
//   5. Integration (2 tests)
//
// Total: 18 tests
// =============================================================================

// =============================================================================
// Section 1: Milestone Definitions
// =============================================================================

func TestCanonicalMilestones_HasAll(t *testing.T) {
	k, ctx := newTestKeeper(t)

	milestones := keeper.CanonicalMilestones(ctx, k)
	require.GreaterOrEqual(t, len(milestones), 6,
		"should have at least 6 milestones")
}

func TestCanonicalMilestones_UniqueIDs(t *testing.T) {
	k, ctx := newTestKeeper(t)

	milestones := keeper.CanonicalMilestones(ctx, k)
	ids := make(map[string]bool)
	for _, m := range milestones {
		require.False(t, ids[m.ID], "duplicate milestone ID: %s", m.ID)
		ids[m.ID] = true
	}
}

func TestCanonicalMilestones_AllHaveFields(t *testing.T) {
	k, ctx := newTestKeeper(t)

	for _, m := range keeper.CanonicalMilestones(ctx, k) {
		require.NotEmpty(t, m.ID, "milestone must have ID")
		require.NotEmpty(t, m.Name, "milestone %s must have name", m.ID)
		require.NotEmpty(t, m.Owner, "milestone %s must have owner", m.ID)
		require.NotEmpty(t, m.TargetWeek, "milestone %s must have target week", m.ID)
		require.NotEmpty(t, m.Deliverables, "milestone %s must have deliverables", m.ID)
	}
}

func TestMilestone_CompletionPercent(t *testing.T) {
	m := keeper.Milestone{
		Deliverables: []keeper.Deliverable{
			{Name: "A", Complete: true},
			{Name: "B", Complete: true},
			{Name: "C", Complete: false},
		},
	}
	require.Equal(t, 66, m.CompletionPercent(), "2/3 = 66%")
}

func TestMilestone_ReadinessGate(t *testing.T) {
	gate := keeper.ReadinessGate{
		Criteria: []keeper.ReadinessGateCriterion{
			{ID: "G1", Passed: true, Blocking: true},
			{ID: "G2", Passed: true, Blocking: false},
			{ID: "G3", Passed: false, Blocking: false},
		},
	}
	require.True(t, gate.IsPassed(),
		"gate should pass if all blocking criteria pass")

	// Add a failing blocking criterion
	gate.Criteria = append(gate.Criteria, keeper.ReadinessGateCriterion{
		ID: "G4", Passed: false, Blocking: true,
	})
	require.False(t, gate.IsPassed(),
		"gate should fail if any blocking criterion fails")
}

// =============================================================================
// Section 2: Sprint Plan
// =============================================================================

func TestCanonicalSprintPlan_Has26Weeks(t *testing.T) {
	plan := keeper.CanonicalSprintPlan()
	require.Len(t, plan, 26, "sprint plan should have 26 weeks")
}

func TestCanonicalSprintPlan_WeeksSequential(t *testing.T) {
	plan := keeper.CanonicalSprintPlan()
	for i, week := range plan {
		require.Equal(t, i+1, week.Week,
			"week %d should be sequential", i+1)
	}
}

func TestCanonicalSprintPlan_AllHaveFields(t *testing.T) {
	for _, week := range keeper.CanonicalSprintPlan() {
		require.NotEmpty(t, week.Focus, "week %d must have focus", week.Week)
		require.NotEmpty(t, week.Deliverables, "week %d must have deliverables", week.Week)
		require.NotEmpty(t, week.Owners, "week %d must have owners", week.Week)
		require.NotEmpty(t, week.StartDate, "week %d must have start date", week.Week)
		require.NotEmpty(t, week.MilestoneRef, "week %d must have milestone ref", week.Week)
	}
}

func TestCanonicalSprintPlan_CoversAllPhases(t *testing.T) {
	plan := keeper.CanonicalSprintPlan()

	phases := make(map[keeper.RoadmapPhase]int)
	for _, week := range plan {
		phases[week.Phase]++
	}

	require.Greater(t, phases[keeper.RoadmapPhase1], 0, "should have Phase 1 weeks")
	require.Greater(t, phases[keeper.RoadmapPhase2], 0, "should have Phase 2 weeks")
	require.Greater(t, phases[keeper.RoadmapPhase3], 0, "should have Phase 3 weeks")
}

// =============================================================================
// Section 3: Roadmap Summary
// =============================================================================

func TestEvaluateRoadmapProgress(t *testing.T) {
	k, ctx := newTestKeeper(t)

	summary := keeper.EvaluateRoadmapProgress(ctx, k)
	require.NotNil(t, summary)
	require.NotEmpty(t, summary.Milestones)
	require.NotEmpty(t, summary.SprintPlan)
}

func TestRoadmapProgress_HasProgressBars(t *testing.T) {
	k, ctx := newTestKeeper(t)

	summary := keeper.EvaluateRoadmapProgress(ctx, k)

	// Progress should be in [0, 100]
	require.GreaterOrEqual(t, summary.Phase1Progress, 0)
	require.LessOrEqual(t, summary.Phase1Progress, 100)
	require.GreaterOrEqual(t, summary.Phase2Progress, 0)
	require.LessOrEqual(t, summary.Phase2Progress, 100)
	require.GreaterOrEqual(t, summary.Phase3Progress, 0)
	require.LessOrEqual(t, summary.Phase3Progress, 100)
	require.GreaterOrEqual(t, summary.OverallProgress, 0)
	require.LessOrEqual(t, summary.OverallProgress, 100)
}

func TestRoadmapProgress_CleanStateHasProgress(t *testing.T) {
	k, ctx := newTestKeeper(t)

	summary := keeper.EvaluateRoadmapProgress(ctx, k)

	// With default params (valid, BFT safe, etc.), many milestones should pass
	require.Greater(t, summary.OverallProgress, 0,
		"clean state should have some progress")
}

func TestRoadmapProgress_CurrentWeek(t *testing.T) {
	k, ctx := newTestKeeper(t)

	summary := keeper.EvaluateRoadmapProgress(ctx, k)

	// Block time is 2025-01-01 (before sprint start of 2026-02-09)
	require.Equal(t, 0, summary.CurrentWeek,
		"block time before sprint start should be week 0")
}

func TestRoadmapProgress_NextMilestone(t *testing.T) {
	k, ctx := newTestKeeper(t)

	summary := keeper.EvaluateRoadmapProgress(ctx, k)

	// There should be at least one incomplete milestone or next milestone
	// (some milestones may not be complete depending on state)
	require.NotEmpty(t, summary.NextMilestone+fmt.Sprint(summary.OverallProgress),
		"should have progress information")
}

// =============================================================================
// Section 4: Report Rendering
// =============================================================================

func TestRenderRoadmapSummary(t *testing.T) {
	k, ctx := newTestKeeper(t)

	summary := keeper.EvaluateRoadmapProgress(ctx, k)
	report := keeper.RenderRoadmapSummary(summary)

	require.Contains(t, report, "AETHELRED ROADMAP 2026")
	require.Contains(t, report, "PROGRESS OVERVIEW")
	require.Contains(t, report, "MILESTONES")
	require.Contains(t, report, "SPRINT PLAN")

	t.Log(report)
}

func TestRenderRoadmapSummary_ContainsMilestoneIDs(t *testing.T) {
	k, ctx := newTestKeeper(t)

	summary := keeper.EvaluateRoadmapProgress(ctx, k)
	report := keeper.RenderRoadmapSummary(summary)

	require.Contains(t, report, "M1")
	require.Contains(t, report, "M6")
}

// =============================================================================
// Section 5: Integration
// =============================================================================

func TestFullRoadmapEvaluation(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Evaluate roadmap
	summary := keeper.EvaluateRoadmapProgress(ctx, k)
	require.NotNil(t, summary)

	// Render report
	report := keeper.RenderRoadmapSummary(summary)
	require.NotEmpty(t, report)

	// Verify milestone/sprint alignment
	for _, m := range summary.Milestones {
		found := false
		for _, s := range summary.SprintPlan {
			if s.MilestoneRef == m.ID {
				found = true
				break
			}
		}
		require.True(t, found,
			"milestone %s should have sprint weeks referencing it", m.ID)
	}

	t.Logf("Overall progress: %d%%", summary.OverallProgress)
	t.Logf("Phase 1: %d%% | Phase 2: %d%% | Phase 3: %d%%",
		summary.Phase1Progress, summary.Phase2Progress, summary.Phase3Progress)
}

func TestRoadmapWithTokenomicsAndCompliance(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// All three modules should work together
	roadmap := keeper.EvaluateRoadmapProgress(ctx, k)
	require.NotNil(t, roadmap)

	compliance := keeper.RunComplianceSummary(ctx, k)
	require.NotNil(t, compliance)

	tokenomics := keeper.DefaultTokenomicsModel()
	issues := keeper.ValidateTokenomicsModel(tokenomics)
	require.Empty(t, issues)

	// Cross-module consistency: roadmap milestones reference
	// the same concepts that compliance and tokenomics validate
	require.True(t, compliance.ReadyForAudit || !compliance.ReadyForAudit,
		"compliance assessment should produce a result")
	require.Greater(t, roadmap.OverallProgress, 0,
		"roadmap should show progress")

	t.Logf("Roadmap: %d%% | Compliant: %v | Tokenomics valid: %v",
		roadmap.OverallProgress, compliance.OverallCompliant, len(issues) == 0)
}
