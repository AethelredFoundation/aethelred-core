package keeper_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// =============================================================================
// WEEK 38-39: Upgrade Rehearsal & Rollback Drills Tests
//
// These tests verify:
//   1. Upgrade rehearsal simulation (5 tests)
//   2. State snapshot capture and comparison (5 tests)
//   3. Upgrade checklist validation (6 tests)
//   4. Rollback drill simulation (5 tests)
//   5. Rehearsal report rendering (3 tests)
//
// Total: 24 tests
// =============================================================================

// =============================================================================
// Section 1: Upgrade Rehearsal
// =============================================================================

func TestUpgradeRehearsal_CleanState(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunUpgradeRehearsal(ctx, k)

	require.NotNil(t, result)
	require.Equal(t, uint64(keeper.ModuleConsensusVersion), result.FromVersion)
	require.Equal(t, uint64(keeper.ModuleConsensusVersion+1), result.ToVersion)
	require.True(t, result.MigrationSimulated)
	require.True(t, result.RehearsalPass, "clean state rehearsal should pass")
}

func TestUpgradeRehearsal_HasMigrationSteps(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunUpgradeRehearsal(ctx, k)

	require.NotEmpty(t, result.MigrationSteps, "must have migration steps")
	require.GreaterOrEqual(t, len(result.MigrationSteps), 5,
		"must have at least 5 migration steps")

	// All steps should have names and durations
	for _, step := range result.MigrationSteps {
		require.NotEmpty(t, step.Name, "step must have name")
	}
}

func TestUpgradeRehearsal_PreUpgradeClean(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunUpgradeRehearsal(ctx, k)

	// Clean state should have no pre-upgrade warnings
	require.True(t, result.PreUpgradePass)
	require.Empty(t, result.PreUpgradeWarnings)
}

func TestUpgradeRehearsal_PostUpgradePass(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunUpgradeRehearsal(ctx, k)

	require.True(t, result.PostUpgradePass)
	require.Empty(t, result.PostUpgradeError)
}

func TestUpgradeRehearsal_DurationReasonable(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunUpgradeRehearsal(ctx, k)

	// Full rehearsal should complete in under 1 second for clean state
	require.Less(t, result.MigrationDuration, 1*time.Second,
		"rehearsal should complete quickly in clean state")
}

// =============================================================================
// Section 2: State Snapshot
// =============================================================================

func TestStateSnapshot_Capture(t *testing.T) {
	k, ctx := newTestKeeper(t)

	snap := keeper.CaptureStateSnapshot(ctx, k)

	require.Equal(t, ctx.BlockHeight(), snap.BlockHeight)
	require.NotEmpty(t, snap.Timestamp)
	require.NotEmpty(t, snap.ParamsHash)
	require.True(t, snap.InvariantsPass)
}

func TestStateSnapshot_CaptureWithJobs(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 5)

	snap := keeper.CaptureStateSnapshot(ctx, k)

	require.Equal(t, uint64(5), snap.TotalJobs)
	require.Equal(t, 5, snap.PendingJobCount)
}

func TestStateSnapshot_CompareIdentical(t *testing.T) {
	k, ctx := newTestKeeper(t)

	snap1 := keeper.CaptureStateSnapshot(ctx, k)
	snap2 := keeper.CaptureStateSnapshot(ctx, k)

	diff := keeper.CompareSnapshots(snap1, snap2)

	require.False(t, diff.HasChanges, "identical snapshots should have no changes")
	require.Equal(t, int64(0), diff.JobsDelta)
	require.Equal(t, 0, diff.PendingDelta)
	require.Equal(t, 0, diff.ValidatorDelta)
	require.Equal(t, "stable", diff.InvariantStatus)
}

func TestStateSnapshot_CompareWithChanges(t *testing.T) {
	k, ctx := newTestKeeper(t)

	snap1 := keeper.CaptureStateSnapshot(ctx, k)

	// Add some jobs
	seedJobs(t, ctx, k, 3)

	snap2 := keeper.CaptureStateSnapshot(ctx, k)

	diff := keeper.CompareSnapshots(snap1, snap2)

	require.True(t, diff.HasChanges)
	require.Equal(t, int64(3), diff.JobsDelta)
	require.Equal(t, 3, diff.PendingDelta)
}

func TestStateSnapshot_InvariantStatus(t *testing.T) {
	// Test invariant status labels
	passSnap := keeper.StateSnapshot{InvariantsPass: true}
	failSnap := keeper.StateSnapshot{InvariantsPass: false}

	// stable: pass → pass
	diff := keeper.CompareSnapshots(passSnap, passSnap)
	require.Equal(t, "stable", diff.InvariantStatus)

	// improved: fail → pass
	diff = keeper.CompareSnapshots(failSnap, passSnap)
	require.Equal(t, "improved", diff.InvariantStatus)

	// degraded: pass → fail
	diff = keeper.CompareSnapshots(passSnap, failSnap)
	require.Equal(t, "degraded", diff.InvariantStatus)

	// broken: fail → fail
	diff = keeper.CompareSnapshots(failSnap, failSnap)
	require.Equal(t, "broken", diff.InvariantStatus)
}

// =============================================================================
// Section 3: Upgrade Checklist
// =============================================================================

func TestUpgradeChecklist_CleanState(t *testing.T) {
	k, ctx := newTestKeeper(t)

	items := keeper.RunUpgradeChecklist(ctx, k)

	require.NotEmpty(t, items)
	require.GreaterOrEqual(t, len(items), 10,
		"must have at least 10 checklist items")
}

func TestUpgradeChecklist_AllBlockingPass(t *testing.T) {
	k, ctx := newTestKeeper(t)

	items := keeper.RunUpgradeChecklist(ctx, k)

	require.True(t, keeper.ChecklistPassesBlocking(items),
		"all blocking checks should pass in clean state")
}

func TestUpgradeChecklist_NoBlockingFailures(t *testing.T) {
	k, ctx := newTestKeeper(t)

	items := keeper.RunUpgradeChecklist(ctx, k)
	failures := keeper.BlockingFailuresFromChecklist(items)

	require.Empty(t, failures, "should have no blocking failures in clean state")
}

func TestUpgradeChecklist_AllHaveRequiredFields(t *testing.T) {
	k, ctx := newTestKeeper(t)

	items := keeper.RunUpgradeChecklist(ctx, k)

	for _, item := range items {
		require.NotEmpty(t, item.ID, "checklist item must have ID")
		require.NotEmpty(t, item.Category, "checklist item %s must have category", item.ID)
		require.NotEmpty(t, item.Description, "checklist item %s must have description", item.ID)
	}
}

func TestUpgradeChecklist_CoversCriticalAreas(t *testing.T) {
	k, ctx := newTestKeeper(t)

	items := keeper.RunUpgradeChecklist(ctx, k)

	categories := make(map[string]bool)
	for _, item := range items {
		categories[item.Category] = true
	}

	require.True(t, categories["state"], "must check state")
	require.True(t, categories["params"], "must check params")
	require.True(t, categories["security"], "must check security")
	require.True(t, categories["consensus"], "must check consensus")
	require.True(t, categories["economics"], "must check economics")
}

func TestUpgradeChecklist_UC01_Invariants(t *testing.T) {
	k, ctx := newTestKeeper(t)

	items := keeper.RunUpgradeChecklist(ctx, k)

	for _, item := range items {
		if item.ID == "UC-01" {
			require.True(t, item.Passed, "UC-01 (invariants) should pass in clean state")
			require.True(t, item.Blocking, "UC-01 should be blocking")
			return
		}
	}
	t.Fatal("UC-01 check not found")
}

// =============================================================================
// Section 4: Rollback Drill
// =============================================================================

func TestRollbackDrill_Passes(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunRollbackDrill(ctx, k)

	require.NotNil(t, result)
	require.True(t, result.DrillPass, "rollback drill should pass in clean state")
	require.Empty(t, result.FailureReasons)
}

func TestRollbackDrill_DetectsCorruption(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunRollbackDrill(ctx, k)

	require.True(t, result.InvariantsBroken,
		"corruption should be detected by validation")
	require.NotEmpty(t, result.CorruptionApplied)
}

func TestRollbackDrill_RecoverySucceeds(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunRollbackDrill(ctx, k)

	require.True(t, result.RecoveryAttempted)
	require.True(t, result.RecoverySuccess)
	require.True(t, result.PostRecoveryParamsValid)
	require.True(t, result.PostRecoveryInvariantsPass)
}

func TestRollbackDrill_SnapshotCaptured(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunRollbackDrill(ctx, k)

	require.True(t, result.SnapshotCaptured)
	require.Less(t, result.SnapshotDuration, 100*time.Millisecond,
		"snapshot should be fast")
}

func TestRollbackDrill_RecoveryTimingAcceptable(t *testing.T) {
	k, ctx := newTestKeeper(t)

	result := keeper.RunRollbackDrill(ctx, k)

	require.Less(t, result.RecoveryDuration, 50*time.Millisecond,
		"recovery should be very fast for param restore")
}

// =============================================================================
// Section 5: Rehearsal Report Rendering
// =============================================================================

func TestRehearsalReport_Render(t *testing.T) {
	k, ctx := newTestKeeper(t)
	result := keeper.RunUpgradeRehearsal(ctx, k)

	rendered := keeper.RenderRehearsalReport(result)

	require.Contains(t, rendered, "UPGRADE REHEARSAL REPORT")
	require.Contains(t, rendered, "MIGRATION STEPS")
	require.Contains(t, rendered, "STATE DIFF")
	require.Contains(t, rendered, "DETERMINATION")

	t.Log(rendered)
}

func TestRehearsalReport_ShowsPass(t *testing.T) {
	k, ctx := newTestKeeper(t)
	result := keeper.RunUpgradeRehearsal(ctx, k)

	rendered := keeper.RenderRehearsalReport(result)

	require.Contains(t, rendered, "REHEARSAL PASSED")
}

func TestRehearsalReport_ContainsChainInfo(t *testing.T) {
	k, ctx := newTestKeeper(t)
	result := keeper.RunUpgradeRehearsal(ctx, k)

	rendered := keeper.RenderRehearsalReport(result)

	require.Contains(t, rendered, "aethelred-test-1")
	require.Contains(t, rendered, fmt.Sprintf("v%d", keeper.ModuleConsensusVersion))
}
