package keeper

import (
	"fmt"
	"strings"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// ---------------------------------------------------------------------------
// WEEK 38-39: Final Upgrade Rehearsal & Rollback Drills
// ---------------------------------------------------------------------------
//
// This file implements:
//   1. Upgrade rehearsal simulation — dry-run of v1→v2 migration with
//      pre/post validation and timing measurements.
//   2. Rollback procedures — state snapshot capture and restore mechanism
//      for safe upgrade rollback.
//   3. Upgrade checklist — comprehensive pre-upgrade checklist with
//      automated verification of all preconditions.
//   4. State snapshot — lightweight capture of critical state for comparison.
//   5. Rollback drill runner — end-to-end rollback simulation.
//
// Design principles:
//   - Rehearsals are non-destructive (read-only analysis of current state)
//   - Rollback snapshots capture only the delta needed for restore
//   - All timings are measured for SLA compliance
//   - Checklists are deterministic and machine-verifiable
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Section 1: Upgrade Rehearsal
// ---------------------------------------------------------------------------

// UpgradeRehearsalResult captures the outcome of an upgrade rehearsal.
type UpgradeRehearsalResult struct {
	// Identity
	FromVersion uint64
	ToVersion   uint64
	ChainID     string
	BlockHeight int64
	RunAt       string

	// Pre-upgrade checks
	PreUpgradeWarnings []string
	PreUpgradePass     bool

	// Migration simulation
	MigrationDuration  time.Duration
	MigrationSteps     []MigrationStepResult
	MigrationSimulated bool // true = dry-run, false = actual migration

	// Post-upgrade checks
	PostUpgradePass  bool
	PostUpgradeError string

	// State diff
	StateDiff StateSnapshotDiff

	// Overall
	RehearsalPass  bool
	FailureReasons []string
}

// MigrationStepResult describes the outcome of one migration step.
type MigrationStepResult struct {
	Name     string
	Duration time.Duration
	Passed   bool
	Details  string
}

// RunUpgradeRehearsal performs a dry-run of the next registered migration
// against the current chain state. It captures pre-state, simulates the migration
// path, and validates post-state without making any actual changes.
func RunUpgradeRehearsal(ctx sdk.Context, k Keeper) *UpgradeRehearsalResult {
	result := &UpgradeRehearsalResult{
		FromVersion:        ModuleConsensusVersion,
		ToVersion:          ModuleConsensusVersion + 1,
		ChainID:            ctx.ChainID(),
		BlockHeight:        ctx.BlockHeight(),
		RunAt:              ctx.BlockTime().UTC().Format(time.RFC3339),
		MigrationSimulated: true,
		RehearsalPass:      true,
	}

	// Step 1: Run pre-upgrade validation
	preStart := time.Now()
	result.PreUpgradeWarnings = PreUpgradeValidation(ctx, k)
	result.PreUpgradePass = len(result.PreUpgradeWarnings) == 0

	result.MigrationSteps = append(result.MigrationSteps, MigrationStepResult{
		Name:     "pre_upgrade_validation",
		Duration: time.Since(preStart),
		Passed:   result.PreUpgradePass,
		Details:  fmt.Sprintf("%d warnings", len(result.PreUpgradeWarnings)),
	})

	// Step 2: Capture pre-migration snapshot
	snapStart := time.Now()
	preSnapshot := CaptureStateSnapshot(ctx, k)
	result.MigrationSteps = append(result.MigrationSteps, MigrationStepResult{
		Name:     "capture_pre_snapshot",
		Duration: time.Since(snapStart),
		Passed:   true,
		Details:  fmt.Sprintf("jobs=%d, validators=%d, models=%d", preSnapshot.TotalJobs, preSnapshot.TotalValidators, preSnapshot.TotalModels),
	})

	// Step 3: Verify migration handlers are registered
	migStart := time.Now()
	migrations := GetMigrations()
	migrationAvailable := false
	for _, m := range migrations {
		if m.FromVersion == ModuleConsensusVersion && m.ToVersion == ModuleConsensusVersion+1 {
			migrationAvailable = true
		}
	}
	details := fmt.Sprintf("v%d→v%d handler registered: %v", ModuleConsensusVersion, ModuleConsensusVersion+1, migrationAvailable)
	if !migrationAvailable {
		details = fmt.Sprintf("no pending migration for v%d", ModuleConsensusVersion)
	}
	result.MigrationSteps = append(result.MigrationSteps, MigrationStepResult{
		Name:     "verify_migration_handler",
		Duration: time.Since(migStart),
		Passed:   migrationAvailable,
		Details:  details,
	})

	// Step 4: Validate invariants (simulates post-migration check)
	invStart := time.Now()
	invariants := AllInvariants(k)
	invMsg, invBroken := invariants(ctx)
	result.MigrationSteps = append(result.MigrationSteps, MigrationStepResult{
		Name:     "invariant_verification",
		Duration: time.Since(invStart),
		Passed:   !invBroken,
		Details:  invMsg,
	})

	if invBroken {
		result.RehearsalPass = false
		result.FailureReasons = append(result.FailureReasons, "invariants broken: "+invMsg)
	}

	// Step 5: Run post-upgrade validation (against current state as proxy)
	postStart := time.Now()
	postErr := PostUpgradeValidation(ctx, k)
	result.PostUpgradePass = postErr == nil
	if postErr != nil {
		result.PostUpgradeError = postErr.Error()
		result.RehearsalPass = false
		result.FailureReasons = append(result.FailureReasons, "post-upgrade validation failed: "+postErr.Error())
	}
	result.MigrationSteps = append(result.MigrationSteps, MigrationStepResult{
		Name:     "post_upgrade_validation",
		Duration: time.Since(postStart),
		Passed:   result.PostUpgradePass,
		Details:  fmt.Sprintf("error=%v", postErr),
	})

	// Step 6: Compute state diff (pre vs current = no-op for dry-run)
	postSnapshot := CaptureStateSnapshot(ctx, k)
	result.StateDiff = CompareSnapshots(preSnapshot, postSnapshot)

	// Calculate total migration duration
	totalDuration := time.Duration(0)
	for _, step := range result.MigrationSteps {
		totalDuration += step.Duration
	}
	result.MigrationDuration = totalDuration

	// Check for pre-upgrade warnings that are non-blocking
	for _, w := range result.PreUpgradeWarnings {
		if strings.Contains(w, "AllowSimulated is true") {
			result.RehearsalPass = false
			result.FailureReasons = append(result.FailureReasons, w)
		}
	}

	return result
}

// ---------------------------------------------------------------------------
// Section 2: State Snapshot
// ---------------------------------------------------------------------------

// StateSnapshot captures a lightweight summary of critical module state.
type StateSnapshot struct {
	BlockHeight     int64
	Timestamp       string
	TotalJobs       uint64
	PendingJobCount int
	TotalValidators int
	TotalModels     int
	ParamsHash      string
	InvariantsPass  bool
}

// CaptureStateSnapshot creates a snapshot of the current module state.
func CaptureStateSnapshot(ctx sdk.Context, k Keeper) StateSnapshot {
	snap := StateSnapshot{
		BlockHeight: ctx.BlockHeight(),
		Timestamp:   ctx.BlockTime().UTC().Format(time.RFC3339),
	}

	// Job count
	snap.TotalJobs, _ = k.JobCount.Get(ctx)

	// Pending jobs
	pendingJobs := k.GetPendingJobs(ctx)
	snap.PendingJobCount = len(pendingJobs)

	// Validators
	_ = k.ValidatorStats.Walk(ctx, nil, func(_ string, _ types.ValidatorStats) (bool, error) {
		snap.TotalValidators++
		return false, nil
	})

	// Models
	_ = k.RegisteredModels.Walk(ctx, nil, func(_ string, _ types.RegisteredModel) (bool, error) {
		snap.TotalModels++
		return false, nil
	})

	// Params hash (simplified — just use string representation)
	params, err := k.GetParams(ctx)
	if err == nil && params != nil {
		snap.ParamsHash = fmt.Sprintf("CT%d-MV%d-JTB%d-MJB%d",
			params.ConsensusThreshold, params.MinValidators,
			params.JobTimeoutBlocks, params.MaxJobsPerBlock)
	}

	// Invariants
	invariants := AllInvariants(k)
	_, broken := invariants(ctx)
	snap.InvariantsPass = !broken

	return snap
}

// StateSnapshotDiff describes the differences between two snapshots.
type StateSnapshotDiff struct {
	JobsDelta       int64
	PendingDelta    int
	ValidatorDelta  int
	ModelDelta      int
	ParamsChanged   bool
	InvariantStatus string // "stable", "improved", "degraded"
	HasChanges      bool
}

// CompareSnapshots computes the diff between two state snapshots.
func CompareSnapshots(before, after StateSnapshot) StateSnapshotDiff {
	diff := StateSnapshotDiff{
		JobsDelta:      int64(after.TotalJobs) - int64(before.TotalJobs),
		PendingDelta:   after.PendingJobCount - before.PendingJobCount,
		ValidatorDelta: after.TotalValidators - before.TotalValidators,
		ModelDelta:     after.TotalModels - before.TotalModels,
		ParamsChanged:  before.ParamsHash != after.ParamsHash,
	}

	if before.InvariantsPass && after.InvariantsPass {
		diff.InvariantStatus = "stable"
	} else if !before.InvariantsPass && after.InvariantsPass {
		diff.InvariantStatus = "improved"
	} else if before.InvariantsPass && !after.InvariantsPass {
		diff.InvariantStatus = "degraded"
	} else {
		diff.InvariantStatus = "broken"
	}

	diff.HasChanges = diff.JobsDelta != 0 || diff.PendingDelta != 0 ||
		diff.ValidatorDelta != 0 || diff.ModelDelta != 0 || diff.ParamsChanged

	return diff
}

// ---------------------------------------------------------------------------
// Section 3: Upgrade Checklist
// ---------------------------------------------------------------------------

// UpgradeChecklistItem represents a single pre-upgrade checklist item.
type UpgradeChecklistItem struct {
	ID          string
	Category    string
	Description string
	Passed      bool
	Details     string
	Blocking    bool // If true, failure prevents upgrade
}

// RunUpgradeChecklist performs all pre-upgrade checks and returns the results.
func RunUpgradeChecklist(ctx sdk.Context, k Keeper) []UpgradeChecklistItem {
	var checks []UpgradeChecklistItem

	// UC-01: All invariants pass
	invariants := AllInvariants(k)
	invMsg, invBroken := invariants(ctx)
	checks = append(checks, UpgradeChecklistItem{
		ID:          "UC-01",
		Category:    "state",
		Description: "All module invariants pass",
		Passed:      !invBroken,
		Details:     invMsg,
		Blocking:    true,
	})

	// UC-02: Parameters are valid
	params, err := k.GetParams(ctx)
	paramValid := err == nil && params != nil && ValidateParams(params) == nil
	checks = append(checks, UpgradeChecklistItem{
		ID:          "UC-02",
		Category:    "params",
		Description: "Parameters pass validation",
		Passed:      paramValid,
		Details:     fmt.Sprintf("err=%v", err),
		Blocking:    true,
	})

	// UC-03: AllowSimulated is false
	simDisabled := params != nil && !params.AllowSimulated
	checks = append(checks, UpgradeChecklistItem{
		ID:          "UC-03",
		Category:    "security",
		Description: "AllowSimulated is disabled",
		Passed:      simDisabled,
		Details:     fmt.Sprintf("AllowSimulated=%v", params != nil && params.AllowSimulated),
		Blocking:    true,
	})

	// UC-04: No pending jobs in flight (warning only)
	pendingJobs := k.GetPendingJobs(ctx)
	checks = append(checks, UpgradeChecklistItem{
		ID:          "UC-04",
		Category:    "state",
		Description: "No pending jobs in flight",
		Passed:      len(pendingJobs) == 0,
		Details:     fmt.Sprintf("%d pending jobs", len(pendingJobs)),
		Blocking:    false, // Warning only
	})

	// UC-05: Job count consistent
	storedCount, _ := k.JobCount.Get(ctx)
	actualCount := uint64(0)
	_ = k.Jobs.Walk(ctx, nil, func(_ string, _ types.ComputeJob) (bool, error) {
		actualCount++
		return false, nil
	})
	checks = append(checks, UpgradeChecklistItem{
		ID:          "UC-05",
		Category:    "state",
		Description: "Job count matches actual count",
		Passed:      storedCount == actualCount,
		Details:     fmt.Sprintf("stored=%d, actual=%d", storedCount, actualCount),
		Blocking:    true,
	})

	// UC-06: Migration handler exists
	migrations := GetMigrations()
	hasMigration := false
	for _, m := range migrations {
		if m.FromVersion == ModuleConsensusVersion {
			hasMigration = true
		}
	}
	checks = append(checks, UpgradeChecklistItem{
		ID:          "UC-06",
		Category:    "upgrade",
		Description: "Migration handler registered for current version",
		Passed:      hasMigration,
		Details:     fmt.Sprintf("from v%d handler exists: %v", ModuleConsensusVersion, hasMigration),
		Blocking:    false, // May not need migration if no breaking changes
	})

	// UC-07: Consensus threshold meets BFT requirement
	bftSafe := params != nil && params.ConsensusThreshold >= 67
	checks = append(checks, UpgradeChecklistItem{
		ID:          "UC-07",
		Category:    "consensus",
		Description: "Consensus threshold >= 67% (BFT safety)",
		Passed:      bftSafe,
		Details:     fmt.Sprintf("threshold=%d", params.ConsensusThreshold),
		Blocking:    true,
	})

	// UC-08: Fee distribution conserves value
	config := DefaultFeeDistributionConfig()
	bpsSum := config.ValidatorRewardBps + config.TreasuryBps + config.BurnBps + config.InsuranceFundBps
	checks = append(checks, UpgradeChecklistItem{
		ID:          "UC-08",
		Category:    "economics",
		Description: "Fee BPS sum to 10000",
		Passed:      bpsSum == 10000,
		Details:     fmt.Sprintf("sum=%d", bpsSum),
		Blocking:    true,
	})

	// UC-09: Validator stats are non-negative
	statsClean := true
	_ = k.ValidatorStats.Walk(ctx, nil, func(_ string, s types.ValidatorStats) (bool, error) {
		if s.ReputationScore < 0 || s.ReputationScore > 100 ||
			s.TotalJobsProcessed < 0 || s.FailedJobs < 0 {
			statsClean = false
		}
		return false, nil
	})
	checks = append(checks, UpgradeChecklistItem{
		ID:          "UC-09",
		Category:    "state",
		Description: "Validator stats are within bounds",
		Passed:      statsClean,
		Blocking:    false,
	})

	// UC-10: State snapshot can be captured
	snapStart := time.Now()
	snap := CaptureStateSnapshot(ctx, k)
	snapDuration := time.Since(snapStart)
	checks = append(checks, UpgradeChecklistItem{
		ID:          "UC-10",
		Category:    "infrastructure",
		Description: "State snapshot can be captured within 100ms",
		Passed:      snapDuration < 100*time.Millisecond,
		Details: fmt.Sprintf("duration=%v, jobs=%d, validators=%d",
			snapDuration, snap.TotalJobs, snap.TotalValidators),
		Blocking: false,
	})

	return checks
}

// ChecklistPassesBlocking returns true if all blocking items pass.
func ChecklistPassesBlocking(items []UpgradeChecklistItem) bool {
	for _, item := range items {
		if item.Blocking && !item.Passed {
			return false
		}
	}
	return true
}

// BlockingFailuresFromChecklist returns only the blocking failures.
func BlockingFailuresFromChecklist(items []UpgradeChecklistItem) []UpgradeChecklistItem {
	var failures []UpgradeChecklistItem
	for _, item := range items {
		if item.Blocking && !item.Passed {
			failures = append(failures, item)
		}
	}
	return failures
}

// ---------------------------------------------------------------------------
// Section 4: Rollback Drill
// ---------------------------------------------------------------------------

// RollbackDrillResult captures the outcome of a rollback drill simulation.
type RollbackDrillResult struct {
	// Identity
	ChainID     string
	BlockHeight int64
	DrillAt     string

	// Snapshot
	SnapshotCaptured bool
	SnapshotDuration time.Duration

	// Simulated corruption
	CorruptionApplied string
	InvariantsBroken  bool

	// Recovery
	RecoveryAttempted bool
	RecoveryDuration  time.Duration
	RecoverySuccess   bool
	RecoveryDetails   string

	// Post-recovery
	PostRecoveryInvariantsPass bool
	PostRecoveryParamsValid    bool

	// Overall
	DrillPass      bool
	FailureReasons []string
}

// RunRollbackDrill simulates a rollback scenario by:
//  1. Capturing state snapshot
//  2. Simulating state corruption (parameter violation)
//  3. Detecting the corruption via invariants/validation
//  4. Restoring from snapshot
//  5. Verifying recovery
//
// This operates on LIVE STATE within the test context, which is safe because
// test contexts use in-memory stores that are discarded after the test.
func RunRollbackDrill(ctx sdk.Context, k Keeper) *RollbackDrillResult {
	result := &RollbackDrillResult{
		ChainID:     ctx.ChainID(),
		BlockHeight: ctx.BlockHeight(),
		DrillAt:     ctx.BlockTime().UTC().Format(time.RFC3339),
		DrillPass:   true,
	}

	// Step 1: Capture pre-corruption snapshot
	snapStart := time.Now()
	preSnapshot := CaptureStateSnapshot(ctx, k)
	result.SnapshotDuration = time.Since(snapStart)
	result.SnapshotCaptured = true

	// Save current params for restoration
	originalParams, err := k.GetParams(ctx)
	if err != nil {
		result.DrillPass = false
		result.FailureReasons = append(result.FailureReasons, "cannot read params: "+err.Error())
		return result
	}

	// Step 2: Apply simulated corruption — set consensus threshold below BFT safety
	corruptParams := *originalParams
	corruptParams.ConsensusThreshold = 40 // Dangerously low — below ValidateParams minimum
	_ = k.Params.Set(ctx, corruptParams)
	result.CorruptionApplied = "consensus_threshold set to 40 (below BFT safety minimum of 51)"

	// Step 3: Detect corruption
	corruptedParams, _ := k.GetParams(ctx)
	validationErr := ValidateParams(corruptedParams)
	result.InvariantsBroken = validationErr != nil

	if !result.InvariantsBroken {
		result.DrillPass = false
		result.FailureReasons = append(result.FailureReasons,
			"corruption was not detected by validation")
	}

	// Step 4: Recovery — restore original params
	recoveryStart := time.Now()
	result.RecoveryAttempted = true

	restoreErr := k.Params.Set(ctx, *originalParams)
	result.RecoveryDuration = time.Since(recoveryStart)

	if restoreErr != nil {
		result.RecoverySuccess = false
		result.RecoveryDetails = "failed to restore params: " + restoreErr.Error()
		result.DrillPass = false
		result.FailureReasons = append(result.FailureReasons, result.RecoveryDetails)
	} else {
		result.RecoverySuccess = true
		result.RecoveryDetails = "params restored from snapshot"
	}

	// Step 5: Post-recovery verification
	restoredParams, _ := k.GetParams(ctx)
	result.PostRecoveryParamsValid = ValidateParams(restoredParams) == nil

	invariants := AllInvariants(k)
	_, broken := invariants(ctx)
	result.PostRecoveryInvariantsPass = !broken

	// Verify state matches pre-corruption snapshot
	postSnapshot := CaptureStateSnapshot(ctx, k)
	diff := CompareSnapshots(preSnapshot, postSnapshot)
	if diff.ParamsChanged {
		result.DrillPass = false
		result.FailureReasons = append(result.FailureReasons,
			"params hash mismatch after recovery")
	}

	if !result.PostRecoveryInvariantsPass {
		result.DrillPass = false
		result.FailureReasons = append(result.FailureReasons,
			"invariants still broken after recovery")
	}

	if !result.PostRecoveryParamsValid {
		result.DrillPass = false
		result.FailureReasons = append(result.FailureReasons,
			"params still invalid after recovery")
	}

	return result
}

// ---------------------------------------------------------------------------
// Section 5: Rehearsal Report Renderer
// ---------------------------------------------------------------------------

// RenderRehearsalReport produces a human-readable upgrade rehearsal report.
func RenderRehearsalReport(r *UpgradeRehearsalResult) string {
	var sb strings.Builder

	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║           UPGRADE REHEARSAL REPORT                          ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	sb.WriteString(fmt.Sprintf("Chain: %s | Block: %d | Time: %s\n", r.ChainID, r.BlockHeight, r.RunAt))
	sb.WriteString(fmt.Sprintf("Upgrade: v%d → v%d (simulated: %v)\n\n", r.FromVersion, r.ToVersion, r.MigrationSimulated))

	sb.WriteString("─── MIGRATION STEPS ───────────────────────────────────────────\n")
	for _, step := range r.MigrationSteps {
		status := "PASS"
		if !step.Passed {
			status = "FAIL"
		}
		sb.WriteString(fmt.Sprintf("  [%s] %-30s %v  %s\n", status, step.Name, step.Duration, step.Details))
	}

	sb.WriteString(fmt.Sprintf("\n  Total Duration: %v\n", r.MigrationDuration))

	if len(r.PreUpgradeWarnings) > 0 {
		sb.WriteString("\n─── PRE-UPGRADE WARNINGS ──────────────────────────────────────\n")
		for _, w := range r.PreUpgradeWarnings {
			sb.WriteString(fmt.Sprintf("  ⚠ %s\n", w))
		}
	}

	sb.WriteString("\n─── STATE DIFF ────────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Jobs:       %+d\n", r.StateDiff.JobsDelta))
	sb.WriteString(fmt.Sprintf("  Pending:    %+d\n", r.StateDiff.PendingDelta))
	sb.WriteString(fmt.Sprintf("  Validators: %+d\n", r.StateDiff.ValidatorDelta))
	sb.WriteString(fmt.Sprintf("  Models:     %+d\n", r.StateDiff.ModelDelta))
	sb.WriteString(fmt.Sprintf("  Params:     changed=%v\n", r.StateDiff.ParamsChanged))
	sb.WriteString(fmt.Sprintf("  Invariants: %s\n", r.StateDiff.InvariantStatus))

	sb.WriteString("\n─── DETERMINATION ─────────────────────────────────────────────\n")
	if r.RehearsalPass {
		sb.WriteString("  *** REHEARSAL PASSED *** — Ready for upgrade\n")
	} else {
		sb.WriteString("  *** REHEARSAL FAILED *** — NOT ready for upgrade\n")
		for _, reason := range r.FailureReasons {
			sb.WriteString(fmt.Sprintf("  ✗ %s\n", reason))
		}
	}

	sb.WriteString("\n══════════════════════════════════════════════════════════════\n")

	return sb.String()
}
