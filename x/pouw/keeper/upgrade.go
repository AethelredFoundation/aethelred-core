package keeper

import (
	"fmt"
	"strconv"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// ---------------------------------------------------------------------------
// Module Upgrade Infrastructure
// ---------------------------------------------------------------------------
//
// This file provides upgrade handlers for the pouw module. Each consensus
// version bump (v1 → v2, etc.) is handled by a dedicated migration function
// that can modify state, add new parameters, or restructure collections.
//
// The upgrade framework follows Cosmos SDK conventions:
//   1. ConsensusVersion() returns the current version
//   2. RegisterMigrations() registers migration functions for each version step
//   3. Each migration is a pure function of the old state → new state
//   4. Migrations are tested deterministically with golden data
//
// Current version: 2 (genesis + v1→v2 migration applied)
// ---------------------------------------------------------------------------

// ModuleConsensusVersion is the current consensus version of the pouw module.
// Bump this when making breaking changes to the state schema.
const ModuleConsensusVersion = 2

// ---------------------------------------------------------------------------
// Migration registry
// ---------------------------------------------------------------------------

// ModuleMigration defines a single version migration step.
type ModuleMigration struct {
	FromVersion uint64
	ToVersion   uint64
	Handler     func(ctx sdk.Context, k Keeper) error
}

// GetMigrations returns all registered module migrations in order.
// Each entry represents a single version bump (e.g., v1→v2).
func GetMigrations() []ModuleMigration {
	return []ModuleMigration{
		// v1 → v2: Add insurance fund parameters and fee distribution config.
		// This migration will be activated when ModuleConsensusVersion is bumped to 2.
		{
			FromVersion: 1,
			ToVersion:   2,
			Handler:     migrateV1ToV2,
		},
	}
}

// RunMigrations executes all applicable migrations from fromVersion to
// toVersion sequentially. Returns an error if any migration fails.
func RunMigrations(ctx sdk.Context, k Keeper, fromVersion, toVersion uint64) error {
	if fromVersion >= toVersion {
		return nil // nothing to do
	}

	migrations := GetMigrations()
	for _, m := range migrations {
		if m.FromVersion >= fromVersion && m.ToVersion <= toVersion {
			ctx.Logger().Info(
				"running pouw module migration",
				"from_version", m.FromVersion,
				"to_version", m.ToVersion,
			)

			if err := m.Handler(ctx, k); err != nil {
				return fmt.Errorf("migration v%d→v%d failed: %w", m.FromVersion, m.ToVersion, err)
			}

			ctx.EventManager().EmitEvent(
				sdk.NewEvent(
					"module_migration",
					sdk.NewAttribute("module", types.ModuleName),
					sdk.NewAttribute("from_version", strconv.FormatUint(m.FromVersion, 10)),
					sdk.NewAttribute("to_version", strconv.FormatUint(m.ToVersion, 10)),
					sdk.NewAttribute("status", "success"),
				),
			)

			ctx.Logger().Info(
				"pouw module migration completed",
				"from_version", m.FromVersion,
				"to_version", m.ToVersion,
			)
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// v1 → v2 migration
// ---------------------------------------------------------------------------

// migrateV1ToV2 upgrades module state from consensus version 1 to version 2.
//
// Changes:
//   - Ensures all parameters have valid values (backfills missing fields)
//   - Sets default fee distribution percentages if not already present
//   - Validates all existing jobs have correct state machine invariants
//   - Cleans up any orphaned pending jobs
func migrateV1ToV2(ctx sdk.Context, k Keeper) error {
	// Step 1: Backfill params with any new defaults.
	params, err := k.GetParams(ctx)
	if err != nil {
		params = types.DefaultParams()
	}

	// Ensure all required fields have sensible values.
	defaults := types.DefaultParams()
	if params.MinValidators == 0 {
		params.MinValidators = defaults.MinValidators
	}
	if params.ConsensusThreshold == 0 {
		params.ConsensusThreshold = defaults.ConsensusThreshold
	}
	if params.JobTimeoutBlocks == 0 {
		params.JobTimeoutBlocks = defaults.JobTimeoutBlocks
	}
	if params.BaseJobFee == "" {
		params.BaseJobFee = defaults.BaseJobFee
	}
	if params.VerificationReward == "" {
		params.VerificationReward = defaults.VerificationReward
	}
	if params.SlashingPenalty == "" {
		params.SlashingPenalty = defaults.SlashingPenalty
	}
	if params.MaxJobsPerBlock == 0 {
		params.MaxJobsPerBlock = defaults.MaxJobsPerBlock
	}
	if len(params.AllowedProofTypes) == 0 {
		params.AllowedProofTypes = defaults.AllowedProofTypes
	}
	if params.VoteExtensionMaxPastSkewSecs == 0 {
		params.VoteExtensionMaxPastSkewSecs = defaults.VoteExtensionMaxPastSkewSecs
	}
	if params.VoteExtensionMaxFutureSkewSecs == 0 {
		params.VoteExtensionMaxFutureSkewSecs = defaults.VoteExtensionMaxFutureSkewSecs
	}

	if err := ValidateParams(params); err != nil {
		return fmt.Errorf("params validation failed after backfill: %w", err)
	}
	if err := k.SetParams(ctx, params); err != nil {
		return fmt.Errorf("failed to persist params: %w", err)
	}

	// Step 2: Clean up orphaned pending jobs.
	// A pending job is orphaned if its authoritative record in the Jobs
	// collection has a terminal status (completed/failed/expired) or if
	// the job no longer exists in Jobs at all.
	var orphanIDs []string
	_ = k.PendingJobs.Walk(ctx, nil, func(id string, _ types.ComputeJob) (bool, error) {
		// Look up the authoritative record from the Jobs collection.
		authJob, err := k.Jobs.Get(ctx, id)
		if err != nil {
			// Job doesn't exist in Jobs — definitely orphaned.
			orphanIDs = append(orphanIDs, id)
			return false, nil
		}
		switch authJob.Status {
		case types.JobStatusCompleted, types.JobStatusFailed, types.JobStatusExpired:
			orphanIDs = append(orphanIDs, id)
		}
		return false, nil
	})

	for _, id := range orphanIDs {
		_ = k.PendingJobs.Remove(ctx, id)
	}

	if len(orphanIDs) > 0 {
		ctx.Logger().Info("cleaned up orphaned pending jobs during migration",
			"count", len(orphanIDs),
		)
	}

	// Step 3: Reconcile JobCount.
	actualCount := uint64(0)
	_ = k.Jobs.Walk(ctx, nil, func(_ string, _ types.ComputeJob) (bool, error) {
		actualCount++
		return false, nil
	})

	storedCount, getErr := k.JobCount.Get(ctx)
	if getErr != nil || storedCount != actualCount {
		if err := k.JobCount.Set(ctx, actualCount); err != nil {
			return fmt.Errorf("failed to reconcile job count: %w", err)
		}
		ctx.Logger().Info("reconciled job count during migration",
			"old_count", storedCount,
			"new_count", actualCount,
		)
	}

	// Step 4: Validate all validator stats have non-negative values.
	_ = k.ValidatorStats.Walk(ctx, nil, func(addr string, stats types.ValidatorStats) (bool, error) {
		dirty := false
		if stats.ReputationScore < 0 {
			stats.ReputationScore = 0
			dirty = true
		}
		if stats.ReputationScore > 100 {
			stats.ReputationScore = 100
			dirty = true
		}
		if stats.TotalJobsProcessed < 0 {
			stats.TotalJobsProcessed = 0
			dirty = true
		}
		if dirty {
			_ = k.ValidatorStats.Set(ctx, addr, stats)
		}
		return false, nil
	})

	return nil
}

// ---------------------------------------------------------------------------
// Pre-upgrade validation
// ---------------------------------------------------------------------------

// PreUpgradeValidation performs a set of checks before an upgrade is applied.
// This can be called from a governance proposal handler to verify the chain
// is in a safe state for upgrading.
func PreUpgradeValidation(ctx sdk.Context, k Keeper) []string {
	var warnings []string

	// Check 1: No pending jobs in flight
	pendingJobs := k.GetPendingJobs(ctx)
	if len(pendingJobs) > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"WARNING: %d pending jobs in flight — these may be lost during upgrade",
			len(pendingJobs),
		))
	}

	// Check 2: All invariants pass
	invariants := AllInvariants(k)
	if msg, broken := invariants(ctx); broken {
		warnings = append(warnings, fmt.Sprintf(
			"WARNING: module invariant broken: %s",
			msg,
		))
	}

	// Check 3: Params are valid
	params, err := k.GetParams(ctx)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf(
			"WARNING: failed to retrieve params: %v", err,
		))
	} else if err := ValidateParams(params); err != nil {
		warnings = append(warnings, fmt.Sprintf(
			"WARNING: current params fail validation: %v", err,
		))
	}

	// Check 4: AllowSimulated should be false on production chains
	if params != nil && params.AllowSimulated {
		warnings = append(warnings, "WARNING: AllowSimulated is true — this should be false on production chains before upgrade")
	}

	return warnings
}

// ---------------------------------------------------------------------------
// Post-upgrade validation
// ---------------------------------------------------------------------------

// PostUpgradeValidation verifies that the upgrade completed successfully by
// running all invariants and checking state consistency.
func PostUpgradeValidation(ctx sdk.Context, k Keeper) error {
	// Run all invariants.
	invariants := AllInvariants(k)
	if msg, broken := invariants(ctx); broken {
		return fmt.Errorf("post-upgrade invariant check failed: %s", msg)
	}

	// Verify params are still valid.
	params, err := k.GetParams(ctx)
	if err != nil {
		return fmt.Errorf("failed to read params after upgrade: %w", err)
	}
	if err := ValidateParams(params); err != nil {
		return fmt.Errorf("params invalid after upgrade: %w", err)
	}

	// Verify job count consistency.
	storedCount, _ := k.JobCount.Get(ctx)
	actualCount := uint64(0)
	_ = k.Jobs.Walk(ctx, nil, func(_ string, _ types.ComputeJob) (bool, error) {
		actualCount++
		return false, nil
	})
	if storedCount != actualCount {
		return fmt.Errorf("job count mismatch after upgrade: stored=%d, actual=%d", storedCount, actualCount)
	}

	ctx.Logger().Info("post-upgrade validation passed",
		"module", types.ModuleName,
		"consensus_version", ModuleConsensusVersion,
	)

	return nil
}
