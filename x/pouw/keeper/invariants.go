package keeper

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// RegisterInvariants registers all module invariants with the invariant registry.
func RegisterInvariants(ir sdk.InvariantRegistry, k Keeper) {
	ir.RegisterRoute(types.ModuleName, "job-state-machine", JobStateMachineInvariant(k))
	ir.RegisterRoute(types.ModuleName, "pending-jobs-consistency", PendingJobsConsistencyInvariant(k))
	ir.RegisterRoute(types.ModuleName, "job-count-consistency", JobCountConsistencyInvariant(k))
	ir.RegisterRoute(types.ModuleName, "no-orphan-pending-jobs", NoOrphanPendingJobsInvariant(k))
	ir.RegisterRoute(types.ModuleName, "completed-jobs-have-seals", CompletedJobsHaveSealsInvariant(k))
	ir.RegisterRoute(types.ModuleName, "validator-stats-non-negative", ValidatorStatsNonNegativeInvariant(k))
	ir.RegisterRoute(types.ModuleName, "no-duplicate-validator-capabilities", NoDuplicateValidatorCapabilitiesInvariant(k))
}

// AllInvariants runs all invariants of the pouw module.
func AllInvariants(k Keeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		invariants := []sdk.Invariant{
			JobStateMachineInvariant(k),
			PendingJobsConsistencyInvariant(k),
			JobCountConsistencyInvariant(k),
			NoOrphanPendingJobsInvariant(k),
			CompletedJobsHaveSealsInvariant(k),
			ValidatorStatsNonNegativeInvariant(k),
			NoDuplicateValidatorCapabilitiesInvariant(k),
		}

		for _, inv := range invariants {
			if msg, broken := inv(ctx); broken {
				return msg, broken
			}
		}
		return "", false
	}
}

// JobStateMachineInvariant checks that all jobs are in a valid state and
// that no job has transitioned to an impossible state. Specifically:
//   - All jobs must have a recognized status
//   - Completed jobs must have OutputHash and SealId set
//   - Processing jobs must not have CompletedAt set
//   - Pending jobs must not have OutputHash or SealId set
func JobStateMachineInvariant(k Keeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		var msg string
		broken := false

		_ = k.Jobs.Walk(ctx, nil, func(id string, job types.ComputeJob) (bool, error) {
			// Check valid status
			switch job.Status {
			case types.JobStatusPending, types.JobStatusProcessing,
				types.JobStatusCompleted, types.JobStatusFailed, types.JobStatusExpired:
				// valid
			default:
				msg += fmt.Sprintf("INVARIANT BROKEN: job %s has unknown status %d\n", id, job.Status)
				broken = true
				return false, nil
			}

			// Completed jobs must have output and seal
			if job.Status == types.JobStatusCompleted {
				if len(job.OutputHash) == 0 {
					msg += fmt.Sprintf("INVARIANT BROKEN: completed job %s has no output hash\n", id)
					broken = true
				}
				if job.SealId == "" {
					msg += fmt.Sprintf("INVARIANT BROKEN: completed job %s has no seal ID\n", id)
					broken = true
				}
				if job.CompletedAt == nil {
					msg += fmt.Sprintf("INVARIANT BROKEN: completed job %s has no CompletedAt timestamp\n", id)
					broken = true
				}
			}

			// Processing jobs must not have CompletedAt
			if job.Status == types.JobStatusProcessing {
				if job.CompletedAt != nil {
					msg += fmt.Sprintf("INVARIANT BROKEN: processing job %s has CompletedAt set\n", id)
					broken = true
				}
			}

			// Pending jobs must not have output or seal
			if job.Status == types.JobStatusPending {
				if len(job.OutputHash) > 0 {
					msg += fmt.Sprintf("INVARIANT BROKEN: pending job %s has output hash set\n", id)
					broken = true
				}
				if job.SealId != "" {
					msg += fmt.Sprintf("INVARIANT BROKEN: pending job %s has seal ID set\n", id)
					broken = true
				}
			}

			// All jobs must have valid model and input hashes
			if len(job.ModelHash) != 32 {
				msg += fmt.Sprintf("INVARIANT BROKEN: job %s has invalid model hash length %d\n", id, len(job.ModelHash))
				broken = true
			}
			if len(job.InputHash) != 32 {
				msg += fmt.Sprintf("INVARIANT BROKEN: job %s has invalid input hash length %d\n", id, len(job.InputHash))
				broken = true
			}

			return false, nil
		})

		if broken {
			return sdk.FormatInvariant(types.ModuleName, "job-state-machine", msg), true
		}
		return "", false
	}
}

// PendingJobsConsistencyInvariant ensures the PendingJobs index is consistent
// with the Jobs collection. Specifically:
//   - Every job in PendingJobs must exist in Jobs
//   - Every job in PendingJobs must have status Pending or Processing
//   - Every Pending/Processing job in Jobs must exist in PendingJobs
func PendingJobsConsistencyInvariant(k Keeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		var msg string
		broken := false

		// Build a set of pending job IDs from PendingJobs index
		pendingIndex := make(map[string]bool)
		_ = k.PendingJobs.Walk(ctx, nil, func(id string, job types.ComputeJob) (bool, error) {
			pendingIndex[id] = true

			// Must exist in main Jobs collection
			exists, _ := k.Jobs.Has(ctx, id)
			if !exists {
				msg += fmt.Sprintf("INVARIANT BROKEN: pending job %s not found in Jobs collection\n", id)
				broken = true
			}

			// Must be Pending or Processing
			if job.Status != types.JobStatusPending && job.Status != types.JobStatusProcessing {
				msg += fmt.Sprintf("INVARIANT BROKEN: job %s in PendingJobs has status %s (expected Pending or Processing)\n",
					id, job.Status)
				broken = true
			}

			return false, nil
		})

		// Check reverse: every Pending/Processing job in Jobs should be in PendingJobs
		_ = k.Jobs.Walk(ctx, nil, func(id string, job types.ComputeJob) (bool, error) {
			if job.Status == types.JobStatusPending || job.Status == types.JobStatusProcessing {
				if !pendingIndex[id] {
					msg += fmt.Sprintf("INVARIANT BROKEN: job %s has status %s but is not in PendingJobs index\n",
						id, job.Status)
					broken = true
				}
			}
			return false, nil
		})

		if broken {
			return sdk.FormatInvariant(types.ModuleName, "pending-jobs-consistency", msg), true
		}
		return "", false
	}
}

// JobCountConsistencyInvariant checks that the stored job count matches
// the actual number of jobs in the Jobs collection.
func JobCountConsistencyInvariant(k Keeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		storedCount, err := k.JobCount.Get(ctx)
		if err != nil {
			// If not set, treat as 0
			storedCount = 0
		}

		actualCount := uint64(0)
		_ = k.Jobs.Walk(ctx, nil, func(id string, job types.ComputeJob) (bool, error) {
			actualCount++
			return false, nil
		})

		if storedCount != actualCount {
			msg := fmt.Sprintf("INVARIANT BROKEN: stored job count %d != actual job count %d\n",
				storedCount, actualCount)
			return sdk.FormatInvariant(types.ModuleName, "job-count-consistency", msg), true
		}

		return "", false
	}
}

// NoOrphanPendingJobsInvariant checks that no terminal-state jobs remain
// in the PendingJobs index. Jobs with status Completed, Failed, or Expired
// must be removed from PendingJobs by UpdateJob().
func NoOrphanPendingJobsInvariant(k Keeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		var msg string
		broken := false

		_ = k.PendingJobs.Walk(ctx, nil, func(id string, job types.ComputeJob) (bool, error) {
			switch job.Status {
			case types.JobStatusCompleted, types.JobStatusFailed, types.JobStatusExpired:
				msg += fmt.Sprintf("INVARIANT BROKEN: terminal-state job %s (status=%s) still in PendingJobs\n",
					id, job.Status)
				broken = true
			}
			return false, nil
		})

		if broken {
			return sdk.FormatInvariant(types.ModuleName, "no-orphan-pending-jobs", msg), true
		}
		return "", false
	}
}

// CompletedJobsHaveSealsInvariant checks that every completed job references
// a valid seal ID. This ensures the audit trail is complete.
func CompletedJobsHaveSealsInvariant(k Keeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		var msg string
		broken := false

		_ = k.Jobs.Walk(ctx, nil, func(id string, job types.ComputeJob) (bool, error) {
			if job.Status == types.JobStatusCompleted {
				if job.SealId == "" {
					msg += fmt.Sprintf("INVARIANT BROKEN: completed job %s missing seal ID — audit trail broken\n", id)
					broken = true
				}
				if len(job.OutputHash) != 32 {
					msg += fmt.Sprintf("INVARIANT BROKEN: completed job %s has invalid output hash length %d\n", id, len(job.OutputHash))
					broken = true
				}
			}
			return false, nil
		})

		if broken {
			return sdk.FormatInvariant(types.ModuleName, "completed-jobs-have-seals", msg), true
		}
		return "", false
	}
}

// ValidatorStatsNonNegativeInvariant checks that all validator statistics
// have non-negative values and that TotalJobsProcessed >= SuccessfulJobs + FailedJobs.
func ValidatorStatsNonNegativeInvariant(k Keeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		var msg string
		broken := false

		_ = k.ValidatorStats.Walk(ctx, nil, func(addr string, stats types.ValidatorStats) (bool, error) {
			if stats.TotalJobsProcessed < 0 {
				msg += fmt.Sprintf("INVARIANT BROKEN: validator %s has negative TotalJobsProcessed %d\n",
					addr, stats.TotalJobsProcessed)
				broken = true
			}
			if stats.SuccessfulJobs < 0 {
				msg += fmt.Sprintf("INVARIANT BROKEN: validator %s has negative SuccessfulJobs %d\n",
					addr, stats.SuccessfulJobs)
				broken = true
			}
			if stats.FailedJobs < 0 {
				msg += fmt.Sprintf("INVARIANT BROKEN: validator %s has negative FailedJobs %d\n",
					addr, stats.FailedJobs)
				broken = true
			}
			if stats.ReputationScore < 0 {
				msg += fmt.Sprintf("INVARIANT BROKEN: validator %s has negative ReputationScore %d\n",
					addr, stats.ReputationScore)
				broken = true
			}
			if stats.ReputationScore > 100 {
				msg += fmt.Sprintf("INVARIANT BROKEN: validator %s has ReputationScore %d > 100\n",
					addr, stats.ReputationScore)
				broken = true
			}
			// Total must be >= sum of success + failed
			if stats.TotalJobsProcessed < stats.SuccessfulJobs+stats.FailedJobs {
				msg += fmt.Sprintf("INVARIANT BROKEN: validator %s total %d < success %d + failed %d\n",
					addr, stats.TotalJobsProcessed, stats.SuccessfulJobs, stats.FailedJobs)
				broken = true
			}
			if stats.SlashingEvents < 0 {
				msg += fmt.Sprintf("INVARIANT BROKEN: validator %s has negative SlashingEvents %d\n",
					addr, stats.SlashingEvents)
				broken = true
			}

			return false, nil
		})

		if broken {
			return sdk.FormatInvariant(types.ModuleName, "validator-stats-non-negative", msg), true
		}
		return "", false
	}
}

// NoDuplicateValidatorCapabilitiesInvariant checks that no validator is
// registered more than once. The collection key is the address, so duplicates
// are structurally impossible, but this verifies address consistency.
func NoDuplicateValidatorCapabilitiesInvariant(k Keeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		var msg string
		broken := false

		seen := make(map[string]bool)
		_ = k.ValidatorCapabilities.Walk(ctx, nil, func(addr string, cap types.ValidatorCapability) (bool, error) {
			// Key should match stored address
			if cap.Address != addr {
				msg += fmt.Sprintf("INVARIANT BROKEN: validator capability key %s != stored address %s\n",
					addr, cap.Address)
				broken = true
			}
			if seen[addr] {
				msg += fmt.Sprintf("INVARIANT BROKEN: duplicate validator capability for %s\n", addr)
				broken = true
			}
			seen[addr] = true

			// MaxConcurrentJobs must be positive
			if cap.MaxConcurrentJobs <= 0 {
				msg += fmt.Sprintf("INVARIANT BROKEN: validator %s has non-positive MaxConcurrentJobs %d\n",
					addr, cap.MaxConcurrentJobs)
				broken = true
			}

			return false, nil
		})

		if broken {
			return sdk.FormatInvariant(types.ModuleName, "no-duplicate-validator-capabilities", msg), true
		}
		return "", false
	}
}
