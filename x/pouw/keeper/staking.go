package keeper

import (
	"context"
	"fmt"
	"sort"

	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// ValidatorSelector handles validator selection for compute jobs.
// It integrates with both the staking module (for bonded validator power)
// and the job scheduler (for hardware capability tracking).
type ValidatorSelector struct {
	keeper        *Keeper
	scheduler     *JobScheduler
	stakingKeeper StakingKeeper
}

// NewValidatorSelector creates a new validator selector
func NewValidatorSelector(keeper *Keeper, scheduler *JobScheduler, stakingKeeper StakingKeeper) *ValidatorSelector {
	return &ValidatorSelector{
		keeper:        keeper,
		scheduler:     scheduler,
		stakingKeeper: stakingKeeper,
	}
}

// StakingKeeperFull defines the full staking keeper interface
type StakingKeeperFull interface {
	StakingKeeper
	GetBondedValidatorsByPower(ctx context.Context) ([]stakingtypes.Validator, error)
	GetValidatorByConsAddr(ctx context.Context, consAddr sdk.ConsAddress) (stakingtypes.Validator, error)
	GetLastValidatorPower(ctx context.Context, operator sdk.ValAddress) (int64, error)
}

// ValidatorSelectionCriteria defines criteria for selecting validators
type ValidatorSelectionCriteria struct {
	// ProofType required for the job
	ProofType types.ProofType

	// MinReputationScore required
	MinReputationScore int64

	// MinStake required (in uaeth)
	MinStake int64

	// PreferredPlatforms for TEE jobs
	PreferredPlatforms []string

	// PreferredProofSystems for zkML jobs
	PreferredProofSystems []string

	// MaxValidators to select
	MaxValidators int

	// ExcludeValidators that shouldn't be selected
	ExcludeValidators []string
}

// DefaultSelectionCriteria returns default criteria
func DefaultSelectionCriteria(proofType types.ProofType) ValidatorSelectionCriteria {
	return ValidatorSelectionCriteria{
		ProofType:          proofType,
		MinReputationScore: 30,
		MinStake:           MinimumValidatorStakeUAETH().Int64(), // 100,000 AETHEL (April 1 testnet hardening)
		MaxValidators:      100,
	}
}

// ValidatorWithScore represents a validator with their selection score
type ValidatorWithScore struct {
	Address         string
	OperatorAddress string
	ConsAddress     string
	Capability      *types.ValidatorCapability
	StakingPower    int64
	SelectionScore  int64
}

// SelectValidators selects validators for a compute job based on criteria.
// It queries the scheduler for hardware capabilities and the staking keeper
// for bonded validator power.
func (vs *ValidatorSelector) SelectValidators(ctx context.Context, criteria ValidatorSelectionCriteria) ([]*ValidatorWithScore, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Get all registered validators from scheduler (real capability data)
	capabilities := vs.scheduler.GetValidatorCapabilities()

	var candidates []*ValidatorWithScore

	for addr, cap := range capabilities {
		// Check if validator meets basic criteria
		if !vs.meetsBasicCriteria(cap, criteria) {
			continue
		}

		// Check if excluded
		if vs.isExcluded(addr, criteria.ExcludeValidators) {
			continue
		}

		// Get staking power from staking keeper
		stakingPower := vs.getValidatorStakingPower(ctx, addr)

		// Check minimum stake
		if stakingPower < criteria.MinStake {
			continue
		}

		// Calculate selection score
		score := vs.calculateSelectionScore(cap, stakingPower, criteria)

		candidates = append(candidates, &ValidatorWithScore{
			Address:        addr,
			Capability:     cap,
			StakingPower:   stakingPower,
			SelectionScore: score,
		})
	}

	// Sort by selection score (highest first)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].SelectionScore > candidates[j].SelectionScore
	})

	// Limit to max validators
	if len(candidates) > criteria.MaxValidators {
		candidates = candidates[:criteria.MaxValidators]
	}

	sdkCtx.Logger().Info("Validators selected for job",
		"criteria", criteria.ProofType,
		"candidates_evaluated", len(capabilities),
		"selected", len(candidates),
	)

	return candidates, nil
}

// meetsBasicCriteria checks if a validator meets basic requirements
func (vs *ValidatorSelector) meetsBasicCriteria(cap *types.ValidatorCapability, criteria ValidatorSelectionCriteria) bool {
	// Must be online
	if !cap.IsOnline {
		return false
	}

	// Must have capacity
	if cap.CurrentJobs >= cap.MaxConcurrentJobs {
		return false
	}

	// Must meet reputation requirement
	if cap.ReputationScore < criteria.MinReputationScore {
		return false
	}

	// Must have required capabilities
	switch criteria.ProofType {
	case types.ProofTypeTEE:
		if len(cap.TeePlatforms) == 0 {
			return false
		}
	case types.ProofTypeZKML:
		if len(cap.ZkmlSystems) == 0 {
			return false
		}
	case types.ProofTypeHybrid:
		if len(cap.TeePlatforms) == 0 || len(cap.ZkmlSystems) == 0 {
			return false
		}
	}

	return true
}

// isExcluded checks if a validator is in the exclusion list
func (vs *ValidatorSelector) isExcluded(addr string, exclusions []string) bool {
	for _, excluded := range exclusions {
		if addr == excluded {
			return true
		}
	}
	return false
}

// calculateSelectionScore calculates a score for validator selection
func (vs *ValidatorSelector) calculateSelectionScore(cap *types.ValidatorCapability, stakingPower int64, criteria ValidatorSelectionCriteria) int64 {
	var score int64

	// Reputation component (max 40 points)
	score += cap.ReputationScore * 40 / 100

	// Staking power component (max 30 points)
	// Normalize to max 30 points (assuming 100M max stake)
	stakingScore := stakingPower / 3333333
	if stakingScore > 30 {
		stakingScore = 30
	}
	score += stakingScore

	// Capability match bonus (max 20 points)
	switch criteria.ProofType {
	case types.ProofTypeTEE:
		for _, pref := range criteria.PreferredPlatforms {
			for _, plat := range cap.TeePlatforms {
				if plat == pref {
					score += 10
					break
				}
			}
		}
	case types.ProofTypeZKML:
		for _, pref := range criteria.PreferredProofSystems {
			for _, sys := range cap.ZkmlSystems {
				if sys == pref {
					score += 10
					break
				}
			}
		}
	case types.ProofTypeHybrid:
		score += 15
	}

	// Availability bonus (max 10 points)
	availableSlots := cap.MaxConcurrentJobs - cap.CurrentJobs
	availabilityScore := int64(availableSlots * 2)
	if availabilityScore > 10 {
		availabilityScore = 10
	}
	score += availabilityScore

	return score
}

// getValidatorStakingPower gets a validator's staking power from the staking keeper.
// Falls back to on-chain ValidatorStats reputation if staking keeper query fails.
func (vs *ValidatorSelector) getValidatorStakingPower(ctx context.Context, addr string) int64 {
	// Try to get real staking power from the staking keeper
	if fullKeeper, ok := vs.stakingKeeper.(StakingKeeperFull); ok {
		valAddr, err := sdk.ValAddressFromBech32(addr)
		if err == nil {
			power, err := fullKeeper.GetLastValidatorPower(ctx, valAddr)
			if err == nil && power > 0 {
				return power
			}
		}
	}

	// Fallback: use on-chain validator stats for reputation-weighted power
	stats, err := vs.keeper.GetValidatorStats(ctx, addr)
	if err == nil {
		// Derive a power score from reputation and job history
		// This ensures validators with good track records get selected
		basePower := int64(1000000) // 1 AETH minimum
		reputationBonus := stats.ReputationScore * 10000
		return basePower + reputationBonus
	}

	// Last resort: minimum power for newly registered validators
	return int64(1000000)
}

// SelectCommitteeForJob selects a committee of validators for a specific job
func (vs *ValidatorSelector) SelectCommitteeForJob(ctx context.Context, job *types.ComputeJob, minValidators int) ([]*ValidatorWithScore, error) {
	criteria := DefaultSelectionCriteria(job.ProofType)
	criteria.MaxValidators = minValidators * 2 // Select more candidates than needed

	candidates, err := vs.SelectValidators(ctx, criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to select validators: %w", err)
	}

	if len(candidates) < minValidators {
		return nil, fmt.Errorf("insufficient validators: need %d, found %d", minValidators, len(candidates))
	}

	// Return exactly minValidators
	return candidates[:minValidators], nil
}

// ValidateValidatorForJob checks if a specific validator can handle a job
func (vs *ValidatorSelector) ValidateValidatorForJob(ctx context.Context, validatorAddr string, job *types.ComputeJob) error {
	// Get validator capability from scheduler
	jobsForValidator := vs.scheduler.GetJobsForValidator(ctx, validatorAddr)

	// Check if validator is assigned to this job
	found := false
	for _, j := range jobsForValidator {
		if j.Id == job.Id {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("validator %s is not assigned to job %s", validatorAddr, job.Id)
	}

	return nil
}

// UpdateValidatorPerformance updates a validator's performance metrics after job completion
func (vs *ValidatorSelector) UpdateValidatorPerformance(ctx context.Context, validatorAddr string, success bool, executionTimeMs int64) {
	// Update through scheduler
	if success {
		vs.scheduler.MarkJobComplete(validatorAddr)
	} else {
		vs.scheduler.MarkJobFailed(validatorAddr, "verification failed")
	}
}

// GetValidatorRanking returns validators ranked by their selection scores
func (vs *ValidatorSelector) GetValidatorRanking(ctx context.Context, proofType types.ProofType, limit int) ([]*ValidatorWithScore, error) {
	criteria := DefaultSelectionCriteria(proofType)
	criteria.MaxValidators = limit

	return vs.SelectValidators(ctx, criteria)
}

// CheckValidatorEligibility checks if a validator is eligible to participate
func (vs *ValidatorSelector) CheckValidatorEligibility(ctx context.Context, validatorAddr string) (bool, string) {
	// Check if validator is registered with capabilities
	capabilities := vs.scheduler.GetValidatorCapabilities()
	cap, registered := capabilities[validatorAddr]
	if !registered {
		return false, "validator not registered with compute capabilities"
	}

	if !cap.IsOnline {
		return false, "validator is offline"
	}

	if cap.ReputationScore < 10 {
		return false, "validator reputation too low"
	}

	// Check staking status via staking keeper
	stakingPower := vs.getValidatorStakingPower(ctx, validatorAddr)
	if stakingPower < 1000000 {
		return false, "insufficient staking power"
	}

	return true, ""
}
