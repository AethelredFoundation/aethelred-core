package keeper

import "fmt"

// ---------------------------------------------------------------------------
// Section 5: Treasury & Grants
// ---------------------------------------------------------------------------

// TreasuryConfig defines the treasury management parameters.
type TreasuryConfig struct {
	// AllocationFromEmissionBps is the % of new emission going to treasury.
	AllocationFromEmissionBps int64

	// GrantsAllocationBps is the % of treasury allocated to grants.
	GrantsAllocationBps int64

	// MaxGrantSizeUAETH is the maximum single grant amount.
	MaxGrantSizeUAETH int64

	// GrantVotingPeriodBlocks is the voting period for grant proposals.
	GrantVotingPeriodBlocks int64

	// GrantQuorumBps is the quorum for grant proposals.
	GrantQuorumBps int64

	// InsuranceReserveBps is the % of treasury earmarked for insurance.
	InsuranceReserveBps int64
}

// DefaultTreasuryConfig returns the default treasury configuration.
func DefaultTreasuryConfig() TreasuryConfig {
	return TreasuryConfig{
		AllocationFromEmissionBps: 1500,           // 15% of emissions
		GrantsAllocationBps:       4000,           // 40% of treasury for grants
		MaxGrantSizeUAETH:         10_000_000_000, // 10,000 AETH per grant
		GrantVotingPeriodBlocks:   BlocksPerWeek,  // 1 week
		GrantQuorumBps:            3300,           // 33%
		InsuranceReserveBps:       2000,           // 20% of treasury for insurance
	}
}

// ValidateTreasuryConfig checks treasury parameters.
func ValidateTreasuryConfig(config TreasuryConfig) error {
	if config.AllocationFromEmissionBps < 500 || config.AllocationFromEmissionBps > 5000 {
		return fmt.Errorf("emission allocation must be in [500, 5000] BPS, got %d",
			config.AllocationFromEmissionBps)
	}
	if config.GrantsAllocationBps < 0 || config.GrantsAllocationBps > 8000 {
		return fmt.Errorf("grants allocation must be in [0, 8000] BPS, got %d",
			config.GrantsAllocationBps)
	}
	if config.MaxGrantSizeUAETH <= 0 {
		return fmt.Errorf("max grant size must be positive, got %d", config.MaxGrantSizeUAETH)
	}
	if config.GrantQuorumBps < 2000 || config.GrantQuorumBps > 8000 {
		return fmt.Errorf("grant quorum must be in [2000, 8000] BPS, got %d", config.GrantQuorumBps)
	}
	sumBps := config.GrantsAllocationBps + config.InsuranceReserveBps
	if sumBps > 10000 {
		return fmt.Errorf("grants + insurance cannot exceed 10000 BPS, got %d", sumBps)
	}
	return nil
}

// TreasuryProjection projects treasury balance over time.
type TreasuryProjection struct {
	Year               int
	EmissionToTreasury int64
	GrantsSpent        int64
	InsuranceReserve   int64
	EndBalance         int64
}

// ProjectTreasuryGrowth simulates treasury accumulation over years.
func ProjectTreasuryGrowth(emissionConfig EmissionConfig, treasuryConfig TreasuryConfig, years int) []TreasuryProjection {
	schedule := ComputeEmissionSchedule(emissionConfig, years)
	projections := make([]TreasuryProjection, 0, years)
	balance := int64(0)

	for _, entry := range schedule {
		toTreasury := entry.AnnualEmission * treasuryConfig.AllocationFromEmissionBps / BpsBase
		grantsSpent := toTreasury * treasuryConfig.GrantsAllocationBps / BpsBase
		insuranceReserve := toTreasury * treasuryConfig.InsuranceReserveBps / BpsBase
		balance += toTreasury - grantsSpent

		projections = append(projections, TreasuryProjection{
			Year:               entry.Year,
			EmissionToTreasury: toTreasury,
			GrantsSpent:        grantsSpent,
			InsuranceReserve:   insuranceReserve,
			EndBalance:         balance,
		})
	}

	return projections
}

// ---------------------------------------------------------------------------
// Section 6: Vesting & Distribution
// ---------------------------------------------------------------------------

// VestingSchedule defines a token vesting configuration.
type VestingSchedule struct {
	Category         string
	TotalUAETH       int64
	CliffBlocks      int64 // Cliff period in blocks
	VestingBlocks    int64 // Total vesting period in blocks
	CliffPercent     int64 // % released at cliff (BPS)
	LinearAfterCliff bool  // Linear release after cliff
}

// DefaultVestingSchedules returns the standard vesting schedules.
func DefaultVestingSchedules() []VestingSchedule {
	return []VestingSchedule{
		{
			Category:         "team",
			TotalUAETH:       150_000_000_000_000, // 15% of supply
			CliffBlocks:      BlocksPerYear,       // 12-month cliff
			VestingBlocks:    BlocksPerYear * 5,   // 5-year total vest
			CliffPercent:     0,                   // nothing at cliff, then linear
			LinearAfterCliff: true,
		},
		{
			Category:         "strategic_partners",
			TotalUAETH:       100_000_000_000_000, // 10% of supply
			CliffBlocks:      BlocksPerYear / 2,   // 6-month cliff
			VestingBlocks:    BlocksPerYear * 3,   // 3-year total
			CliffPercent:     1000,                // 10% at cliff
			LinearAfterCliff: true,
		},
		{
			Category:         "community_ecosystem",
			TotalUAETH:       300_000_000_000_000, // 30% of supply
			CliffBlocks:      0,                   // No cliff
			VestingBlocks:    BlocksPerYear * 2,   // 2-year linear
			CliffPercent:     500,                 // 5% at genesis
			LinearAfterCliff: true,
		},
		{
			Category:         "validators_incentives",
			TotalUAETH:       200_000_000_000_000, // 20% of supply
			CliffBlocks:      0,                   // No cliff
			VestingBlocks:    BlocksPerYear * 4,   // 4-year linear
			CliffPercent:     0,
			LinearAfterCliff: true,
		},
		{
			Category:         "treasury_reserve",
			TotalUAETH:       250_000_000_000_000, // 25% of supply
			CliffBlocks:      BlocksPerYear,       // 12-month cliff
			VestingBlocks:    BlocksPerYear * 6,   // 6-year total
			CliffPercent:     0,
			LinearAfterCliff: true,
		},
	}
}

// ValidateVestingSchedules checks all vesting schedules.
func ValidateVestingSchedules(schedules []VestingSchedule) error {
	totalAllocated := int64(0)
	categories := make(map[string]bool)

	for _, s := range schedules {
		if s.Category == "" {
			return fmt.Errorf("vesting category must not be empty")
		}
		if categories[s.Category] {
			return fmt.Errorf("duplicate vesting category %q", s.Category)
		}
		categories[s.Category] = true

		if s.TotalUAETH <= 0 {
			return fmt.Errorf("category %q: total must be positive", s.Category)
		}
		if s.VestingBlocks <= 0 {
			return fmt.Errorf("category %q: vesting period must be positive", s.Category)
		}
		if s.CliffBlocks < 0 {
			return fmt.Errorf("category %q: cliff must be non-negative", s.Category)
		}
		if s.CliffBlocks >= s.VestingBlocks {
			return fmt.Errorf("category %q: cliff (%d) must be < vesting period (%d)",
				s.Category, s.CliffBlocks, s.VestingBlocks)
		}
		if s.CliffPercent < 0 || s.CliffPercent > 5000 {
			return fmt.Errorf("category %q: cliff percent must be in [0, 5000] BPS, got %d",
				s.Category, s.CliffPercent)
		}
		totalAllocated += s.TotalUAETH
	}

	if totalAllocated > InitialSupplyUAETH {
		return fmt.Errorf("total vesting allocation (%d) exceeds initial supply (%d)",
			totalAllocated, InitialSupplyUAETH)
	}

	return nil
}

// VestedAmount calculates how much has vested at a given block height.
func VestedAmount(schedule VestingSchedule, blockHeight int64) int64 {
	if blockHeight <= 0 {
		return 0
	}

	// Before cliff.
	if blockHeight < schedule.CliffBlocks {
		return 0
	}

	// At cliff.
	cliffAmount := schedule.TotalUAETH * schedule.CliffPercent / BpsBase

	if !schedule.LinearAfterCliff {
		if blockHeight >= schedule.VestingBlocks {
			return schedule.TotalUAETH
		}
		return cliffAmount
	}

	// Linear vesting after cliff.
	if blockHeight >= schedule.VestingBlocks {
		return schedule.TotalUAETH
	}

	remainingToVest := schedule.TotalUAETH - cliffAmount
	vestingAfterCliff := schedule.VestingBlocks - schedule.CliffBlocks
	if vestingAfterCliff <= 0 {
		return schedule.TotalUAETH
	}

	elapsed := blockHeight - schedule.CliffBlocks
	linearVested := remainingToVest * elapsed / vestingAfterCliff

	return cliffAmount + linearVested
}
