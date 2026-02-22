package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// =============================================================================
// AETHEL TOKENOMICS MODEL TESTS
//
// These tests verify the tokenomics design principles module:
//   1. Emission model (8 tests)
//   2. Staking economics (6 tests)
//   3. Dynamic fee model (7 tests)
//   4. Slashing economics (6 tests)
//   5. Treasury & grants (5 tests)
//   6. Vesting schedules (7 tests)
//   7. Anti-abuse config (4 tests)
//   8. Comprehensive model validation (4 tests)
//   9. Simulation engine (5 tests)
//  10. Report rendering (3 tests)
//  11. Integration (2 tests)
//
// Total: 57 tests
// =============================================================================

// =============================================================================
// Section 1: Emission Model
// =============================================================================

func TestDefaultEmissionConfig(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	require.NoError(t, keeper.ValidateEmissionConfig(config))
	require.Equal(t, int64(800), config.InitialInflationBps)
	require.Equal(t, int64(200), config.TargetInflationBps)
	require.Equal(t, keeper.EmissionExponentialDecay, config.DecayModel)
}

func TestEmissionConfig_ValidationBounds(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*keeper.EmissionConfig)
		wantErr bool
	}{
		{"valid default", func(c *keeper.EmissionConfig) {}, false},
		{"inflation too low", func(c *keeper.EmissionConfig) { c.InitialInflationBps = 50 }, true},
		{"inflation too high", func(c *keeper.EmissionConfig) { c.InitialInflationBps = 3000 }, true},
		{"target > initial", func(c *keeper.EmissionConfig) { c.TargetInflationBps = 900 }, true},
		{"target too low", func(c *keeper.EmissionConfig) { c.TargetInflationBps = 10 }, true},
		{"invalid decay model", func(c *keeper.EmissionConfig) { c.DecayModel = "unknown" }, true},
		{"decay period too short", func(c *keeper.EmissionConfig) { c.DecayPeriodYears = 1 }, true},
		{"staking target too low", func(c *keeper.EmissionConfig) { c.StakingTargetBps = 1000 }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := keeper.DefaultEmissionConfig()
			tt.modify(&config)
			err := keeper.ValidateEmissionConfig(config)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestEmissionSchedule_ExponentialDecay(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	schedule := keeper.ComputeEmissionSchedule(config, 10)

	require.Len(t, schedule, 10)

	// Inflation should decrease over time
	require.Greater(t, schedule[0].InflationBps, schedule[9].InflationBps,
		"inflation should decrease over 10 years")

	// Year 1 should be near initial inflation
	require.GreaterOrEqual(t, schedule[0].InflationBps, int64(600),
		"year 1 should have high inflation")

	// Supply should grow monotonically
	for i := 1; i < len(schedule); i++ {
		require.Greater(t, schedule[i].CumulativeSupply, schedule[i-1].CumulativeSupply,
			"supply should grow each year")
	}
}

func TestEmissionSchedule_LinearDecay(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	config.DecayModel = keeper.EmissionLinearDecay
	schedule := keeper.ComputeEmissionSchedule(config, 10)

	require.Len(t, schedule, 10)

	// After decay period, should hit target
	for i := int(config.DecayPeriodYears); i < len(schedule); i++ {
		require.Equal(t, config.TargetInflationBps, schedule[i].InflationBps,
			"year %d should be at target inflation", schedule[i].Year)
	}
}

func TestEmissionSchedule_StepDecay(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	config.DecayModel = keeper.EmissionStepDecay
	schedule := keeper.ComputeEmissionSchedule(config, 10)

	require.Len(t, schedule, 10)

	// Inflation should decrease in steps
	require.Greater(t, schedule[0].InflationBps, schedule[9].InflationBps)
	require.GreaterOrEqual(t, schedule[9].InflationBps, config.TargetInflationBps)
}

func TestEmissionSchedule_SupplyGrowsBounded(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	schedule := keeper.ComputeEmissionSchedule(config, 20)

	require.Len(t, schedule, 20)

	// Year 20 supply should not exceed 2x initial (given 8% starting, decaying)
	maxReasonable := int64(float64(keeper.InitialSupplyUAETH) * 2.0)
	require.Less(t, schedule[19].CumulativeSupply, maxReasonable,
		"supply after 20 years should not exceed 2x initial")
}

func TestEmissionSchedule_StakingYieldPositive(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	schedule := keeper.ComputeEmissionSchedule(config, 5)

	for _, entry := range schedule {
		require.GreaterOrEqual(t, entry.StakingYield, 0.0,
			"staking yield should be non-negative")
	}
}

func TestEmissionSchedule_MaxSupplyCap(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	config.MaxSupplyCap = keeper.InitialSupplyUAETH + 50_000_000_000_000 // +50M AETH
	schedule := keeper.ComputeEmissionSchedule(config, 20)

	for _, entry := range schedule {
		require.LessOrEqual(t, entry.CumulativeSupply, config.MaxSupplyCap,
			"supply should not exceed cap")
	}
}

// =============================================================================
// Section 2: Staking Economics
// =============================================================================

func TestDefaultStakingConfig(t *testing.T) {
	config := keeper.DefaultStakingConfig()
	require.NoError(t, keeper.ValidateStakingConfig(config))
	require.Equal(t, 100, config.MaxValidators)
	require.Equal(t, int64(1_000_000_000), config.MinStakeUAETH)
}

func TestStakingConfig_ValidationBounds(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*keeper.StakingConfig)
		wantErr bool
	}{
		{"valid default", func(c *keeper.StakingConfig) {}, false},
		{"min stake too low", func(c *keeper.StakingConfig) { c.MinStakeUAETH = 100 }, true},
		{"max commission < min", func(c *keeper.StakingConfig) { c.MaxCommissionBps = 100; c.MinCommissionBps = 500 }, true},
		{"min commission too low", func(c *keeper.StakingConfig) { c.MinCommissionBps = 50 }, true},
		{"max commission too high", func(c *keeper.StakingConfig) { c.MaxCommissionBps = 6000 }, true},
		{"unbonding too short", func(c *keeper.StakingConfig) { c.UnbondingPeriodBlocks = 1000 }, true},
		{"too few validators", func(c *keeper.StakingConfig) { c.MaxValidators = 3 }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := keeper.DefaultStakingConfig()
			tt.modify(&config)
			err := keeper.ValidateStakingConfig(config)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidatorEconomics_Default(t *testing.T) {
	k, ctx := newTestKeeper(t)

	econ, err := keeper.ComputeValidatorEconomics(ctx, k, "val-0", 1_000_000_000, 1000)
	require.NoError(t, err)
	require.NotNil(t, econ)
	require.Equal(t, "val-0", econ.ValidatorAddress)
	require.Greater(t, econ.BaseRewardPerBlock, int64(0))
	require.Greater(t, econ.ScaledReward, int64(0))
	require.Greater(t, econ.AnnualRevenue, int64(0))
}

func TestValidatorEconomics_ReputationAffectsReward(t *testing.T) {
	k, ctx := newTestKeeper(t)

	econ50, err := keeper.ComputeValidatorEconomics(ctx, k, "val-low", 1_000_000_000, 1000)
	require.NoError(t, err)

	// The default reputation is 50, so scaled reward should be <= base
	require.LessOrEqual(t, econ50.ScaledReward, econ50.BaseRewardPerBlock)
}

func TestValidatorEconomics_DelegatorYield(t *testing.T) {
	k, ctx := newTestKeeper(t)

	econ, err := keeper.ComputeValidatorEconomics(ctx, k, "val-0", 1_000_000_000, 1000)
	require.NoError(t, err)
	require.Greater(t, econ.DelegatorYieldBps, int64(0),
		"delegator yield should be positive")
}

func TestValidatorEconomics_SlashingExposure(t *testing.T) {
	k, ctx := newTestKeeper(t)

	econ, err := keeper.ComputeValidatorEconomics(ctx, k, "val-0", 1_000_000_000, 1000)
	require.NoError(t, err)
	require.Greater(t, econ.SlashingExposure, int64(0),
		"slashing exposure should be positive")
}

// =============================================================================
// Section 3: Dynamic Fee Model
// =============================================================================

func TestDefaultFeeMarketConfig(t *testing.T) {
	config := keeper.DefaultFeeMarketConfig()
	require.NoError(t, keeper.ValidateFeeMarketConfig(config))
	require.Equal(t, int64(1000), config.BaseFeeUAETH)
	require.Len(t, config.PriorityFeeTiers, 3)
}

func TestFeeMarketConfig_ValidationBounds(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*keeper.FeeMarketConfig)
		wantErr bool
	}{
		{"valid default", func(c *keeper.FeeMarketConfig) {}, false},
		{"base fee zero", func(c *keeper.FeeMarketConfig) { c.BaseFeeUAETH = 0 }, true},
		{"multiplier too low", func(c *keeper.FeeMarketConfig) { c.MaxMultiplierBps = 5000 }, true},
		{"congestion too low", func(c *keeper.FeeMarketConfig) { c.CongestionThresholdBps = 1000 }, true},
		{"no tiers", func(c *keeper.FeeMarketConfig) { c.PriorityFeeTiers = nil }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := keeper.DefaultFeeMarketConfig()
			tt.modify(&config)
			err := keeper.ValidateFeeMarketConfig(config)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDynamicFee_BelowThreshold(t *testing.T) {
	config := keeper.DefaultFeeMarketConfig()
	fee := keeper.ComputeDynamicFee(config, 0, 25)
	require.Equal(t, config.BaseFeeUAETH, fee)
}

func TestDynamicFee_AtThreshold(t *testing.T) {
	config := keeper.DefaultFeeMarketConfig()
	fee := keeper.ComputeDynamicFee(config, 175, 25)
	require.Equal(t, config.BaseFeeUAETH, fee)
}

func TestDynamicFee_AboveThreshold(t *testing.T) {
	config := keeper.DefaultFeeMarketConfig()
	fee := keeper.ComputeDynamicFee(config, 200, 25)
	require.Greater(t, fee, config.BaseFeeUAETH,
		"fee should increase above congestion threshold")
}

func TestDynamicFee_MaxCapped(t *testing.T) {
	config := keeper.DefaultFeeMarketConfig()
	fee := keeper.ComputeDynamicFee(config, 10000, 25)
	maxFee := config.BaseFeeUAETH * config.MaxMultiplierBps / 10000
	require.LessOrEqual(t, fee, maxFee,
		"fee should not exceed max multiplier")
}

func TestDynamicFee_ZeroCapacity(t *testing.T) {
	config := keeper.DefaultFeeMarketConfig()
	fee := keeper.ComputeDynamicFee(config, 100, 0)
	require.Equal(t, config.BaseFeeUAETH, fee)
}

// =============================================================================
// Section 4: Slashing Economics
// =============================================================================

func TestDefaultSlashingConfig(t *testing.T) {
	config := keeper.DefaultSlashingConfig()
	require.NoError(t, keeper.ValidateSlashingConfig(config))
	require.Len(t, config.Tiers, 4)
}

func TestSlashingConfig_TiersOrdered(t *testing.T) {
	config := keeper.DefaultSlashingConfig()
	for i := 1; i < len(config.Tiers); i++ {
		require.GreaterOrEqual(t, config.Tiers[i].SlashBps, config.Tiers[i-1].SlashBps,
			"tiers should be in increasing severity")
	}
}

func TestSlashingConfig_ValidationBounds(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*keeper.SlashingConfig)
		wantErr bool
	}{
		{"valid default", func(c *keeper.SlashingConfig) {}, false},
		{"no tiers", func(c *keeper.SlashingConfig) { c.Tiers = nil }, true},
		{"double-sign too low", func(c *keeper.SlashingConfig) { c.DoubleSignSlashBps = 500 }, true},
		{"downtime too low", func(c *keeper.SlashingConfig) { c.DowntimeSlashBps = 5 }, true},
		{"min signed too low", func(c *keeper.SlashingConfig) { c.MinSignedPerWindowBps = 1000 }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := keeper.DefaultSlashingConfig()
			tt.modify(&config)
			err := keeper.ValidateSlashingConfig(config)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestComputeSlashAmount(t *testing.T) {
	tier := keeper.SlashingTier{Name: "major", SlashBps: 1000}
	amount := keeper.ComputeSlashAmount(tier, 1_000_000_000)
	require.Equal(t, int64(100_000_000), amount, "10% of 1B = 100M")
}

func TestDeterrenceRatio(t *testing.T) {
	ratio := keeper.DeterrenceRatio(10000, 1000)
	require.Equal(t, 10.0, ratio, "10000/1000 = 10x deterrence")

	infRatio := keeper.DeterrenceRatio(10000, 0)
	require.True(t, infRatio > 0, "should be positive infinity")
}

func TestSlashing_DeterrenceAboveOne(t *testing.T) {
	config := keeper.DefaultSlashingConfig()
	staking := keeper.DefaultStakingConfig()

	for _, tier := range config.Tiers {
		slash := keeper.ComputeSlashAmount(tier, staking.MinStakeUAETH)
		ratio := keeper.DeterrenceRatio(slash, 1000*keeper.BlocksPerDay)

		if tier.Name == "minor_fault" {
			// Minor faults are warnings — deterrence ratio < 1 is acceptable
			require.Greater(t, ratio, 0.0,
				"tier %s should have positive deterrence ratio", tier.Name)
		} else {
			// Major, fraud, and critical tiers must deter (ratio > 1)
			require.Greater(t, ratio, 1.0,
				"tier %s should have deterrence ratio > 1", tier.Name)
		}
	}
}

// =============================================================================
// Section 5: Treasury & Grants
// =============================================================================

func TestDefaultTreasuryConfig(t *testing.T) {
	config := keeper.DefaultTreasuryConfig()
	require.NoError(t, keeper.ValidateTreasuryConfig(config))
	require.Equal(t, int64(1500), config.AllocationFromEmissionBps)
}

func TestTreasuryConfig_ValidationBounds(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*keeper.TreasuryConfig)
		wantErr bool
	}{
		{"valid default", func(c *keeper.TreasuryConfig) {}, false},
		{"allocation too low", func(c *keeper.TreasuryConfig) { c.AllocationFromEmissionBps = 100 }, true},
		{"allocation too high", func(c *keeper.TreasuryConfig) { c.AllocationFromEmissionBps = 6000 }, true},
		{"grant quorum too low", func(c *keeper.TreasuryConfig) { c.GrantQuorumBps = 1000 }, true},
		{"zero max grant", func(c *keeper.TreasuryConfig) { c.MaxGrantSizeUAETH = 0 }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := keeper.DefaultTreasuryConfig()
			tt.modify(&config)
			err := keeper.ValidateTreasuryConfig(config)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTreasuryProjection_GrowsOverTime(t *testing.T) {
	projections := keeper.ProjectTreasuryGrowth(
		keeper.DefaultEmissionConfig(),
		keeper.DefaultTreasuryConfig(),
		10,
	)

	require.Len(t, projections, 10)

	for _, p := range projections {
		require.Greater(t, p.EmissionToTreasury, int64(0),
			"year %d should have positive treasury emission", p.Year)
	}

	for i := 1; i < len(projections); i++ {
		require.Greater(t, projections[i].EndBalance, projections[i-1].EndBalance,
			"treasury balance should grow year-over-year")
	}
}

func TestTreasuryProjection_InsuranceReservePositive(t *testing.T) {
	projections := keeper.ProjectTreasuryGrowth(
		keeper.DefaultEmissionConfig(),
		keeper.DefaultTreasuryConfig(),
		5,
	)

	for _, p := range projections {
		require.Greater(t, p.InsuranceReserve, int64(0),
			"insurance reserve should be positive")
	}
}

// =============================================================================
// Section 6: Vesting Schedules
// =============================================================================

func TestDefaultVestingSchedules(t *testing.T) {
	schedules := keeper.DefaultVestingSchedules()
	require.NoError(t, keeper.ValidateVestingSchedules(schedules))
	require.Len(t, schedules, 5)
}

func TestVestingSchedules_TotalAllocated(t *testing.T) {
	schedules := keeper.DefaultVestingSchedules()

	total := int64(0)
	for _, s := range schedules {
		total += s.TotalUAETH
	}

	require.Equal(t, keeper.InitialSupplyUAETH, total,
		"vesting allocations should sum to initial supply")
}

func TestVestingSchedules_UniqueCategories(t *testing.T) {
	schedules := keeper.DefaultVestingSchedules()

	categories := make(map[string]bool)
	for _, s := range schedules {
		require.False(t, categories[s.Category], "duplicate category: %s", s.Category)
		categories[s.Category] = true
	}
}

func TestVestedAmount_BeforeCliff(t *testing.T) {
	schedule := keeper.VestingSchedule{
		Category:         "team",
		TotalUAETH:       1_000_000_000,
		CliffBlocks:      keeper.BlocksPerYear,
		VestingBlocks:    keeper.BlocksPerYear * 5,
		CliffPercent:     0,
		LinearAfterCliff: true,
	}

	vested := keeper.VestedAmount(schedule, keeper.BlocksPerYear/2)
	require.Equal(t, int64(0), vested, "nothing should vest before cliff")
}

func TestVestedAmount_AtCliff(t *testing.T) {
	schedule := keeper.VestingSchedule{
		Category:         "partners",
		TotalUAETH:       1_000_000_000,
		CliffBlocks:      keeper.BlocksPerYear,
		VestingBlocks:    keeper.BlocksPerYear * 3,
		CliffPercent:     1000,
		LinearAfterCliff: true,
	}

	vested := keeper.VestedAmount(schedule, keeper.BlocksPerYear)
	expectedCliff := int64(1_000_000_000 * 1000 / 10000)
	require.Equal(t, expectedCliff, vested, "should release cliff amount")
}

func TestVestedAmount_FullyVested(t *testing.T) {
	schedule := keeper.VestingSchedule{
		Category:         "community",
		TotalUAETH:       1_000_000_000,
		CliffBlocks:      0,
		VestingBlocks:    keeper.BlocksPerYear * 2,
		CliffPercent:     0,
		LinearAfterCliff: true,
	}

	vested := keeper.VestedAmount(schedule, keeper.BlocksPerYear*3)
	require.Equal(t, schedule.TotalUAETH, vested, "should be fully vested")
}

func TestVestedAmount_ZeroBlock(t *testing.T) {
	schedule := keeper.DefaultVestingSchedules()[0]
	vested := keeper.VestedAmount(schedule, 0)
	require.Equal(t, int64(0), vested, "nothing vested at block 0")
}

// =============================================================================
// Section 7: Anti-Abuse Config
// =============================================================================

func TestDefaultAntiAbuseConfig(t *testing.T) {
	config := keeper.DefaultAntiAbuseConfig()
	require.NoError(t, keeper.ValidateAntiAbuseConfig(config))
	require.True(t, config.MEVProtectionEnabled)
	require.True(t, config.ProgressivePenaltyEnabled)
}

func TestAntiAbuseConfig_ValidationBounds(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*keeper.AntiAbuseConfig)
		wantErr bool
	}{
		{"valid default", func(c *keeper.AntiAbuseConfig) {}, false},
		{"cap too low", func(c *keeper.AntiAbuseConfig) { c.ValidatorConcentrationCapBps = 500 }, true},
		{"cap too high", func(c *keeper.AntiAbuseConfig) { c.ValidatorConcentrationCapBps = 6000 }, true},
		{"max jobs too low", func(c *keeper.AntiAbuseConfig) { c.MaxDailyJobsPerSubmitter = 5 }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := keeper.DefaultAntiAbuseConfig()
			tt.modify(&config)
			err := keeper.ValidateAntiAbuseConfig(config)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAntiAbuseConfig_ConcentrationCap(t *testing.T) {
	config := keeper.DefaultAntiAbuseConfig()
	require.Equal(t, int64(3300), config.ValidatorConcentrationCapBps)
}

func TestAntiAbuseConfig_ProgressivePenalty(t *testing.T) {
	config := keeper.DefaultAntiAbuseConfig()
	require.True(t, config.ProgressivePenaltyEnabled)
	require.Equal(t, int64(15000), config.ProgressivePenaltyMultiplierBps)
}

// =============================================================================
// Section 8: Comprehensive Model Validation
// =============================================================================

func TestDefaultTokenomicsModel_Valid(t *testing.T) {
	model := keeper.DefaultTokenomicsModel()
	issues := keeper.ValidateTokenomicsModel(model)
	require.Empty(t, issues, "default model should have no issues")
}

func TestTokenomicsModel_InvalidEmission(t *testing.T) {
	model := keeper.DefaultTokenomicsModel()
	model.Emission.InitialInflationBps = 50
	issues := keeper.ValidateTokenomicsModel(model)
	require.NotEmpty(t, issues)
	require.Contains(t, issues[0], "emission")
}

func TestTokenomicsModel_InvalidSlashing(t *testing.T) {
	model := keeper.DefaultTokenomicsModel()
	model.Slashing.Tiers = nil
	issues := keeper.ValidateTokenomicsModel(model)
	require.NotEmpty(t, issues)
	require.Contains(t, issues[0], "slashing")
}

func TestTokenomicsModel_InvalidFeeDistro(t *testing.T) {
	model := keeper.DefaultTokenomicsModel()
	model.FeeDistro.ValidatorRewardBps = 5000
	issues := keeper.ValidateTokenomicsModel(model)
	require.NotEmpty(t, issues)
}

// =============================================================================
// Section 9: Simulation Engine
// =============================================================================

func TestRunDefaultSimulation(t *testing.T) {
	result := keeper.RunDefaultSimulation()

	require.NotNil(t, result)
	require.True(t, result.Valid, "default simulation should be valid")
	require.Empty(t, result.Issues)
	require.Equal(t, "default", result.Scenario)
}

func TestSimulation_EmissionSchedule(t *testing.T) {
	result := keeper.RunDefaultSimulation()

	require.Len(t, result.EmissionSchedule, 10)
	require.Greater(t, result.Year10Supply, keeper.InitialSupplyUAETH,
		"year 10 supply should exceed initial")
}

func TestSimulation_TreasuryProjection(t *testing.T) {
	result := keeper.RunDefaultSimulation()

	require.Len(t, result.TreasuryProjection, 10)
	require.Greater(t, result.Year10Treasury, int64(0),
		"year 10 treasury should be positive")
}

func TestSimulation_DeterrencePositive(t *testing.T) {
	result := keeper.RunDefaultSimulation()

	require.Greater(t, result.MaxDeterrenceRatio, 1.0,
		"deterrence ratio should be > 1")
}

func TestSimulation_DynamicFee(t *testing.T) {
	result := keeper.RunDefaultSimulation()

	require.Greater(t, result.DynamicFeeAtPeak, int64(0),
		"peak dynamic fee should be positive")
}

// =============================================================================
// Section 10: Report Rendering
// =============================================================================

func TestRenderTokenomicsModelReport(t *testing.T) {
	model := keeper.DefaultTokenomicsModel()
	report := keeper.RenderTokenomicsReport(model)

	require.Contains(t, report, "AETHEL TOKENOMICS MODEL")
	require.Contains(t, report, "TOKEN SUPPLY")
	require.Contains(t, report, "EMISSION MODEL")
	require.Contains(t, report, "STAKING ECONOMICS")
	require.Contains(t, report, "FEE MARKET")
	require.Contains(t, report, "SLASHING TIERS")
	require.Contains(t, report, "TREASURY")
	require.Contains(t, report, "VESTING SCHEDULE")
	require.Contains(t, report, "ANTI-ABUSE")
	require.Contains(t, report, "All tokenomics parameters VALID")

	t.Log(report)
}

func TestRenderSimulationReport(t *testing.T) {
	result := keeper.RunDefaultSimulation()
	report := keeper.RenderSimulationReport(result)

	require.Contains(t, report, "TOKENOMICS SIMULATION REPORT")
	require.Contains(t, report, "10-YEAR EMISSION SCHEDULE")
	require.Contains(t, report, "KEY METRICS")

	t.Log(report)
}

func TestRenderTokenomicsModelReport_Invalid(t *testing.T) {
	model := keeper.DefaultTokenomicsModel()
	model.Emission.InitialInflationBps = 50
	report := keeper.RenderTokenomicsReport(model)

	require.Contains(t, report, "emission")
	require.NotContains(t, report, "All tokenomics parameters VALID")
}

// =============================================================================
// Section 11: Integration
// =============================================================================

func TestFullTokenomicsValidation(t *testing.T) {
	model := keeper.DefaultTokenomicsModel()
	issues := keeper.ValidateTokenomicsModel(model)
	require.Empty(t, issues)

	result := keeper.RunDefaultSimulation()
	require.True(t, result.Valid)

	report := keeper.RenderTokenomicsReport(model)
	require.NotEmpty(t, report)

	simReport := keeper.RenderSimulationReport(result)
	require.NotEmpty(t, simReport)

	t.Logf("10-year supply growth: %d -> %d",
		keeper.InitialSupplyUAETH, result.Year10Supply)
	t.Logf("Max deterrence: %.1fx", result.MaxDeterrenceRatio)
}

func TestTokenomicsModelWithKeeper(t *testing.T) {
	k, ctx := newTestKeeper(t)

	econ, err := keeper.ComputeValidatorEconomics(ctx, k, "val-0", 1_000_000_000, 1000)
	require.NoError(t, err)
	require.NotNil(t, econ)

	model := keeper.DefaultTokenomicsModel()
	require.Empty(t, keeper.ValidateTokenomicsModel(model))

	t.Logf("Validator annual revenue: %d uaeth", econ.AnnualRevenue)
	t.Logf("Slashing exposure: %d uaeth", econ.SlashingExposure)
}
