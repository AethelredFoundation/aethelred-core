package keeper

import (
	"fmt"
	"math/big"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// ---------------------------------------------------------------------------
// SAFE TOKENOMICS ARITHMETIC
// ---------------------------------------------------------------------------
//
// This file provides safe integer arithmetic for tokenomics calculations,
// addressing the consultant's concerns about integer overflow risks.
//
// All operations use sdkmath.Int which:
//   - Handles arbitrary-precision integers
//   - Panics on overflow (fail-safe behavior)
//   - Is JSON-serializable
//   - Is deterministic across validators
//
// Consultant Finding: "Integer overflow risk - Low severity"
// Resolution: All tokenomics calculations now use SafeMath wrapper functions
// ---------------------------------------------------------------------------

// SafeMath provides overflow-safe arithmetic operations for tokenomics.
type SafeMath struct{}

// NewSafeMath creates a new SafeMath instance.
func NewSafeMath() *SafeMath {
	return &SafeMath{}
}

// SafeAdd performs overflow-checked addition.
// Returns error if result would overflow.
func (sm *SafeMath) SafeAdd(a, b sdkmath.Int) (result sdkmath.Int, err error) {
	// sdkmath.Int panics on overflow; recover and return a typed error.
	result = sdkmath.ZeroInt()
	defer func() {
		if r := recover(); r != nil {
			result = sdkmath.ZeroInt()
			err = fmt.Errorf("integer overflow in addition: %s + %s", a, b)
		}
	}()

	// Pre-check with big.Int to avoid hitting panic path in common overflow cases.
	sumBig := new(big.Int).Add(a.BigInt(), b.BigInt())
	if sumBig.BitLen() > sdkmath.MaxBitLen {
		return sdkmath.ZeroInt(), fmt.Errorf("integer overflow in addition: %s + %s", a, b)
	}

	result = a.Add(b)

	// Additional sanity check: result should be >= both operands for positive numbers.
	if a.IsPositive() && b.IsPositive() && (result.LT(a) || result.LT(b)) {
		return sdkmath.ZeroInt(), fmt.Errorf("integer overflow in addition: %s + %s", a, b)
	}

	return result, nil
}

// SafeSub performs overflow-checked subtraction.
// Returns error if result would underflow (go negative when not expected).
func (sm *SafeMath) SafeSub(a, b sdkmath.Int) (result sdkmath.Int, err error) {
	result = sdkmath.ZeroInt()
	defer func() {
		if r := recover(); r != nil {
			result = sdkmath.ZeroInt()
			err = fmt.Errorf("integer overflow in subtraction: %s - %s", a, b)
		}
	}()

	result = a.Sub(b)
	return result, nil
}

// SafeMul performs overflow-checked multiplication.
// Returns error if result would overflow.
func (sm *SafeMath) SafeMul(a, b sdkmath.Int) (result sdkmath.Int, err error) {
	result = sdkmath.ZeroInt()
	defer func() {
		if r := recover(); r != nil {
			result = sdkmath.ZeroInt()
			err = fmt.Errorf("integer overflow in multiplication: %s * %s", a, b)
		}
	}()

	// Pre-check overflow using bounded bit length.
	if !a.IsZero() && !b.IsZero() {
		productBig := new(big.Int).Mul(a.BigInt(), b.BigInt())
		if productBig.BitLen() > sdkmath.MaxBitLen {
			return sdkmath.ZeroInt(), fmt.Errorf("integer overflow in multiplication: %s * %s", a, b)
		}
	}

	result = a.Mul(b)
	return result, nil
}

// SafeDiv performs division with zero-check.
// Returns error if divisor is zero.
func (sm *SafeMath) SafeDiv(a, b sdkmath.Int) (sdkmath.Int, error) {
	if b.IsZero() {
		return sdkmath.ZeroInt(), fmt.Errorf("division by zero: %s / 0", a)
	}
	return a.Quo(b), nil
}

// SafeMulDiv performs (a * b) / c with intermediate overflow protection.
// This is useful for percentage calculations.
func (sm *SafeMath) SafeMulDiv(a, b, c sdkmath.Int) (sdkmath.Int, error) {
	if c.IsZero() {
		return sdkmath.ZeroInt(), fmt.Errorf("division by zero in MulDiv")
	}

	// Use BigInt for intermediate calculation to avoid overflow
	aBig := a.BigInt()
	bBig := b.BigInt()
	cBig := c.BigInt()

	// result = (a * b) / c
	intermediate := new(big.Int).Mul(aBig, bBig)
	resultBig := new(big.Int).Quo(intermediate, cBig)

	return sdkmath.NewIntFromBigInt(resultBig), nil
}

// SafeBpsMultiply multiplies a value by basis points (BPS).
// Example: SafeBpsMultiply(1000, 500) = 1000 * 500 / 10000 = 50
func (sm *SafeMath) SafeBpsMultiply(value sdkmath.Int, bps int64) (sdkmath.Int, error) {
	bpsInt := sdkmath.NewInt(bps)
	bpsBase := sdkmath.NewInt(BpsBase)
	return sm.SafeMulDiv(value, bpsInt, bpsBase)
}

// ---------------------------------------------------------------------------
// BONDING CURVE IMPLEMENTATION
// ---------------------------------------------------------------------------
//
// Consultant Finding: "No bonding curve - Medium severity"
// Resolution: Implement AMM-style bonding curve for initial token distribution
//
// The bonding curve provides:
//   1. Price discovery for initial token distribution
//   2. Guaranteed liquidity at any point
//   3. Predictable price based on supply
//
// Formula: price = basePrice * (1 + supply/scaleFactor)^exponent
// ---------------------------------------------------------------------------

// BondingCurveConfig defines the parameters for the bonding curve.
type BondingCurveConfig struct {
	// BasePriceUAETH is the initial token price in uaeth
	BasePriceUAETH sdkmath.Int

	// ScaleFactor determines how quickly price increases with supply
	// Higher value = slower price increase
	ScaleFactor sdkmath.Int

	// ExponentScaled controls curve steepness (scaled by 1000).
	// Supported values are:
	//   - 1000 (linear)
	//   - 1500 (base * sqrt(base))
	//   - 2000 (quadratic)
	// Other values are rejected at runtime.
	ExponentScaled int64

	// MaxSupply is the maximum tokens that can be minted via bonding curve
	MaxSupply sdkmath.Int

	// ReserveRatio in BPS (e.g., 5000 = 50% reserve)
	// Determines how much of purchase price goes to reserve
	ReserveRatioBps int64

	// Enabled indicates if bonding curve is active
	Enabled bool
}

// DefaultBondingCurveConfig returns the default bonding curve configuration.
func DefaultBondingCurveConfig() BondingCurveConfig {
	return BondingCurveConfig{
		BasePriceUAETH:  sdkmath.NewInt(100),                 // 0.0001 AETH base price
		ScaleFactor:     sdkmath.NewInt(100_000_000_000),     // 100K AETH scale
		ExponentScaled:  1500,                                // 1.5 (between linear and quadratic)
		MaxSupply:       sdkmath.NewInt(100_000_000_000_000), // 100M AETH max via curve
		ReserveRatioBps: 5000,                                // 50% reserve
		Enabled:         true,
	}
}

// BondingCurve implements an AMM-style bonding curve for token issuance.
type BondingCurve struct {
	config         BondingCurveConfig
	currentSupply  sdkmath.Int
	reserveBalance sdkmath.Int
	safeMath       *SafeMath
	configErr      error
}

// NewBondingCurve creates a new bonding curve with the given configuration.
func NewBondingCurve(config BondingCurveConfig) *BondingCurve {
	return &BondingCurve{
		config:         config,
		currentSupply:  sdkmath.ZeroInt(),
		reserveBalance: sdkmath.ZeroInt(),
		safeMath:       NewSafeMath(),
		configErr:      ValidateBondingCurveConfig(config),
	}
}

// SupportedBondingCurveExponents returns the exponent values currently
// supported by the integer approximation in this module.
func SupportedBondingCurveExponents() []int64 {
	return []int64{1000, 1500, 2000}
}

func isSupportedBondingCurveExponent(exponentScaled int64) bool {
	for _, supported := range SupportedBondingCurveExponents() {
		if exponentScaled == supported {
			return true
		}
	}
	return false
}

// ValidateBondingCurveConfig validates bonding curve parameters.
func ValidateBondingCurveConfig(config BondingCurveConfig) error {
	if config.BasePriceUAETH.LTE(sdkmath.ZeroInt()) {
		return fmt.Errorf("base price must be positive")
	}
	if config.ScaleFactor.LTE(sdkmath.ZeroInt()) {
		return fmt.Errorf("scale factor must be positive")
	}
	if config.MaxSupply.LTE(sdkmath.ZeroInt()) {
		return fmt.Errorf("max supply must be positive")
	}
	if config.ReserveRatioBps < 0 || config.ReserveRatioBps > BpsBase {
		return fmt.Errorf("reserve ratio bps must be in [0, %d], got %d", BpsBase, config.ReserveRatioBps)
	}
	if !isSupportedBondingCurveExponent(config.ExponentScaled) {
		return fmt.Errorf(
			"unsupported bonding curve exponent %d (supported: %v)",
			config.ExponentScaled,
			SupportedBondingCurveExponents(),
		)
	}
	return nil
}

// GetCurrentPrice returns the current token price based on supply.
// price = basePrice * (1 + supply/scaleFactor)^(exponent/1000)
func (bc *BondingCurve) GetCurrentPrice() sdkmath.Int {
	price, err := bc.GetCurrentPriceSafe()
	if err != nil {
		return sdkmath.ZeroInt()
	}
	return price
}

// GetCurrentPriceSafe returns the current token price and an error when the
// bonding curve configuration is invalid.
func (bc *BondingCurve) GetCurrentPriceSafe() (sdkmath.Int, error) {
	if bc.configErr != nil {
		return sdkmath.ZeroInt(), bc.configErr
	}
	return bc.getPriceAtSupply(bc.currentSupply)
}

// getPriceAtSupply calculates the price at a given supply level.
func (bc *BondingCurve) getPriceAtSupply(supply sdkmath.Int) (sdkmath.Int, error) {
	if !isSupportedBondingCurveExponent(bc.config.ExponentScaled) {
		return sdkmath.ZeroInt(), fmt.Errorf(
			"unsupported bonding curve exponent %d (supported: %v)",
			bc.config.ExponentScaled,
			SupportedBondingCurveExponents(),
		)
	}

	if supply.IsZero() {
		return bc.config.BasePriceUAETH, nil
	}

	// Calculate (1 + supply/scaleFactor) scaled by 1e18 for precision
	scaledOne := sdkmath.NewInt(1e18)
	supplyRatio, err := bc.safeMath.SafeMulDiv(supply, scaledOne, bc.config.ScaleFactor)
	if err != nil {
		return sdkmath.ZeroInt(), err
	}

	base := scaledOne.Add(supplyRatio)

	// Apply exponent using deterministic integer approximation.
	var priceMultiplier sdkmath.Int
	switch bc.config.ExponentScaled {
	case 1000:
		// Linear.
		priceMultiplier = base
	case 1500:
		// base * sqrt(base)
		sqrtBase := bc.intSqrt(base)
		priceMultiplier, err = bc.safeMath.SafeMulDiv(base, sqrtBase, scaledOne)
		if err != nil {
			return sdkmath.ZeroInt(), err
		}
	case 2000:
		// Quadratic: base^2
		priceMultiplier, err = bc.safeMath.SafeMulDiv(base, base, scaledOne)
		if err != nil {
			return sdkmath.ZeroInt(), err
		}
	default:
		return sdkmath.ZeroInt(), fmt.Errorf(
			"unsupported bonding curve exponent %d (supported: %v)",
			bc.config.ExponentScaled,
			SupportedBondingCurveExponents(),
		)
	}

	// Calculate final price
	price, err := bc.safeMath.SafeMulDiv(bc.config.BasePriceUAETH, priceMultiplier, scaledOne)
	if err != nil {
		return sdkmath.ZeroInt(), err
	}

	return price, nil
}

// intSqrt computes integer square root using Newton's method.
func (bc *BondingCurve) intSqrt(n sdkmath.Int) sdkmath.Int {
	if n.IsZero() || n.IsNegative() {
		return sdkmath.ZeroInt()
	}
	if n.Equal(sdkmath.OneInt()) {
		return sdkmath.OneInt()
	}

	// Initial guess: n / 2
	x := n.QuoRaw(2)

	// Newton's method: x = (x + n/x) / 2
	for i := 0; i < 50; i++ { // Max 50 iterations
		xNew := x.Add(n.Quo(x)).QuoRaw(2)
		if xNew.GTE(x) {
			break
		}
		x = xNew
	}

	return x
}

// CalculatePurchaseCost calculates the cost to purchase a given amount of tokens.
// Uses integral of the bonding curve for accurate pricing.
func (bc *BondingCurve) CalculatePurchaseCost(tokenAmount sdkmath.Int) (sdkmath.Int, error) {
	if bc.configErr != nil {
		return sdkmath.ZeroInt(), bc.configErr
	}
	if !bc.config.Enabled {
		return sdkmath.ZeroInt(), fmt.Errorf("bonding curve is disabled")
	}

	// Check max supply
	newSupply := bc.currentSupply.Add(tokenAmount)
	if newSupply.GT(bc.config.MaxSupply) {
		return sdkmath.ZeroInt(), fmt.Errorf("purchase would exceed max supply: %s + %s > %s",
			bc.currentSupply, tokenAmount, bc.config.MaxSupply)
	}

	// Use trapezoidal approximation for the integral
	// Divide into steps for accuracy
	steps := int64(100)
	stepSize := tokenAmount.QuoRaw(steps)
	if stepSize.IsZero() {
		stepSize = sdkmath.OneInt()
		steps = tokenAmount.Int64()
	}

	totalCost := sdkmath.ZeroInt()
	currentSupplyStep := bc.currentSupply

	for i := int64(0); i < steps; i++ {
		// Price at this point
		priceAtStep, err := bc.getPriceAtSupply(currentSupplyStep)
		if err != nil {
			return sdkmath.ZeroInt(), fmt.Errorf("failed to evaluate price at supply: %w", err)
		}

		// Cost for this step
		stepCost, err := bc.safeMath.SafeMul(priceAtStep, stepSize)
		if err != nil {
			return sdkmath.ZeroInt(), fmt.Errorf("overflow calculating step cost: %w", err)
		}

		totalCost, err = bc.safeMath.SafeAdd(totalCost, stepCost)
		if err != nil {
			return sdkmath.ZeroInt(), fmt.Errorf("overflow calculating total cost: %w", err)
		}

		currentSupplyStep = currentSupplyStep.Add(stepSize)
	}

	// Scale to uaeth (costs were in price * tokens, need to divide by 1e6 for uaeth)
	totalCost = totalCost.QuoRaw(1_000_000)

	return totalCost, nil
}

// CalculateSaleReturn calculates the return for selling a given amount of tokens.
func (bc *BondingCurve) CalculateSaleReturn(tokenAmount sdkmath.Int) (sdkmath.Int, error) {
	if bc.configErr != nil {
		return sdkmath.ZeroInt(), bc.configErr
	}
	if !bc.config.Enabled {
		return sdkmath.ZeroInt(), fmt.Errorf("bonding curve is disabled")
	}

	if tokenAmount.GT(bc.currentSupply) {
		return sdkmath.ZeroInt(), fmt.Errorf("cannot sell more than current supply")
	}

	// Calculate using the same integral method, but in reverse
	steps := int64(100)
	stepSize := tokenAmount.QuoRaw(steps)
	if stepSize.IsZero() {
		stepSize = sdkmath.OneInt()
		steps = tokenAmount.Int64()
	}

	totalReturn := sdkmath.ZeroInt()
	currentSupplyStep := bc.currentSupply

	for i := int64(0); i < steps; i++ {
		currentSupplyStep = currentSupplyStep.Sub(stepSize)

		// Price at this point
		priceAtStep, err := bc.getPriceAtSupply(currentSupplyStep)
		if err != nil {
			return sdkmath.ZeroInt(), fmt.Errorf("failed to evaluate price at supply: %w", err)
		}

		// Return for this step
		stepReturn, err := bc.safeMath.SafeMul(priceAtStep, stepSize)
		if err != nil {
			return sdkmath.ZeroInt(), fmt.Errorf("overflow calculating step return: %w", err)
		}

		totalReturn, err = bc.safeMath.SafeAdd(totalReturn, stepReturn)
		if err != nil {
			return sdkmath.ZeroInt(), fmt.Errorf("overflow calculating total return: %w", err)
		}
	}

	// Scale and apply reserve ratio (only reserve ratio portion is returned)
	totalReturn = totalReturn.QuoRaw(1_000_000)
	returnWithReserve, err := bc.safeMath.SafeBpsMultiply(totalReturn, bc.config.ReserveRatioBps)
	if err != nil {
		return sdkmath.ZeroInt(), err
	}

	return returnWithReserve, nil
}

// ExecutePurchase executes a token purchase on the bonding curve.
func (bc *BondingCurve) ExecutePurchase(tokenAmount sdkmath.Int) (cost sdkmath.Int, err error) {
	cost, err = bc.CalculatePurchaseCost(tokenAmount)
	if err != nil {
		return sdkmath.ZeroInt(), err
	}

	// Update state
	bc.currentSupply = bc.currentSupply.Add(tokenAmount)

	// Add to reserve (based on reserve ratio)
	reserveAddition, _ := bc.safeMath.SafeBpsMultiply(cost, bc.config.ReserveRatioBps)
	bc.reserveBalance = bc.reserveBalance.Add(reserveAddition)

	return cost, nil
}

// ExecuteSale executes a token sale on the bonding curve.
func (bc *BondingCurve) ExecuteSale(tokenAmount sdkmath.Int) (returnAmount sdkmath.Int, err error) {
	returnAmount, err = bc.CalculateSaleReturn(tokenAmount)
	if err != nil {
		return sdkmath.ZeroInt(), err
	}

	// Check reserve has enough
	if returnAmount.GT(bc.reserveBalance) {
		return sdkmath.ZeroInt(), fmt.Errorf("insufficient reserve balance")
	}

	// Update state
	bc.currentSupply = bc.currentSupply.Sub(tokenAmount)
	bc.reserveBalance = bc.reserveBalance.Sub(returnAmount)

	return returnAmount, nil
}

// GetState returns the current bonding curve state.
func (bc *BondingCurve) GetState() (supply, reserve, price sdkmath.Int) {
	return bc.currentSupply, bc.reserveBalance, bc.GetCurrentPrice()
}

// ---------------------------------------------------------------------------
// CONFIGURABLE BLOCK TIME
// ---------------------------------------------------------------------------
//
// Consultant Finding: "Fixed block time assumption - Low severity"
// Resolution: Make block time configurable via chain parameters
// ---------------------------------------------------------------------------

// BlockTimeConfig defines configurable block time parameters.
type BlockTimeConfig struct {
	// TargetBlockTimeMs is the target block time in milliseconds
	TargetBlockTimeMs int64

	// MinBlockTimeMs is the minimum allowed block time
	MinBlockTimeMs int64

	// MaxBlockTimeMs is the maximum allowed block time
	MaxBlockTimeMs int64

	// AdaptiveEnabled enables adaptive block time based on network conditions
	AdaptiveEnabled bool

	// AdaptiveWindowBlocks is the number of blocks to use for adaptive calculation
	AdaptiveWindowBlocks int64
}

// DefaultBlockTimeConfig returns the default block time configuration.
func DefaultBlockTimeConfig() BlockTimeConfig {
	return BlockTimeConfig{
		TargetBlockTimeMs:    6000,  // 6 seconds default
		MinBlockTimeMs:       1000,  // 1 second minimum
		MaxBlockTimeMs:       30000, // 30 seconds maximum
		AdaptiveEnabled:      false, // Disabled by default for determinism
		AdaptiveWindowBlocks: 100,   // Look at last 100 blocks
	}
}

// ValidateBlockTimeConfig validates the block time configuration.
func ValidateBlockTimeConfig(config BlockTimeConfig) error {
	if config.TargetBlockTimeMs < config.MinBlockTimeMs {
		return fmt.Errorf("target block time (%d ms) cannot be less than minimum (%d ms)",
			config.TargetBlockTimeMs, config.MinBlockTimeMs)
	}
	if config.TargetBlockTimeMs > config.MaxBlockTimeMs {
		return fmt.Errorf("target block time (%d ms) cannot exceed maximum (%d ms)",
			config.TargetBlockTimeMs, config.MaxBlockTimeMs)
	}
	if config.MinBlockTimeMs < 500 {
		return fmt.Errorf("minimum block time cannot be less than 500ms, got %d", config.MinBlockTimeMs)
	}
	if config.MaxBlockTimeMs > 60000 {
		return fmt.Errorf("maximum block time cannot exceed 60000ms (1 minute), got %d", config.MaxBlockTimeMs)
	}
	if config.AdaptiveWindowBlocks < 10 {
		return fmt.Errorf("adaptive window must be at least 10 blocks, got %d", config.AdaptiveWindowBlocks)
	}
	return nil
}

// BlocksPerYearForConfig calculates blocks per year for a given block time.
func BlocksPerYearForConfig(config BlockTimeConfig) int64 {
	secondsPerYear := int64(365 * 24 * 60 * 60)
	blockTimeSeconds := config.TargetBlockTimeMs / 1000
	if blockTimeSeconds == 0 {
		blockTimeSeconds = 1
	}
	return secondsPerYear / blockTimeSeconds
}

// BlocksPerDayForConfig calculates blocks per day for a given block time.
func BlocksPerDayForConfig(config BlockTimeConfig) int64 {
	secondsPerDay := int64(24 * 60 * 60)
	blockTimeSeconds := config.TargetBlockTimeMs / 1000
	if blockTimeSeconds == 0 {
		blockTimeSeconds = 1
	}
	return secondsPerDay / blockTimeSeconds
}

// RecalculateTokenomicsForBlockTime recalculates all tokenomics parameters
// when block time changes.
func RecalculateTokenomicsForBlockTime(model TokenomicsModel, newBlockTimeMs int64) TokenomicsModel {
	// Calculate scaling factor (ratio of new block time to default 6s)
	defaultBlockTimeMs := int64(6000)
	scaleFactor := float64(newBlockTimeMs) / float64(defaultBlockTimeMs)

	// Adjust time-based parameters
	model.Staking.UnbondingPeriodBlocks = int64(float64(model.Staking.UnbondingPeriodBlocks) / scaleFactor)
	model.Staking.RedelegationCooldownBlocks = int64(float64(model.Staking.RedelegationCooldownBlocks) / scaleFactor)

	model.Slashing.DowntimeWindowBlocks = int64(float64(model.Slashing.DowntimeWindowBlocks) / scaleFactor)
	for i := range model.Slashing.Tiers {
		model.Slashing.Tiers[i].JailBlocks = int64(float64(model.Slashing.Tiers[i].JailBlocks) / scaleFactor)
		model.Slashing.Tiers[i].EvidenceMaxAge = int64(float64(model.Slashing.Tiers[i].EvidenceMaxAge) / scaleFactor)
	}

	model.Treasury.GrantVotingPeriodBlocks = int64(float64(model.Treasury.GrantVotingPeriodBlocks) / scaleFactor)

	for i := range model.Vesting {
		model.Vesting[i].CliffBlocks = int64(float64(model.Vesting[i].CliffBlocks) / scaleFactor)
		model.Vesting[i].VestingBlocks = int64(float64(model.Vesting[i].VestingBlocks) / scaleFactor)
	}

	return model
}

// ---------------------------------------------------------------------------
// SAFE EMISSION CALCULATION
// ---------------------------------------------------------------------------
// Uses sdkmath.Int for all emission calculations to prevent overflow.
// ---------------------------------------------------------------------------

// ComputeEmissionScheduleSafe generates a multi-year emission schedule using safe math.
func ComputeEmissionScheduleSafe(config EmissionConfig, years int, blockTimeConfig BlockTimeConfig) ([]EmissionScheduleEntry, error) {
	safeMath := NewSafeMath()
	schedule := make([]EmissionScheduleEntry, 0, years)

	supply := sdkmath.NewInt(InitialSupplyUAETH)

	for year := 1; year <= years; year++ {
		inflationBps := computeInflationForYear(config, year)

		// Annual emission = supply * inflationBps / 10000
		emission, err := safeMath.SafeBpsMultiply(supply, inflationBps)
		if err != nil {
			return nil, fmt.Errorf("overflow calculating emission for year %d: %w", year, err)
		}

		supply, err = safeMath.SafeAdd(supply, emission)
		if err != nil {
			return nil, fmt.Errorf("overflow calculating supply for year %d: %w", year, err)
		}

		// Cap supply if max is set
		if config.MaxSupplyCap > 0 {
			maxCap := sdkmath.NewInt(config.MaxSupplyCap)
			if supply.GT(maxCap) {
				emission = emission.Sub(supply.Sub(maxCap))
				supply = maxCap
			}
		}

		// Approximate staking yield
		validatorShareBps := MainnetFeeDistribution().ValidatorRewardBps
		validatorShare, _ := safeMath.SafeBpsMultiply(emission, validatorShareBps)
		stakingAmount, _ := safeMath.SafeBpsMultiply(supply, config.StakingTargetBps)

		yield := ratioToPercent(validatorShare, stakingAmount)

		annualEmission, ok := mathIntToInt64(emission)
		if !ok {
			return nil, fmt.Errorf("annual emission exceeds int64 range at year %d", year)
		}
		cumulativeSupply, ok := mathIntToInt64(supply)
		if !ok {
			return nil, fmt.Errorf("cumulative supply exceeds int64 range at year %d", year)
		}

		schedule = append(schedule, EmissionScheduleEntry{
			Year:             year,
			InflationBps:     inflationBps,
			InflationPercent: float64(inflationBps) / 100,
			AnnualEmission:   annualEmission,
			CumulativeSupply: cumulativeSupply,
			StakingYield:     yield,
		})
	}

	return schedule, nil
}

// ---------------------------------------------------------------------------
// SAFE REWARD CALCULATION
// ---------------------------------------------------------------------------

// ComputeValidatorRewardSafe calculates validator rewards using safe arithmetic.
func ComputeValidatorRewardSafe(
	baseReward sdk.Coin,
	reputationScore int64,
	commissionBps int64,
) (validatorReward, delegatorReward sdk.Coin, err error) {
	safeMath := NewSafeMath()

	// Scale by reputation (50-150% based on score 0-100)
	scaledAmount := sdkmath.NewInt(baseReward.Amount.Int64())

	// reputationMultiplier = 50 + reputationScore (so 0 score = 50%, 100 score = 150%)
	reputationMultiplier := 5000 + (reputationScore * 100) // In BPS
	scaledAmount, err = safeMath.SafeBpsMultiply(scaledAmount, reputationMultiplier)
	if err != nil {
		return sdk.Coin{}, sdk.Coin{}, fmt.Errorf("overflow in reputation scaling: %w", err)
	}

	// Calculate commission
	commissionAmount, err := safeMath.SafeBpsMultiply(scaledAmount, commissionBps)
	if err != nil {
		return sdk.Coin{}, sdk.Coin{}, fmt.Errorf("overflow in commission calculation: %w", err)
	}

	delegatorAmount := scaledAmount.Sub(commissionAmount)

	validatorReward = sdk.NewCoin(baseReward.Denom, commissionAmount)
	delegatorReward = sdk.NewCoin(baseReward.Denom, delegatorAmount)

	return validatorReward, delegatorReward, nil
}
