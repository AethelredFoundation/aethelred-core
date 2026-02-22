package keeper

import (
	"context"
	"testing"
	"time"

	"cosmossdk.io/log"
	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	slashingtypes "github.com/cosmos/cosmos-sdk/x/slashing/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

// =============================================================================
// Mock Implementations for Testing
// =============================================================================

type mockStakingKeeper struct {
	validators map[string]stakingtypes.Validator
	powers     map[string]int64
	jailed     map[string]bool
	slashed    map[string]sdkmath.Int
}

func newMockStakingKeeper() *mockStakingKeeper {
	return &mockStakingKeeper{
		validators: make(map[string]stakingtypes.Validator),
		powers:     make(map[string]int64),
		jailed:     make(map[string]bool),
		slashed:    make(map[string]sdkmath.Int),
	}
}

func (m *mockStakingKeeper) GetValidator(ctx sdk.Context, addr sdk.ValAddress) (stakingtypes.Validator, error) {
	if v, ok := m.validators[addr.String()]; ok {
		return v, nil
	}
	return stakingtypes.Validator{}, stakingtypes.ErrNoValidatorFound
}

func (m *mockStakingKeeper) GetValidatorByConsAddr(ctx sdk.Context, consAddr sdk.ConsAddress) (stakingtypes.Validator, error) {
	if v, ok := m.validators[consAddr.String()]; ok {
		return v, nil
	}
	return stakingtypes.Validator{}, stakingtypes.ErrNoValidatorFound
}

func (m *mockStakingKeeper) Slash(ctx sdk.Context, consAddr sdk.ConsAddress, infractionHeight int64, power int64, slashFactor sdkmath.LegacyDec) (sdkmath.Int, error) {
	slashAmount := sdkmath.NewInt(power).Mul(sdkmath.NewIntFromBigInt(slashFactor.BigInt())).Quo(sdkmath.NewInt(10000))
	m.slashed[consAddr.String()] = slashAmount
	return slashAmount, nil
}

func (m *mockStakingKeeper) Jail(ctx sdk.Context, consAddr sdk.ConsAddress) error {
	m.jailed[consAddr.String()] = true
	return nil
}

func (m *mockStakingKeeper) Unjail(ctx sdk.Context, consAddr sdk.ConsAddress) error {
	m.jailed[consAddr.String()] = false
	return nil
}

func (m *mockStakingKeeper) GetLastValidatorPower(ctx sdk.Context, operator sdk.ValAddress) (int64, error) {
	if p, ok := m.powers[operator.String()]; ok {
		return p, nil
	}
	return 1000000, nil // Default power
}

func (m *mockStakingKeeper) GetAllValidators(ctx sdk.Context) ([]stakingtypes.Validator, error) {
	var validators []stakingtypes.Validator
	for _, v := range m.validators {
		validators = append(validators, v)
	}
	return validators, nil
}

func (m *mockStakingKeeper) Delegation(ctx sdk.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress) (stakingtypes.Delegation, error) {
	return stakingtypes.Delegation{}, nil
}

type mockSlashingKeeper struct {
	signingInfo map[string]slashingtypes.ValidatorSigningInfo
	tombstoned  map[string]bool
	jailUntil   map[string]time.Time
}

func newMockSlashingKeeper() *mockSlashingKeeper {
	return &mockSlashingKeeper{
		signingInfo: make(map[string]slashingtypes.ValidatorSigningInfo),
		tombstoned:  make(map[string]bool),
		jailUntil:   make(map[string]time.Time),
	}
}

func (m *mockSlashingKeeper) GetValidatorSigningInfo(ctx sdk.Context, address sdk.ConsAddress) (slashingtypes.ValidatorSigningInfo, error) {
	if info, ok := m.signingInfo[address.String()]; ok {
		return info, nil
	}
	return slashingtypes.ValidatorSigningInfo{}, nil
}

func (m *mockSlashingKeeper) SetValidatorSigningInfo(ctx sdk.Context, address sdk.ConsAddress, info slashingtypes.ValidatorSigningInfo) error {
	m.signingInfo[address.String()] = info
	return nil
}

func (m *mockSlashingKeeper) GetParams(ctx sdk.Context) (slashingtypes.Params, error) {
	return slashingtypes.DefaultParams(), nil
}

func (m *mockSlashingKeeper) JailUntil(ctx sdk.Context, consAddr sdk.ConsAddress, jailTime time.Time) error {
	m.jailUntil[consAddr.String()] = jailTime
	return nil
}

func (m *mockSlashingKeeper) Tombstone(ctx sdk.Context, consAddr sdk.ConsAddress) error {
	m.tombstoned[consAddr.String()] = true
	return nil
}

func (m *mockSlashingKeeper) IsTombstoned(ctx sdk.Context, consAddr sdk.ConsAddress) bool {
	return m.tombstoned[consAddr.String()]
}

type mockBankKeeper struct{}

func (m *mockBankKeeper) SendCoinsFromModuleToModule(ctx sdk.Context, senderModule, recipientModule string, amt sdk.Coins) error {
	return nil
}

func (m *mockBankKeeper) BurnCoins(ctx sdk.Context, moduleName string, amt sdk.Coins) error {
	return nil
}

type mockInsuranceKeeper struct {
	calls      int
	lastReason string
	lastAmount sdkmath.Int
}

func (m *mockInsuranceKeeper) EscrowFraudSlash(
	_ context.Context,
	_ string,
	amount sdkmath.Int,
	reason string,
	_ string,
) (string, error) {
	m.calls++
	m.lastReason = reason
	m.lastAmount = amount
	return "escrow-1", nil
}

// =============================================================================
// Tests
// =============================================================================

func TestSlashingModuleAdapter_SlashForDowntime(t *testing.T) {
	logger := log.NewNopLogger()
	stakingKeeper := newMockStakingKeeper()
	slashingKeeper := newMockSlashingKeeper()
	bankKeeper := &mockBankKeeper{}

	// Add a test validator
	consAddr := sdk.ConsAddress([]byte("test_validator_addr"))
	stakingKeeper.validators[consAddr.String()] = stakingtypes.Validator{}
	stakingKeeper.powers[consAddr.String()] = 1000000

	config := DefaultSlashingAdapterConfig()
	adapter := NewSlashingModuleAdapter(logger, stakingKeeper, slashingKeeper, bankKeeper, config)

	ctx := sdk.Context{}.WithBlockTime(time.Now())

	result, err := adapter.SlashForDowntime(ctx, consAddr, 500, 100)
	if err != nil {
		t.Fatalf("SlashForDowntime failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Reason != SlashReasonDowntime {
		t.Errorf("Expected reason %s, got %s", SlashReasonDowntime, result.Reason)
	}

	if !result.Jailed {
		t.Error("Expected validator to be jailed")
	}

	if result.SlashFractionBps != config.DowntimeSlashBps {
		t.Errorf("Expected slash fraction %d, got %d", config.DowntimeSlashBps, result.SlashFractionBps)
	}
}

func TestSlashingModuleAdapter_SlashForDoubleSign(t *testing.T) {
	logger := log.NewNopLogger()
	stakingKeeper := newMockStakingKeeper()
	slashingKeeper := newMockSlashingKeeper()
	bankKeeper := &mockBankKeeper{}

	consAddr := sdk.ConsAddress([]byte("double_sign_validator"))
	stakingKeeper.validators[consAddr.String()] = stakingtypes.Validator{}
	stakingKeeper.powers[consAddr.String()] = 1000000

	config := DefaultSlashingAdapterConfig()
	adapter := NewSlashingModuleAdapter(logger, stakingKeeper, slashingKeeper, bankKeeper, config)

	ctx := sdk.Context{}.WithBlockTime(time.Now())

	evidence := &EquivocationEvidence{
		ValidatorAddress: consAddr.String(),
		BlockHeight:      100,
	}

	result, err := adapter.SlashForDoubleSign(ctx, consAddr, 100, evidence)
	if err != nil {
		t.Fatalf("SlashForDoubleSign failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Reason != SlashReasonDoubleSign {
		t.Errorf("Expected reason %s, got %s", SlashReasonDoubleSign, result.Reason)
	}

	if !result.Tombstoned {
		t.Error("Expected validator to be tombstoned")
	}

	if result.SlashFractionBps != config.DoubleSignSlashBps {
		t.Errorf("Expected slash fraction %d, got %d", config.DoubleSignSlashBps, result.SlashFractionBps)
	}
}

func TestSlashingModuleAdapter_SlashForCollusion(t *testing.T) {
	logger := log.NewNopLogger()
	stakingKeeper := newMockStakingKeeper()
	slashingKeeper := newMockSlashingKeeper()
	bankKeeper := &mockBankKeeper{}

	// Add multiple colluding validators
	consAddrs := make([]sdk.ConsAddress, 3)
	for i := 0; i < 3; i++ {
		consAddrs[i] = sdk.ConsAddress([]byte(string(rune('A'+i)) + "_validator"))
		stakingKeeper.validators[consAddrs[i].String()] = stakingtypes.Validator{}
		stakingKeeper.powers[consAddrs[i].String()] = 1000000
	}

	config := DefaultSlashingAdapterConfig()
	adapter := NewSlashingModuleAdapter(logger, stakingKeeper, slashingKeeper, bankKeeper, config)

	ctx := sdk.Context{}.WithBlockTime(time.Now())

	results, err := adapter.SlashForCollusion(ctx, consAddrs, 100, "test collusion evidence")
	if err != nil {
		t.Fatalf("SlashForCollusion failed: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(results))
	}

	for _, result := range results {
		if result.Reason != SlashReasonCollusion {
			t.Errorf("Expected reason %s, got %s", SlashReasonCollusion, result.Reason)
		}

		if !result.Tombstoned {
			t.Error("Expected validator to be tombstoned for collusion")
		}

		if result.SlashFractionBps != config.CollusionSlashBps {
			t.Errorf("Expected 100%% slash, got %d bps", result.SlashFractionBps)
		}
	}
}

func TestSlashingModuleAdapter_EscrowsInvalidOutputFraudSlash(t *testing.T) {
	logger := log.NewNopLogger()
	stakingKeeper := newMockStakingKeeper()
	slashingKeeper := newMockSlashingKeeper()
	bankKeeper := &mockBankKeeper{}
	insuranceKeeper := &mockInsuranceKeeper{}

	consAddr := sdk.ConsAddress([]byte("invalid_output_validator"))
	operator := sdk.ValAddress([]byte("operator-1-addr")).String()
	stakingKeeper.validators[consAddr.String()] = stakingtypes.Validator{OperatorAddress: operator}
	stakingKeeper.powers[operator] = 1000000

	config := DefaultSlashingAdapterConfig()
	adapter := NewSlashingModuleAdapter(logger, stakingKeeper, slashingKeeper, bankKeeper, config)
	adapter.SetInsuranceEscrowKeeper(insuranceKeeper)

	ctx := sdk.Context{}.WithBlockTime(time.Now())

	_, err := adapter.SlashForInvalidOutput(ctx, consAddr, "job-1", 10)
	if err != nil {
		t.Fatalf("SlashForInvalidOutput failed: %v", err)
	}

	if insuranceKeeper.calls != 1 {
		t.Fatalf("expected insurance escrow to be called once, got %d", insuranceKeeper.calls)
	}
	if insuranceKeeper.lastReason != string(SlashReasonInvalidOutput) {
		t.Fatalf("expected reason %q, got %q", string(SlashReasonInvalidOutput), insuranceKeeper.lastReason)
	}
}

func TestSlashingModuleAdapter_EscrowsFakeAttestationFraudSlash(t *testing.T) {
	logger := log.NewNopLogger()
	stakingKeeper := newMockStakingKeeper()
	slashingKeeper := newMockSlashingKeeper()
	bankKeeper := &mockBankKeeper{}
	insuranceKeeper := &mockInsuranceKeeper{}

	consAddr := sdk.ConsAddress([]byte("fake_attestation_validator"))
	operator := sdk.ValAddress([]byte("operator-2-addr")).String()
	stakingKeeper.validators[consAddr.String()] = stakingtypes.Validator{OperatorAddress: operator}
	stakingKeeper.powers[operator] = 1000000

	config := DefaultSlashingAdapterConfig()
	adapter := NewSlashingModuleAdapter(logger, stakingKeeper, slashingKeeper, bankKeeper, config)
	adapter.SetInsuranceEscrowKeeper(insuranceKeeper)

	ctx := sdk.Context{}.WithBlockTime(time.Now())

	_, err := adapter.SlashForFakeAttestation(ctx, consAddr, 10, "pcr mismatch")
	if err != nil {
		t.Fatalf("SlashForFakeAttestation failed: %v", err)
	}

	if insuranceKeeper.calls != 1 {
		t.Fatalf("expected insurance escrow to be called once, got %d", insuranceKeeper.calls)
	}
	if insuranceKeeper.lastReason != string(SlashReasonFakeAttestation) {
		t.Fatalf("expected reason %q, got %q", string(SlashReasonFakeAttestation), insuranceKeeper.lastReason)
	}
}

func TestSlashingModuleAdapter_TombstonedValidatorCannotBeSlashed(t *testing.T) {
	logger := log.NewNopLogger()
	stakingKeeper := newMockStakingKeeper()
	slashingKeeper := newMockSlashingKeeper()
	bankKeeper := &mockBankKeeper{}

	consAddr := sdk.ConsAddress([]byte("tombstoned_validator"))
	stakingKeeper.validators[consAddr.String()] = stakingtypes.Validator{}
	slashingKeeper.tombstoned[consAddr.String()] = true

	config := DefaultSlashingAdapterConfig()
	adapter := NewSlashingModuleAdapter(logger, stakingKeeper, slashingKeeper, bankKeeper, config)

	ctx := sdk.Context{}.WithBlockTime(time.Now())

	_, err := adapter.SlashForDowntime(ctx, consAddr, 500, 100)
	if err == nil {
		t.Error("Expected error when slashing tombstoned validator")
	}
}

func TestDefaultSlashingAdapterConfig(t *testing.T) {
	config := DefaultSlashingAdapterConfig()

	// Verify default values are sane
	if config.DowntimeSlashBps != 500 {
		t.Errorf("Expected DowntimeSlashBps 500, got %d", config.DowntimeSlashBps)
	}

	if config.DoubleSignSlashBps != 5000 {
		t.Errorf("Expected DoubleSignSlashBps 5000, got %d", config.DoubleSignSlashBps)
	}

	if config.CollusionSlashBps != 10000 {
		t.Errorf("Expected CollusionSlashBps 10000, got %d", config.CollusionSlashBps)
	}

	if config.DowntimeJailDuration != 24*time.Hour {
		t.Errorf("Expected DowntimeJailDuration 24h, got %v", config.DowntimeJailDuration)
	}

	if config.DoubleSignJailDuration != 30*24*time.Hour {
		t.Errorf("Expected DoubleSignJailDuration 30 days, got %v", config.DoubleSignJailDuration)
	}
}

func TestPoUWSlashResult_Fields(t *testing.T) {
	result := &PoUWSlashResult{
		ValidatorAddress: "test_validator",
		SlashedAmount:    sdkmath.NewInt(100000),
		SlashFractionBps: 1000,
		Reason:           SlashReasonInvalidOutput,
		Jailed:           true,
		JailUntil:        time.Now().Add(24 * time.Hour),
		Tombstoned:       false,
		InfractionHeight: 500,
		JobID:            "job-123",
	}

	if result.ValidatorAddress != "test_validator" {
		t.Errorf("Expected ValidatorAddress 'test_validator', got '%s'", result.ValidatorAddress)
	}

	if !result.SlashedAmount.Equal(sdkmath.NewInt(100000)) {
		t.Errorf("Expected SlashedAmount 100000, got %s", result.SlashedAmount.String())
	}

	if result.Reason != SlashReasonInvalidOutput {
		t.Errorf("Expected Reason 'invalid_output', got '%s'", result.Reason)
	}

	if result.JobID != "job-123" {
		t.Errorf("Expected JobID 'job-123', got '%s'", result.JobID)
	}
}
