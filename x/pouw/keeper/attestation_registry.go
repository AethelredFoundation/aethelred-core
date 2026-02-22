package keeper

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

const (
	nitroPlatformPrefix        = "aws-nitro"
	sgxPlatformPrefix          = "intel-sgx"
	nitroPlatformPCR0Prefix    = "aws-nitro:pcr0="
	sgxPlatformMRENCLAVEPrefix = "intel-sgx:mrenclave="
	measurementHexLength       = 64 // 32-byte measurement hash encoded as hex
	fakeAttestationSlashRatio  = "1.00"
)

// TrustedMeasurementRegistration represents a parsed platform-qualified
// TEE measurement declaration from validator capabilities.
type TrustedMeasurementRegistration struct {
	Platform       string
	MeasurementHex string
}

func canonicalizePlatform(platform string) (string, error) {
	switch strings.TrimSpace(strings.ToLower(platform)) {
	case nitroPlatformPrefix:
		return nitroPlatformPrefix, nil
	case sgxPlatformPrefix:
		return sgxPlatformPrefix, nil
	default:
		return "", fmt.Errorf("unsupported TEE platform: %s", platform)
	}
}

func normalizeMeasurementHex(raw string) (string, error) {
	normalized := strings.TrimSpace(strings.ToLower(raw))
	if len(normalized) != measurementHexLength {
		return "", fmt.Errorf("invalid measurement hex length: got %d, need %d", len(normalized), measurementHexLength)
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", fmt.Errorf("invalid measurement hex: %w", err)
	}
	return normalized, nil
}

func measurementRegistryKey(platform, measurementHex string) string {
	return platform + ":" + measurementHex
}

func validatorMeasurementKey(validatorAddr, platform string) string {
	return validatorAddr + "|" + platform
}

// RegisterValidatorMeasurement stores a validator's trusted platform measurement
// and marks it as globally registered.
func (k Keeper) RegisterValidatorMeasurement(
	ctx context.Context,
	validatorAddr string,
	platform string,
	measurementHex string,
) error {
	if validatorAddr == "" {
		return fmt.Errorf("validator address cannot be empty")
	}

	normalizedPlatform, err := canonicalizePlatform(platform)
	if err != nil {
		return err
	}

	normalizedMeasurement, err := normalizeMeasurementHex(measurementHex)
	if err != nil {
		return err
	}

	validatorPlatformKey := validatorMeasurementKey(validatorAddr, normalizedPlatform)
	if err := k.ValidatorMeasurements.Set(ctx, validatorPlatformKey, normalizedMeasurement); err != nil {
		return err
	}

	globalKey := measurementRegistryKey(normalizedPlatform, normalizedMeasurement)
	if err := k.RegisteredMeasurements.Set(ctx, globalKey); err != nil {
		return err
	}

	if sdkCtx, ok := unwrapSDKContext(ctx); ok {
		sdkCtx.EventManager().EmitEvent(
			sdk.NewEvent(
				"validator_tee_measurement_registered",
				sdk.NewAttribute("validator", validatorAddr),
				sdk.NewAttribute("platform", normalizedPlatform),
				sdk.NewAttribute("measurement", normalizedMeasurement),
			),
		)
	}

	return nil
}

// RegisterValidatorPCR0 stores a validator's trusted Nitro PCR0 hash and marks
// it as globally registered.
func (k Keeper) RegisterValidatorPCR0(ctx context.Context, validatorAddr, pcr0Hex string) error {
	if err := k.RegisterValidatorMeasurement(ctx, validatorAddr, nitroPlatformPrefix, pcr0Hex); err != nil {
		return err
	}

	// Backward-compatible storage paths for existing query/CLI surfaces.
	normalized, err := normalizePCR0Hex(pcr0Hex)
	if err != nil {
		return err
	}
	if err := k.ValidatorPCR0Mappings.Set(ctx, validatorAddr, normalized); err != nil {
		return err
	}
	if err := k.RegisteredPCR0Set.Set(ctx, normalized); err != nil {
		return err
	}
	return nil
}

// ValidateTEEAttestationMeasurement ensures the attested measurement is both globally
// registered and bound to the submitting validator for the given platform.
func (k Keeper) ValidateTEEAttestationMeasurement(
	ctx context.Context,
	validatorAddr string,
	platform string,
	measurement []byte,
) error {
	if len(measurement) == 0 {
		return fmt.Errorf("missing TEE measurement for registry check")
	}

	normalizedPlatform, err := canonicalizePlatform(platform)
	if err != nil {
		return err
	}

	measurementHex := strings.ToLower(hex.EncodeToString(measurement))
	if len(measurementHex) != measurementHexLength {
		return fmt.Errorf("invalid %s measurement length: got %d hex chars, need %d", normalizedPlatform, len(measurementHex), measurementHexLength)
	}

	globalKey := measurementRegistryKey(normalizedPlatform, measurementHex)
	isRegistered, err := k.RegisteredMeasurements.Has(ctx, globalKey)
	if err != nil {
		return fmt.Errorf("failed to query %s measurement registry: %w", normalizedPlatform, err)
	}
	if !isRegistered {
		return fmt.Errorf("unregistered %s measurement: %s", normalizedPlatform, measurementHex)
	}

	expectedMeasurement, err := k.ValidatorMeasurements.Get(ctx, validatorMeasurementKey(validatorAddr, normalizedPlatform))
	if err != nil {
		return fmt.Errorf("validator %s has no registered %s measurement", validatorAddr, normalizedPlatform)
	}
	if expectedMeasurement != measurementHex {
		return fmt.Errorf("tampered %s measurement for validator %s", normalizedPlatform, validatorAddr)
	}

	return nil
}

// ValidateTEEAttestationPCR0 ensures the attested measurement is both globally
// registered and bound to the submitting validator.
func (k Keeper) ValidateTEEAttestationPCR0(ctx context.Context, validatorAddr string, measurement []byte) error {
	return k.ValidateTEEAttestationMeasurement(ctx, validatorAddr, nitroPlatformPrefix, measurement)
}

// IsRegisteredMeasurement checks platform-qualified global registry membership.
func (k Keeper) IsRegisteredMeasurement(
	ctx context.Context,
	platform string,
	measurement []byte,
) (bool, string, error) {
	if len(measurement) == 0 {
		return false, "", fmt.Errorf("missing TEE measurement for registry check")
	}
	normalizedPlatform, err := canonicalizePlatform(platform)
	if err != nil {
		return false, "", err
	}

	measurementHex := strings.ToLower(hex.EncodeToString(measurement))
	if len(measurementHex) != measurementHexLength {
		return false, measurementHex, fmt.Errorf("invalid %s measurement length: got %d hex chars, need %d", normalizedPlatform, len(measurementHex), measurementHexLength)
	}

	registered, err := k.RegisteredMeasurements.Has(ctx, measurementRegistryKey(normalizedPlatform, measurementHex))
	if err != nil {
		return false, measurementHex, fmt.Errorf("failed to query %s measurement registry: %w", normalizedPlatform, err)
	}
	return registered, measurementHex, nil
}

// AppendTrustedMeasurementByAuthority appends a new trusted measurement.
// This is intended to be invoked by governance-controlled upgrade handlers.
func (k Keeper) AppendTrustedMeasurementByAuthority(
	ctx context.Context,
	authority string,
	platform string,
	measurementHex string,
) error {
	if strings.TrimSpace(authority) != k.GetAuthority() {
		return fmt.Errorf("unauthorized measurement update caller")
	}

	normalizedPlatform, err := canonicalizePlatform(platform)
	if err != nil {
		return err
	}
	normalizedMeasurement, err := normalizeMeasurementHex(measurementHex)
	if err != nil {
		return err
	}

	key := measurementRegistryKey(normalizedPlatform, normalizedMeasurement)
	if err := k.RegisteredMeasurements.Set(ctx, key); err != nil {
		return err
	}

	if normalizedPlatform == nitroPlatformPrefix {
		if err := k.RegisteredPCR0Set.Set(ctx, normalizedMeasurement); err != nil {
			return err
		}
	}

	return nil
}

// RevokeTrustedMeasurementBySecurityCommittee removes a trusted measurement using
// emergency committee authority (top 10 validators by bonded stake).
func (k Keeper) RevokeTrustedMeasurementBySecurityCommittee(
	ctx context.Context,
	requester string,
	platform string,
	measurementHex string,
) error {
	if !k.isSecurityCommitteeMember(ctx, requester) {
		return fmt.Errorf("requester is not in security committee")
	}

	normalizedPlatform, err := canonicalizePlatform(platform)
	if err != nil {
		return err
	}
	normalizedMeasurement, err := normalizeMeasurementHex(measurementHex)
	if err != nil {
		return err
	}

	key := measurementRegistryKey(normalizedPlatform, normalizedMeasurement)
	if err := k.RegisteredMeasurements.Remove(ctx, key); err != nil {
		return err
	}

	if normalizedPlatform == nitroPlatformPrefix {
		_ = k.RegisteredPCR0Set.Remove(ctx, normalizedMeasurement)
	}

	return nil
}

// IsRegisteredPCR0 checks global registry membership for a measurement hash.
func (k Keeper) IsRegisteredPCR0(ctx context.Context, measurement []byte) (bool, string, error) {
	return k.IsRegisteredMeasurement(ctx, nitroPlatformPrefix, measurement)
}

func normalizeCommitteeAddress(address string) string {
	return strings.TrimSpace(address)
}

func isRequesterMatchValidator(requester string, validator stakingtypes.Validator) bool {
	req := normalizeCommitteeAddress(requester)
	if req == "" {
		return false
	}
	if validator.GetOperator() == req {
		return true
	}
	if valAddr, err := sdk.ValAddressFromBech32(validator.GetOperator()); err == nil {
		if sdk.AccAddress(valAddr).String() == req {
			return true
		}
	}
	return false
}

func (k Keeper) isSecurityCommitteeMember(ctx context.Context, requester string) bool {
	if k.stakingKeeper == nil {
		return false
	}

	validators, err := k.stakingKeeper.GetAllValidators(ctx)
	if err != nil || len(validators) == 0 {
		return false
	}

	sort.Slice(validators, func(i, j int) bool {
		left := validators[i].GetBondedTokens()
		right := validators[j].GetBondedTokens()
		if !left.Equal(right) {
			return left.GT(right)
		}
		return validators[i].GetOperator() < validators[j].GetOperator()
	})

	committeeSize := 10
	if len(validators) < committeeSize {
		committeeSize = len(validators)
	}

	for i := 0; i < committeeSize; i++ {
		if isRequesterMatchValidator(requester, validators[i]) {
			return true
		}
	}
	return false
}

// ExtractTEETrustedMeasurementsFromPlatforms parses platform strings and returns
// recognized platform-qualified trusted measurements.
func ExtractTEETrustedMeasurementsFromPlatforms(platforms []string) []TrustedMeasurementRegistration {
	seen := make(map[string]struct{})
	var registrations []TrustedMeasurementRegistration

	for _, platform := range platforms {
		normalized := strings.TrimSpace(strings.ToLower(platform))
		if strings.HasPrefix(normalized, nitroPlatformPCR0Prefix) {
			raw := strings.TrimPrefix(normalized, nitroPlatformPCR0Prefix)
			measurement, err := normalizeMeasurementHex(raw)
			if err != nil {
				continue
			}
			key := measurementRegistryKey(nitroPlatformPrefix, measurement)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			registrations = append(registrations, TrustedMeasurementRegistration{
				Platform:       nitroPlatformPrefix,
				MeasurementHex: measurement,
			})
			continue
		}

		if strings.HasPrefix(normalized, sgxPlatformMRENCLAVEPrefix) {
			raw := strings.TrimPrefix(normalized, sgxPlatformMRENCLAVEPrefix)
			measurement, err := normalizeMeasurementHex(raw)
			if err != nil {
				continue
			}
			key := measurementRegistryKey(sgxPlatformPrefix, measurement)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			registrations = append(registrations, TrustedMeasurementRegistration{
				Platform:       sgxPlatformPrefix,
				MeasurementHex: measurement,
			})
		}
	}

	return registrations
}

// ExtractNitroPCR0FromPlatforms parses a validator's tee_platforms list and
// returns a configured Nitro PCR0 hash when present.
func ExtractNitroPCR0FromPlatforms(platforms []string) (string, bool) {
	for _, registration := range ExtractTEETrustedMeasurementsFromPlatforms(platforms) {
		if registration.Platform == nitroPlatformPrefix {
			return registration.MeasurementHex, true
		}
	}
	return "", false
}

// hasNitroPlatform returns true when a capability advertises AWS Nitro.
func hasNitroPlatform(platforms []string) bool {
	for _, platform := range platforms {
		normalized := strings.TrimSpace(strings.ToLower(platform))
		if strings.HasPrefix(normalized, nitroPlatformPrefix) {
			return true
		}
	}
	return false
}

func normalizePCR0Hex(pcr0Hex string) (string, error) {
	normalized := strings.TrimSpace(strings.ToLower(pcr0Hex))
	if len(normalized) != measurementHexLength {
		return "", fmt.Errorf("invalid PCR0 hex length: got %d, need %d", len(normalized), measurementHexLength)
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", fmt.Errorf("invalid PCR0 hex: %w", err)
	}
	return normalized, nil
}

// slashUntrustedAttestationValidator applies punitive slashing when a validator
// submits an unregistered or tampered TEE measurement.
func (k Keeper) slashUntrustedAttestationValidator(ctx context.Context, validatorAddr, jobID, reason string) {
	slashFactor := sdkmath.LegacyMustNewDecFromStr(fakeAttestationSlashRatio)
	slashedAmount, applied, slashErr := k.slashValidatorBondedStake(ctx, validatorAddr, slashFactor)
	if slashErr != nil {
		if sdkCtx, ok := unwrapSDKContext(ctx); ok {
			sdkCtx.Logger().Warn("Failed bonded-stake slashing for untrusted TEE attestation",
				"validator", validatorAddr,
				"error", slashErr,
			)
		}
	}

	stats, err := k.GetValidatorStats(ctx, validatorAddr)
	if err != nil || stats == nil {
		stats = types.NewValidatorStats(validatorAddr)
	}
	stats.RecordFailure()
	stats.RecordSlashing()
	_ = k.SetValidatorStats(ctx, stats)

	if sdkCtx, ok := unwrapSDKContext(ctx); ok {
		slashedValue := "0"
		if applied {
			slashedValue = slashedAmount.String()
		}

		sdkCtx.EventManager().EmitEvent(
			sdk.NewEvent(
				"validator_slashed_untrusted_tee",
				sdk.NewAttribute("validator", validatorAddr),
				sdk.NewAttribute("job_id", jobID),
				sdk.NewAttribute("reason", reason),
				sdk.NewAttribute("slash_factor", fakeAttestationSlashRatio),
				sdk.NewAttribute("slashed_amount", slashedValue),
				sdk.NewAttribute("slashed_from_bonded_stake", fmt.Sprintf("%t", applied)),
			),
		)
	}
}
