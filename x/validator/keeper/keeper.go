package keeper

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"cosmossdk.io/collections"
	"cosmossdk.io/core/store"
	"cosmossdk.io/log"
	sdkmath "cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aethelred/aethelred/x/validator/types"
)

// Keeper manages the validator module state
type Keeper struct {
	cdc          codec.Codec
	storeService store.KVStoreService
	logger       log.Logger
	authority    string

	// External keepers
	stakingKeeper  StakingKeeper
	slashingKeeper SlashingKeeper

	// State collections
	HardwareCapabilities collections.Map[string, types.HardwareCapability]
	SlashingRecords      collections.Map[string, types.SlashingRecord]
	TombstonedValidators collections.KeySet[string]
	ValidatorJailUntil   collections.Map[string, int64]
	Params               collections.Item[types.Params]
}

const (
	// MaxActiveValidators enforces testnet/mainnet active validator cap.
	MaxActiveValidators = 100

	// ZoneCapBps limits active validators per cloud region (33%).
	ZoneCapBps = 3300
)

// StakingKeeper defines the expected staking keeper interface
type StakingKeeper interface {
	GetAllValidators(ctx context.Context) ([]interface{}, error)
	GetValidator(ctx context.Context, addr sdk.ValAddress) (interface{}, error)
	Slash(ctx context.Context, consAddr sdk.ConsAddress, fraction sdkmath.LegacyDec) error
	Jail(ctx context.Context, consAddr sdk.ConsAddress) error
}

// SlashingKeeper defines the expected slashing keeper interface
type SlashingKeeper interface {
	Slash(ctx context.Context, consAddr sdk.ConsAddress, fraction sdkmath.LegacyDec, power int64, height int64) error
	Jail(ctx context.Context, consAddr sdk.ConsAddress) error
}

// NewKeeper creates a new Keeper instance
func NewKeeper(
	cdc codec.Codec,
	storeService store.KVStoreService,
	logger log.Logger,
	stakingKeeper StakingKeeper,
	slashingKeeper SlashingKeeper,
	authority string,
) Keeper {
	sb := collections.NewSchemaBuilder(storeService)

	return Keeper{
		cdc:            cdc,
		storeService:   storeService,
		logger:         logger,
		authority:      authority,
		stakingKeeper:  stakingKeeper,
		slashingKeeper: slashingKeeper,
		HardwareCapabilities: collections.NewMap(
			sb,
			collections.NewPrefix(types.HardwareCapabilityKeyPrefix),
			"hardware_capabilities",
			collections.StringKey,
			codec.CollValue[types.HardwareCapability](cdc),
		),
		SlashingRecords: collections.NewMap(
			sb,
			collections.NewPrefix(types.SlashingRecordKeyPrefix),
			"slashing_records",
			collections.StringKey,
			codec.CollValue[types.SlashingRecord](cdc),
		),
		TombstonedValidators: collections.NewKeySet(
			sb,
			collections.NewPrefix(types.TombstonedValidatorKeyPrefix),
			"tombstoned_validators",
			collections.StringKey,
		),
		ValidatorJailUntil: collections.NewMap(
			sb,
			collections.NewPrefix(types.ValidatorJailUntilKeyPrefix),
			"validator_jail_until",
			collections.StringKey,
			collections.Int64Value,
		),
		Params: collections.NewItem(
			sb,
			collections.NewPrefix(types.ParamsKey),
			"params",
			codec.CollValue[types.Params](cdc),
		),
	}
}

// GetAuthority returns the module's governance authority address
func (k Keeper) GetAuthority() string {
	return k.authority
}

// RegisterHardwareCapability registers or updates a validator's hardware capabilities
func (k Keeper) RegisterHardwareCapability(ctx context.Context, capability *types.HardwareCapability) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Validate capability
	if err := capability.Validate(); err != nil {
		return fmt.Errorf("invalid hardware capability: %w", err)
	}

	tombstoned, err := k.TombstonedValidators.Has(ctx, capability.ValidatorAddress)
	if err == nil && tombstoned {
		return fmt.Errorf("validator %s is permanently tombstoned", capability.ValidatorAddress)
	}
	if capability.Status != nil && capability.Status.Online {
		if jailedUntil, jailErr := k.ValidatorJailUntil.Get(ctx, capability.ValidatorAddress); jailErr == nil {
			nowUnix := sdkCtx.BlockTime().Unix()
			if nowUnix < jailedUntil {
				return fmt.Errorf("validator %s is temporarily jailed until %d", capability.ValidatorAddress, jailedUntil)
			}
			_ = k.ValidatorJailUntil.Remove(ctx, capability.ValidatorAddress)
		}
	}

	if err := k.enforceValidatorSetConstraints(ctx, capability); err != nil {
		return err
	}

	// Store capability
	if err := k.HardwareCapabilities.Set(ctx, capability.ValidatorAddress, *capability); err != nil {
		return err
	}

	teeActive := false
	zkmlActive := false
	teePlatforms := 0
	zkmlSystems := 0
	if capability.Tee != nil {
		teeActive = capability.Tee.Active
		teePlatforms = len(capability.Tee.Platforms)
	}
	if capability.Zkml != nil {
		zkmlActive = capability.Zkml.Active
		zkmlSystems = len(capability.Zkml.ProofSystems)
	}

	k.logger.Info("Hardware capability registered",
		"validator", capability.ValidatorAddress,
		"tee_active", teeActive,
		"zkml_active", zkmlActive,
	)

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"hardware_capability_registered",
			sdk.NewAttribute("validator_address", capability.ValidatorAddress),
			sdk.NewAttribute("tee_platforms", fmt.Sprintf("%d", teePlatforms)),
			sdk.NewAttribute("zkml_systems", fmt.Sprintf("%d", zkmlSystems)),
		),
	)

	return nil
}

func normalizeRegion(region string) string {
	return strings.ToLower(strings.TrimSpace(region))
}

// enforceValidatorSetConstraints applies the max-validator and zone-cap policy.
func (k Keeper) enforceValidatorSetConstraints(ctx context.Context, capability *types.HardwareCapability) error {
	if capability == nil || capability.Status == nil || !capability.Status.Online {
		return nil
	}

	existing, existingErr := k.GetHardwareCapability(ctx, capability.ValidatorAddress)
	existingOnline := existingErr == nil && existing != nil && existing.Status != nil && existing.Status.Online

	totalActive, regionActive := k.countActiveValidatorsByRegion(ctx, capability.ValidatorAddress)
	projectedActive := totalActive + 1
	if existingOnline {
		projectedActive = totalActive + 1
	}

	if projectedActive > MaxActiveValidators {
		return fmt.Errorf("active validator cap reached (%d). validator queued", MaxActiveValidators)
	}

	targetRegion := ""
	if capability.Network != nil {
		targetRegion = normalizeRegion(capability.Network.Region)
	}
	if targetRegion == "" {
		return nil
	}

	projectedRegion := regionActive[targetRegion] + 1
	allowed := (projectedActive * ZoneCapBps) / 10_000
	if allowed < 1 {
		allowed = 1
	}
	if projectedRegion > allowed {
		return fmt.Errorf(
			"region %s exceeds %d%% zone cap (%d/%d active validators). validator queued",
			targetRegion,
			ZoneCapBps/100,
			projectedRegion,
			projectedActive,
		)
	}

	return nil
}

func (k Keeper) countActiveValidatorsByRegion(ctx context.Context, excludeAddr string) (int, map[string]int) {
	totalActive := 0
	regionActive := make(map[string]int)
	_ = k.HardwareCapabilities.Walk(ctx, nil, func(addr string, cap types.HardwareCapability) (bool, error) {
		if addr == excludeAddr || cap.Status == nil || !cap.Status.Online {
			return false, nil
		}
		totalActive++
		region := ""
		if cap.Network != nil {
			region = normalizeRegion(cap.Network.Region)
		}
		if region != "" {
			regionActive[region]++
		}
		return false, nil
	})
	return totalActive, regionActive
}

// GetHardwareCapability retrieves a validator's hardware capabilities
func (k Keeper) GetHardwareCapability(ctx context.Context, validatorAddr string) (*types.HardwareCapability, error) {
	capability, err := k.HardwareCapabilities.Get(ctx, validatorAddr)
	if err != nil {
		return nil, fmt.Errorf("hardware capability not found for %s", validatorAddr)
	}
	capCopy := capability
	return &capCopy, nil
}

// UpdateValidatorStatus updates a validator's online status
func (k Keeper) UpdateValidatorStatus(ctx context.Context, validatorAddr string, online bool, currentJobs int) error {
	capability, err := k.GetHardwareCapability(ctx, validatorAddr)
	if err != nil {
		return err
	}

	capability.UpdateStatus(online, currentJobs)

	return k.HardwareCapabilities.Set(ctx, validatorAddr, *capability)
}

// RecordHeartbeat records a heartbeat from a validator
func (k Keeper) RecordHeartbeat(ctx context.Context, validatorAddr string) error {
	capability, err := k.GetHardwareCapability(ctx, validatorAddr)
	if err != nil {
		// Create minimal capability if not exists
		capability = types.NewHardwareCapability(validatorAddr, "")
	}

	if capability.Status == nil {
		capability.Status = &types.CapabilityStatus{}
	}
	capability.Status.LastHeartbeat = timestamppb.Now()
	capability.Status.Online = true

	return k.HardwareCapabilities.Set(ctx, validatorAddr, *capability)
}

// GetOnlineValidators returns all online validators with their capabilities
func (k Keeper) GetOnlineValidators(ctx context.Context) []*types.HardwareCapability {
	var validators []*types.HardwareCapability

	_ = k.HardwareCapabilities.Walk(ctx, nil, func(addr string, cap types.HardwareCapability) (bool, error) {
		if cap.IsAvailable() {
			capCopy := cap
			validators = append(validators, &capCopy)
		}
		return false, nil
	})

	return validators
}

// GetValidatorsForProofType returns validators capable of a specific proof type
func (k Keeper) GetValidatorsForProofType(ctx context.Context, proofType string) []*types.HardwareCapability {
	var validators []*types.HardwareCapability

	_ = k.HardwareCapabilities.Walk(ctx, nil, func(addr string, cap types.HardwareCapability) (bool, error) {
		if !cap.IsAvailable() {
			return false, nil
		}

		switch proofType {
		case "tee":
			if cap.CanHandleTEE() {
				capCopy := cap
				validators = append(validators, &capCopy)
			}
		case "zkml":
			if cap.CanHandleZKML() {
				capCopy := cap
				validators = append(validators, &capCopy)
			}
		case "hybrid":
			if cap.CanHandleHybrid() {
				capCopy := cap
				validators = append(validators, &capCopy)
			}
		}

		return false, nil
	})

	// Sort by capability score (highest first)
	sort.Slice(validators, func(i, j int) bool {
		return validators[i].GetCapabilityScore() > validators[j].GetCapabilityScore()
	})

	return validators
}

// SelectValidatorsForJob selects the best validators for a compute job
func (k Keeper) SelectValidatorsForJob(ctx context.Context, proofType string, count int) []*types.HardwareCapability {
	candidates := k.GetValidatorsForProofType(ctx, proofType)

	if len(candidates) <= count {
		return candidates
	}

	return candidates[:count]
}

// RecordJobCompletion records a job completion for a validator
func (k Keeper) RecordJobCompletion(ctx context.Context, validatorAddr string, success bool, latencyMs int64) error {
	capability, err := k.GetHardwareCapability(ctx, validatorAddr)
	if err != nil {
		return err
	}

	capability.RecordJobCompletion(success, latencyMs)

	return k.HardwareCapabilities.Set(ctx, validatorAddr, *capability)
}

// GetValidatorStats returns statistics for a validator
func (k Keeper) GetValidatorStats(ctx context.Context, validatorAddr string) (*types.CapabilityStatus, error) {
	capability, err := k.GetHardwareCapability(ctx, validatorAddr)
	if err != nil {
		return nil, err
	}
	if capability.Status == nil {
		return nil, fmt.Errorf("capability status not found for %s", validatorAddr)
	}
	return capability.Status, nil
}

// MarkValidatorOffline marks a validator as offline
func (k Keeper) MarkValidatorOffline(ctx context.Context, validatorAddr string) error {
	capability, err := k.GetHardwareCapability(ctx, validatorAddr)
	if err != nil {
		return err
	}

	if capability.Status == nil {
		capability.Status = &types.CapabilityStatus{}
	}
	capability.Status.Online = false
	capability.UpdatedAt = timestamppb.Now()

	return k.HardwareCapabilities.Set(ctx, validatorAddr, *capability)
}

// CheckInactiveValidators marks validators as offline if they haven't sent a heartbeat
func (k Keeper) CheckInactiveValidators(ctx context.Context, timeout time.Duration) {
	now := time.Now().UTC()

	_ = k.HardwareCapabilities.Walk(ctx, nil, func(addr string, cap types.HardwareCapability) (bool, error) {
		if cap.Status == nil {
			return false, nil
		}
		lastHeartbeat := time.Time{}
		if cap.Status.LastHeartbeat != nil {
			lastHeartbeat = cap.Status.LastHeartbeat.AsTime()
		}
		if cap.Status.Online && !lastHeartbeat.IsZero() && now.Sub(lastHeartbeat) > timeout {
			cap.Status.Online = false
			cap.UpdatedAt = timestamppb.Now()
			_ = k.HardwareCapabilities.Set(ctx, addr, cap)

			k.logger.Info("Validator marked offline due to inactivity",
				"validator", addr,
				"last_heartbeat", lastHeartbeat,
			)
		}
		return false, nil
	})
}

// GetAllHardwareCapabilities returns all registered hardware capabilities
func (k Keeper) GetAllHardwareCapabilities(ctx context.Context) []*types.HardwareCapability {
	var capabilities []*types.HardwareCapability

	_ = k.HardwareCapabilities.Walk(ctx, nil, func(addr string, cap types.HardwareCapability) (bool, error) {
		capCopy := cap
		capabilities = append(capabilities, &capCopy)
		return false, nil
	})

	return capabilities
}

// InitGenesis initializes the module's state from genesis
func (k Keeper) InitGenesis(ctx context.Context, gs *types.GenesisState) error {
	// Set params
	params := gs.Params
	if params == nil {
		params = types.DefaultParams()
	}
	if err := k.Params.Set(ctx, *params); err != nil {
		return err
	}

	// Set hardware capabilities
	for _, cap := range gs.HardwareCapabilities {
		if cap == nil {
			return fmt.Errorf("nil hardware capability in genesis")
		}
		if err := k.HardwareCapabilities.Set(ctx, cap.ValidatorAddress, *cap); err != nil {
			return err
		}
	}

	return nil
}

// ExportGenesis exports the module's state
func (k Keeper) ExportGenesis(ctx context.Context) (*types.GenesisState, error) {
	params, err := k.Params.Get(ctx)
	if err != nil {
		params = *types.DefaultParams()
	}

	capabilities := k.GetAllHardwareCapabilities(ctx)

	paramsCopy := params
	return &types.GenesisState{
		Params:               &paramsCopy,
		HardwareCapabilities: capabilities,
	}, nil
}
