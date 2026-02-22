package keeper

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"cosmossdk.io/collections"
	"cosmossdk.io/core/store"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/crisis/types"
)

// Keeper manages sovereign emergency halt controls.
type Keeper struct {
	cdc          codec.Codec
	storeService store.KVStoreService
	authority    string

	CouncilConfig collections.Item[string]
	HaltState     collections.Item[string]
}

// NewKeeper creates a new sovereign crisis keeper.
func NewKeeper(
	cdc codec.Codec,
	storeService store.KVStoreService,
	authority string,
) Keeper {
	sb := collections.NewSchemaBuilder(storeService)

	return Keeper{
		cdc:          cdc,
		storeService: storeService,
		authority:    authority,
		CouncilConfig: collections.NewItem(
			sb,
			collections.NewPrefix(types.SecurityCouncilConfigKey),
			"security_council_config",
			collections.StringValue,
		),
		HaltState: collections.NewItem(
			sb,
			collections.NewPrefix(types.HaltStateKey),
			"sovereign_halt_state",
			collections.StringValue,
		),
	}
}

func (k Keeper) GetAuthority() string {
	return k.authority
}

// SetSecurityCouncilConfig stores the 5-of-7 council structure.
func (k Keeper) SetSecurityCouncilConfig(
	ctx context.Context,
	requester string,
	config types.SecurityCouncilConfig,
) error {
	if strings.TrimSpace(requester) != strings.TrimSpace(k.authority) {
		return fmt.Errorf("unauthorized council config update")
	}
	if err := config.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return k.CouncilConfig.Set(ctx, string(raw))
}

// GetSecurityCouncilConfig returns the configured council.
func (k Keeper) GetSecurityCouncilConfig(ctx context.Context) (*types.SecurityCouncilConfig, error) {
	raw, err := k.CouncilConfig.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("security council is not configured")
	}
	var config types.SecurityCouncilConfig
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return nil, fmt.Errorf("decode council config: %w", err)
	}
	return &config, nil
}

// MsgHaltNetwork executes emergency halt if signer quorum satisfies 5-of-7.
func (k Keeper) MsgHaltNetwork(ctx context.Context, msg types.MsgHaltNetwork) error {
	if err := msg.ValidateBasic(); err != nil {
		return err
	}
	config, err := k.GetSecurityCouncilConfig(ctx)
	if err != nil {
		return err
	}
	if err := verifyCouncilSigners(config, msg.Signers); err != nil {
		return err
	}
	if !containsSigner(msg.Signers, msg.Requester) {
		return fmt.Errorf("requester must be part of signer set")
	}

	sdkCtx, now := contextNow(ctx)
	state := types.HaltState{
		Active:                true,
		Reason:                strings.TrimSpace(msg.Reason),
		TriggeredBy:           normalizeSigners(msg.Signers),
		TriggeredByRequester:  strings.TrimSpace(msg.Requester),
		TriggeredAtHeight:     sdkCtx.BlockHeight(),
		TriggeredAtUnix:       now.Unix(),
		BridgeTransfersHalted: true,
		PoUWAllocationsHalted: true,
		GovernanceAllowed:     true,
	}
	if err := k.setHaltState(ctx, state); err != nil {
		return err
	}

	emitEventIfPossible(sdkCtx, sdk.NewEvent(
		"sovereign_network_halted",
		sdk.NewAttribute("reason", state.Reason),
		sdk.NewAttribute("requester", state.TriggeredByRequester),
		sdk.NewAttribute("signers", strings.Join(state.TriggeredBy, ",")),
		sdk.NewAttribute("bridge_halted", "true"),
		sdk.NewAttribute("pouw_halted", "true"),
		sdk.NewAttribute("governance_allowed", "true"),
	))

	return nil
}

// ClearHaltByAuthority clears halt state after emergency remediation.
func (k Keeper) ClearHaltByAuthority(ctx context.Context, requester string) error {
	if strings.TrimSpace(requester) != strings.TrimSpace(k.authority) {
		return fmt.Errorf("unauthorized halt clear request")
	}
	state := types.HaltState{
		Active:                false,
		GovernanceAllowed:     true,
		BridgeTransfersHalted: false,
		PoUWAllocationsHalted: false,
	}
	return k.setHaltState(ctx, state)
}

func (k Keeper) GetHaltState(ctx context.Context) (types.HaltState, error) {
	raw, err := k.HaltState.Get(ctx)
	if err != nil {
		return types.HaltState{
			Active:                false,
			GovernanceAllowed:     true,
			BridgeTransfersHalted: false,
			PoUWAllocationsHalted: false,
		}, nil
	}
	var state types.HaltState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return types.HaltState{}, fmt.Errorf("decode halt state: %w", err)
	}
	return state, nil
}

func (k Keeper) IsPoUWHalted(ctx context.Context) bool {
	state, err := k.GetHaltState(ctx)
	if err != nil {
		return false
	}
	return state.Active && state.PoUWAllocationsHalted
}

func (k Keeper) IsBridgeTransfersHalted(ctx context.Context) bool {
	state, err := k.GetHaltState(ctx)
	if err != nil {
		return false
	}
	return state.Active && state.BridgeTransfersHalted
}

func (k Keeper) setHaltState(ctx context.Context, state types.HaltState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return k.HaltState.Set(ctx, string(raw))
}

func verifyCouncilSigners(config *types.SecurityCouncilConfig, signers []string) error {
	if config == nil {
		return fmt.Errorf("security council config is nil")
	}

	memberSet := make(map[string]struct{}, len(config.Members))
	for _, member := range config.Members {
		memberSet[strings.TrimSpace(member.Address)] = struct{}{}
	}

	normalized := normalizeSigners(signers)
	if len(normalized) < config.Threshold {
		return fmt.Errorf("insufficient signatures: got %d, need %d", len(normalized), config.Threshold)
	}
	for _, signer := range normalized {
		if _, ok := memberSet[signer]; !ok {
			return fmt.Errorf("signer %s is not a security council member", signer)
		}
	}
	return nil
}

func normalizeSigners(signers []string) []string {
	seen := make(map[string]struct{}, len(signers))
	out := make([]string, 0, len(signers))
	for _, signer := range signers {
		signer = strings.TrimSpace(signer)
		if signer == "" {
			continue
		}
		if _, ok := seen[signer]; ok {
			continue
		}
		seen[signer] = struct{}{}
		out = append(out, signer)
	}
	sort.Strings(out)
	return out
}

func containsSigner(signers []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, signer := range signers {
		if strings.TrimSpace(signer) == target {
			return true
		}
	}
	return false
}

func unwrapSDKContext(ctx context.Context) (sdk.Context, bool) {
	if ctx == nil {
		return sdk.Context{}, false
	}
	if sdkCtx, ok := ctx.(sdk.Context); ok {
		return sdkCtx, true
	}
	if val := ctx.Value(sdk.SdkContextKey); val != nil {
		if sdkCtx, ok := val.(sdk.Context); ok {
			return sdkCtx, true
		}
	}
	return sdk.Context{}, false
}

func contextNow(ctx context.Context) (sdk.Context, time.Time) {
	if sdkCtx, ok := unwrapSDKContext(ctx); ok {
		return sdkCtx, sdkCtx.BlockTime()
	}
	return sdk.Context{}, time.Now().UTC()
}

func emitEventIfPossible(ctx sdk.Context, event sdk.Event) {
	if em := ctx.EventManager(); em != nil {
		em.EmitEvent(event)
	}
}
