package keeper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/verify/types"
)

// RegisterVerifyingKey registers a new verifying key.
// The hash is always recomputed from KeyBytes for integrity. If the caller
// provides a hash that doesn't match the key bytes, registration is rejected.
func (k Keeper) RegisterVerifyingKey(ctx context.Context, vk *types.VerifyingKey) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	if len(vk.KeyBytes) == 0 {
		return fmt.Errorf("verifying key bytes cannot be empty")
	}

	computedHash := sha256.Sum256(vk.KeyBytes)
	if len(vk.Hash) > 0 {
		if !bytes.Equal(vk.Hash, computedHash[:]) {
			return fmt.Errorf("verifying key hash mismatch: supplied hash does not match SHA-256 of key bytes")
		}
	}
	vk.Hash = computedHash[:]

	params, _ := k.GetParams(ctx)
	if int64(len(vk.KeyBytes)) > params.MaxVerifyingKeySize {
		return fmt.Errorf("verifying key exceeds max size: %d > %d", len(vk.KeyBytes), params.MaxVerifyingKeySize)
	}

	hashKey := fmt.Sprintf("%x", vk.Hash)
	exists, _ := k.VerifyingKeys.Has(ctx, hashKey)
	if exists {
		return fmt.Errorf("verifying key already registered: %s", hashKey)
	}

	if err := k.VerifyingKeys.Set(ctx, hashKey, *vk); err != nil {
		return err
	}

	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"verifying_key_registered",
			sdk.NewAttribute("hash", hashKey),
			sdk.NewAttribute("proof_system", vk.ProofSystem),
			sdk.NewAttribute("registered_by", vk.RegisteredBy),
		),
	)

	return nil
}

// RegisterCircuit registers a new circuit.
// The hash is always recomputed from CircuitBytes for integrity. If the caller
// provides a hash that doesn't match the circuit bytes, registration is rejected.
func (k Keeper) RegisterCircuit(ctx context.Context, circuit *types.Circuit) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	if len(circuit.CircuitBytes) == 0 {
		return fmt.Errorf("circuit bytes cannot be empty")
	}

	computedHash := sha256.Sum256(circuit.CircuitBytes)
	if len(circuit.Hash) > 0 {
		if !bytes.Equal(circuit.Hash, computedHash[:]) {
			return fmt.Errorf("circuit hash mismatch: supplied hash does not match SHA-256 of circuit bytes")
		}
	}
	circuit.Hash = computedHash[:]

	params, _ := k.GetParams(ctx)
	if int64(len(circuit.CircuitBytes)) > params.MaxCircuitSize {
		return fmt.Errorf("circuit exceeds max size: %d > %d", len(circuit.CircuitBytes), params.MaxCircuitSize)
	}

	hashKey := fmt.Sprintf("%x", circuit.Hash)
	exists, _ := k.Circuits.Has(ctx, hashKey)
	if exists {
		return fmt.Errorf("circuit already registered: %s", hashKey)
	}

	if err := k.Circuits.Set(ctx, hashKey, *circuit); err != nil {
		return err
	}

	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"circuit_registered",
			sdk.NewAttribute("hash", hashKey),
			sdk.NewAttribute("proof_system", circuit.ProofSystem),
			sdk.NewAttribute("registered_by", circuit.RegisteredBy),
		),
	)

	return nil
}

// GetVerifyingKey retrieves a verifying key by hash.
func (k Keeper) GetVerifyingKey(ctx context.Context, hash []byte) (*types.VerifyingKey, error) {
	hashKey := fmt.Sprintf("%x", hash)
	vk, err := k.VerifyingKeys.Get(ctx, hashKey)
	if err != nil {
		return nil, fmt.Errorf("verifying key not found: %x", hash)
	}
	vkCopy := vk
	return &vkCopy, nil
}

// GetCircuit retrieves a circuit by hash.
func (k Keeper) GetCircuit(ctx context.Context, hash []byte) (*types.Circuit, error) {
	hashKey := fmt.Sprintf("%x", hash)
	circuit, err := k.Circuits.Get(ctx, hashKey)
	if err != nil {
		return nil, fmt.Errorf("circuit not found: %x", hash)
	}
	circuitCopy := circuit
	return &circuitCopy, nil
}

// SetTEEConfig sets a TEE platform configuration.
func (k Keeper) SetTEEConfig(ctx context.Context, config *types.TEEConfig) error {
	if config == nil {
		return fmt.Errorf("TEE config cannot be nil")
	}
	return k.TEEConfigs.Set(ctx, config.Platform.String(), *config)
}

// GetTEEConfig retrieves a TEE platform configuration.
func (k Keeper) GetTEEConfig(ctx context.Context, platform types.TEEPlatform) (*types.TEEConfig, error) {
	config, err := k.TEEConfigs.Get(ctx, platform.String())
	if err != nil {
		return nil, fmt.Errorf("TEE config not found: %s", platform.String())
	}
	configCopy := config
	return &configCopy, nil
}

// GetParams returns the module parameters.
func (k Keeper) GetParams(ctx context.Context) (*types.Params, error) {
	params, err := k.Params.Get(ctx)
	if err != nil {
		return types.DefaultParams(), nil
	}
	paramsCopy := params
	return &paramsCopy, nil
}

// SetParams sets the module parameters.
func (k Keeper) SetParams(ctx context.Context, params *types.Params) error {
	if params == nil {
		return fmt.Errorf("params cannot be nil")
	}
	return k.Params.Set(ctx, *params)
}

// InitGenesis initializes the module's state from genesis.
func (k Keeper) InitGenesis(ctx context.Context, gs *types.GenesisState) error {
	params := gs.Params
	if params == nil {
		params = types.DefaultParams()
	}
	if err := k.SetParams(ctx, params); err != nil {
		return err
	}

	for _, vk := range gs.VerifyingKeys {
		if vk == nil {
			return fmt.Errorf("nil verifying key in genesis")
		}
		hashKey := fmt.Sprintf("%x", vk.Hash)
		if err := k.VerifyingKeys.Set(ctx, hashKey, *vk); err != nil {
			return err
		}
	}

	for _, circuit := range gs.Circuits {
		if circuit == nil {
			return fmt.Errorf("nil circuit in genesis")
		}
		hashKey := fmt.Sprintf("%x", circuit.Hash)
		if err := k.Circuits.Set(ctx, hashKey, *circuit); err != nil {
			return err
		}
	}

	for _, config := range gs.TeeConfigs {
		if config == nil {
			return fmt.Errorf("nil TEE config in genesis")
		}
		if err := k.TEEConfigs.Set(ctx, config.Platform.String(), *config); err != nil {
			return err
		}
	}

	return nil
}

// ExportGenesis exports the module's state.
func (k Keeper) ExportGenesis(ctx context.Context) (*types.GenesisState, error) {
	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, err
	}

	var vks []*types.VerifyingKey
	_ = k.VerifyingKeys.Walk(ctx, nil, func(id string, vk types.VerifyingKey) (bool, error) {
		vkCopy := vk
		vks = append(vks, &vkCopy)
		return false, nil
	})

	var circuits []*types.Circuit
	_ = k.Circuits.Walk(ctx, nil, func(id string, c types.Circuit) (bool, error) {
		cCopy := c
		circuits = append(circuits, &cCopy)
		return false, nil
	})

	var configs []*types.TEEConfig
	_ = k.TEEConfigs.Walk(ctx, nil, func(id string, c types.TEEConfig) (bool, error) {
		cCopy := c
		configs = append(configs, &cCopy)
		return false, nil
	})

	return &types.GenesisState{
		Params:        params,
		VerifyingKeys: vks,
		Circuits:      circuits,
		TeeConfigs:    configs,
	}, nil
}
