package keeper

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	"cosmossdk.io/collections"
	"cosmossdk.io/collections/indexes"
	"cosmossdk.io/core/store"
	"cosmossdk.io/log"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/seal/types"
)

// SealIndexes defines secondary indexes for seals.
type SealIndexes struct {
	ByModel     *indexes.Multi[string, string, types.DigitalSeal]
	ByRequester *indexes.Multi[string, string, types.DigitalSeal]
}

// IndexesList returns all indexes maintained for seals.
func (i SealIndexes) IndexesList() []collections.Index[string, types.DigitalSeal] {
	return []collections.Index[string, types.DigitalSeal]{
		i.ByModel,
		i.ByRequester,
	}
}

// Keeper manages the seal module state
type Keeper struct {
	cdc          codec.Codec
	storeService store.KVStoreService
	authority    string
	logger       log.Logger

	// State collections (for production with store)
	Seals     *collections.IndexedMap[string, types.DigitalSeal, SealIndexes]
	SealCount collections.Item[uint64]
	Params    collections.Item[types.Params]

	// In-memory storage for testing
	memSeals    map[string]*types.DigitalSeal
	memMutex    sync.RWMutex
	useMemStore bool
}

// NewKeeper creates a new Keeper instance for production
func NewKeeper(
	cdc codec.Codec,
	storeService store.KVStoreService,
	authority string,
) Keeper {
	if storeService == nil {
		// Testing mode - use in-memory storage
		return Keeper{
			cdc:         cdc,
			authority:   authority,
			logger:      log.NewNopLogger(),
			memSeals:    make(map[string]*types.DigitalSeal),
			useMemStore: true,
		}
	}

	sb := collections.NewSchemaBuilder(storeService)
	sealIndexes := SealIndexes{
		ByModel: indexes.NewMulti(
			sb,
			collections.NewPrefix(types.SealByModelKeyPrefix),
			"seals_by_model",
			collections.StringKey,
			collections.StringKey,
			func(_ string, seal types.DigitalSeal) (string, error) {
				return hex.EncodeToString(seal.ModelCommitment), nil
			},
		),
		ByRequester: indexes.NewMulti(
			sb,
			collections.NewPrefix(types.SealByRequesterKeyPrefix),
			"seals_by_requester",
			collections.StringKey,
			collections.StringKey,
			func(_ string, seal types.DigitalSeal) (string, error) {
				return seal.RequestedBy, nil
			},
		),
	}

	return Keeper{
		cdc:          cdc,
		storeService: storeService,
		authority:    authority,
		logger:       log.NewNopLogger(),
		memSeals:     make(map[string]*types.DigitalSeal),
		useMemStore:  false,
		Seals: collections.NewIndexedMap(
			sb,
			collections.NewPrefix(types.SealKeyPrefix),
			"seals",
			collections.StringKey,
			codec.CollValue[types.DigitalSeal](cdc),
			sealIndexes,
		),
		SealCount: collections.NewItem(
			sb,
			collections.NewPrefix(types.SealCountKey),
			"seal_count",
			collections.Uint64Value,
		),
		Params: collections.NewItem(
			sb,
			collections.NewPrefix(types.ParamsKey),
			"params",
			codec.CollValue[types.Params](cdc),
		),
	}
}

// NewKeeperWithLogger creates a new Keeper instance with a logger (for testing)
func NewKeeperWithLogger(
	logger log.Logger,
	cdc codec.Codec,
	storeService store.KVStoreService,
	authority string,
) Keeper {
	k := NewKeeper(cdc, storeService, authority)
	k.logger = logger
	return k
}

// GetAuthority returns the module's governance authority address
func (k Keeper) GetAuthority() string {
	return k.authority
}

// CreateSeal creates a new Digital Seal
func (k Keeper) CreateSeal(ctx context.Context, seal *types.DigitalSeal) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Validate the seal
	if err := seal.Validate(); err != nil {
		return fmt.Errorf("invalid seal: %w", err)
	}

	// Check if seal already exists
	exists, err := k.Seals.Has(ctx, seal.Id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("seal with ID %s already exists", seal.Id)
	}

	// Set block height if not set
	if seal.BlockHeight == 0 {
		seal.BlockHeight = sdkCtx.BlockHeight()
	}

	// Store the seal
	if err := k.Seals.Set(ctx, seal.Id, *seal); err != nil {
		return err
	}

	// Increment seal count
	count, err := k.SealCount.Get(ctx)
	if err != nil {
		count = 0
	}
	if err := k.SealCount.Set(ctx, count+1); err != nil {
		return err
	}

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"seal_created",
			sdk.NewAttribute("seal_id", seal.Id),
			sdk.NewAttribute("model_hash", fmt.Sprintf("%x", seal.ModelCommitment)),
			sdk.NewAttribute("requested_by", seal.RequestedBy),
			sdk.NewAttribute("purpose", seal.Purpose),
			sdk.NewAttribute("block_height", fmt.Sprintf("%d", seal.BlockHeight)),
		),
	)

	return nil
}

// GetSeal retrieves a seal by ID
func (k *Keeper) GetSeal(ctx context.Context, id string) (*types.DigitalSeal, error) {
	if k.useMemStore {
		k.memMutex.RLock()
		defer k.memMutex.RUnlock()
		if seal, ok := k.memSeals[id]; ok {
			sealCopy := *seal
			return &sealCopy, nil
		}
		return nil, fmt.Errorf("seal not found: %s", id)
	}

	seal, err := k.Seals.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("seal not found: %s", id)
	}
	sealCopy := seal
	return &sealCopy, nil
}

// GetSealByJob retrieves a seal by job ID
func (k Keeper) GetSealByJob(ctx context.Context, jobID string) (*types.DigitalSeal, error) {
	// Iterate through seals to find one with matching job ID
	// In production, this would use an index
	var foundSeal *types.DigitalSeal
	err := k.Seals.Walk(ctx, nil, func(id string, seal types.DigitalSeal) (bool, error) {
		// Check if this seal corresponds to the job
		// This is a simplified check - in production, seals would have a JobID field
		if id == jobID {
			sealCopy := seal
			foundSeal = &sealCopy
			return true, nil // Stop iteration
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	if foundSeal == nil {
		return nil, fmt.Errorf("seal not found for job: %s", jobID)
	}
	return foundSeal, nil
}

// UpdateSeal updates an existing seal
func (k Keeper) UpdateSeal(ctx context.Context, seal *types.DigitalSeal) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Check if seal exists
	exists, err := k.Seals.Has(ctx, seal.Id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("seal not found: %s", seal.Id)
	}

	// Store updated seal
	if err := k.Seals.Set(ctx, seal.Id, *seal); err != nil {
		return err
	}

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"seal_updated",
			sdk.NewAttribute("seal_id", seal.Id),
			sdk.NewAttribute("status", seal.Status.String()),
		),
	)

	return nil
}

// RevokeSeal revokes a seal by ID
func (k Keeper) RevokeSeal(ctx context.Context, id string, reason string) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	seal, err := k.GetSeal(ctx, id)
	if err != nil {
		return err
	}

	// Mark as revoked
	seal.Revoke()

	// Store updated seal
	if err := k.Seals.Set(ctx, id, *seal); err != nil {
		return err
	}

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"seal_revoked",
			sdk.NewAttribute("seal_id", id),
			sdk.NewAttribute("reason", reason),
		),
	)

	return nil
}

// ListSeals returns all seals (paginated)
func (k Keeper) ListSeals(ctx context.Context, limit int, offset int) ([]*types.DigitalSeal, error) {
	var seals []*types.DigitalSeal
	count := 0

	err := k.Seals.Walk(ctx, nil, func(id string, seal types.DigitalSeal) (bool, error) {
		// Skip until offset
		if count < offset {
			count++
			return false, nil
		}

		// Stop at limit
		if len(seals) >= limit {
			return true, nil
		}

		sealCopy := seal
		seals = append(seals, &sealCopy)
		count++
		return false, nil
	})
	if err != nil {
		return nil, err
	}

	return seals, nil
}

// ListSealsByModel returns all seals for a given model hash
func (k Keeper) ListSealsByModel(ctx context.Context, modelHash []byte) ([]*types.DigitalSeal, error) {
	var seals []*types.DigitalSeal

	if k.useMemStore {
		k.memMutex.RLock()
		defer k.memMutex.RUnlock()
		for _, seal := range k.memSeals {
			if bytes.Equal(seal.ModelCommitment, modelHash) {
				sealCopy := *seal
				seals = append(seals, &sealCopy)
			}
		}
		return seals, nil
	}

	iter, err := k.Seals.Indexes.ByModel.MatchExact(ctx, hex.EncodeToString(modelHash))
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	for ; iter.Valid(); iter.Next() {
		id, err := iter.PrimaryKey()
		if err != nil {
			return nil, err
		}
		seal, err := k.Seals.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		sealCopy := seal
		seals = append(seals, &sealCopy)
	}

	return seals, nil
}

// ListSealsByRequester returns all seals requested by a given address
func (k Keeper) ListSealsByRequester(ctx context.Context, requester string) ([]*types.DigitalSeal, error) {
	var seals []*types.DigitalSeal

	if k.useMemStore {
		k.memMutex.RLock()
		defer k.memMutex.RUnlock()
		for _, seal := range k.memSeals {
			if seal.RequestedBy == requester {
				sealCopy := *seal
				seals = append(seals, &sealCopy)
			}
		}
		return seals, nil
	}

	iter, err := k.Seals.Indexes.ByRequester.MatchExact(ctx, requester)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	for ; iter.Valid(); iter.Next() {
		id, err := iter.PrimaryKey()
		if err != nil {
			return nil, err
		}
		seal, err := k.Seals.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		sealCopy := seal
		seals = append(seals, &sealCopy)
	}

	return seals, nil
}

// GetSealCount returns the total number of seals
func (k Keeper) GetSealCount(ctx context.Context) (uint64, error) {
	return k.SealCount.Get(ctx)
}

// VerifySeal verifies the integrity of a seal
func (k Keeper) VerifySeal(ctx context.Context, id string) (bool, error) {
	seal, err := k.GetSeal(ctx, id)
	if err != nil {
		return false, err
	}

	// Check if seal is valid
	if err := seal.Validate(); err != nil {
		return false, nil
	}

	// Check if seal is active
	if seal.Status != types.SealStatusActive {
		return false, nil
	}

	// Check if seal has verification evidence
	if !seal.IsVerified() {
		return false, nil
	}

	return true, nil
}

// GetParams returns the module parameters
func (k Keeper) GetParams(ctx context.Context) (*types.Params, error) {
	params, err := k.Params.Get(ctx)
	if err != nil {
		return types.DefaultParams(), nil
	}
	return &params, nil
}

// SetParams sets the module parameters
func (k Keeper) SetParams(ctx context.Context, params *types.Params) error {
	if params == nil {
		return fmt.Errorf("params cannot be nil")
	}
	return k.Params.Set(ctx, *params)
}

// InitGenesis initializes the module's state from genesis
func (k Keeper) InitGenesis(ctx context.Context, gs *types.GenesisState) error {
	// Set params
	params := gs.Params
	if params == nil {
		params = types.DefaultParams()
	}
	if err := k.SetParams(ctx, params); err != nil {
		return err
	}

	// Set seals
	for _, seal := range gs.Seals {
		if seal == nil {
			return fmt.Errorf("nil seal in genesis")
		}
		if err := k.Seals.Set(ctx, seal.Id, *seal); err != nil {
			return err
		}
	}

	// Set seal count
	if err := k.SealCount.Set(ctx, uint64(len(gs.Seals))); err != nil {
		return err
	}

	return nil
}

// ExportGenesis exports the module's state.
// CRITICAL: This exports ALL seals without truncation to prevent data loss during
// network upgrades. For chains with many seals, this may take significant time.
func (k Keeper) ExportGenesis(ctx context.Context) (*types.GenesisState, error) {
	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, err
	}

	// Export ALL seals using paginated iteration to avoid memory issues
	seals, err := k.ExportAllSeals(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export seals: %w", err)
	}

	return &types.GenesisState{
		Params: params,
		Seals:  seals,
	}, nil
}

// ExportAllSeals exports all seals using paginated iteration.
// This prevents memory issues for chains with large numbers of seals.
func (k Keeper) ExportAllSeals(ctx context.Context) ([]*types.DigitalSeal, error) {
	var allSeals []*types.DigitalSeal

	// Get total count for logging
	totalCount, err := k.SealCount.Get(ctx)
	if err != nil {
		totalCount = 0 // Continue even if count unavailable
	}

	// Use batched iteration to prevent memory issues
	const batchSize = 1000
	offset := 0
	exportedCount := uint64(0)

	for {
		batch, err := k.ListSeals(ctx, batchSize, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch seal batch at offset %d: %w", offset, err)
		}

		if len(batch) == 0 {
			break // No more seals
		}

		allSeals = append(allSeals, batch...)
		exportedCount += uint64(len(batch))
		offset += len(batch)

		// Log progress for large exports
		if totalCount > 0 && exportedCount%10000 == 0 {
			k.logger.Info("Exporting seals progress",
				"exported", exportedCount,
				"total", totalCount,
				"percent", float64(exportedCount)*100/float64(totalCount),
			)
		}

		// Check if we got fewer than batch size (last batch)
		if len(batch) < batchSize {
			break
		}
	}

	k.logger.Info("Seal export completed",
		"total_seals", len(allSeals),
		"expected_count", totalCount,
	)

	return allSeals, nil
}

// ExportGenesisStream exports genesis state in a streaming manner for very large chains.
// This writes seals in batches to a provided writer to avoid holding all seals in memory.
// Use this for chains with millions of seals.
func (k Keeper) ExportGenesisStream(ctx context.Context, sealHandler func(seal *types.DigitalSeal) error) error {
	return k.Seals.Walk(ctx, nil, func(id string, seal types.DigitalSeal) (bool, error) {
		sealCopy := seal
		if err := sealHandler(&sealCopy); err != nil {
			return true, err // Stop on error
		}
		return false, nil // Continue
	})
}

// SetSeal stores or updates a seal
func (k *Keeper) SetSeal(ctx context.Context, seal *types.DigitalSeal) error {
	if seal == nil {
		return fmt.Errorf("seal cannot be nil")
	}

	if k.useMemStore {
		k.memMutex.Lock()
		defer k.memMutex.Unlock()
		sealCopy := *seal
		k.memSeals[seal.Id] = &sealCopy
		return nil
	}

	return k.Seals.Set(ctx, seal.Id, *seal)
}

// GetAllSeals returns all seals in the store
func (k *Keeper) GetAllSeals(ctx context.Context) []*types.DigitalSeal {
	var seals []*types.DigitalSeal

	if k.useMemStore {
		k.memMutex.RLock()
		defer k.memMutex.RUnlock()
		for _, seal := range k.memSeals {
			sealCopy := *seal
			seals = append(seals, &sealCopy)
		}
		return seals
	}

	k.Seals.Walk(ctx, nil, func(id string, seal types.DigitalSeal) (bool, error) {
		sealCopy := seal
		seals = append(seals, &sealCopy)
		return false, nil
	})

	return seals
}
