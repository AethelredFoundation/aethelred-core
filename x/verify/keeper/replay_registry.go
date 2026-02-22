package keeper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/verify/types"
)

const (
	defaultReplayRegistryTTL = 5 * time.Minute
	minReplayRegistryTTL     = time.Minute
)

type teeReplayRegistryEntry struct {
	ExpiresAtUnix  int64  `json:"expires_at_unix"`
	RecordedAtUnix int64  `json:"recorded_at_unix"`
	QuoteHashHex   string `json:"quote_hash_hex,omitempty"`
}

func (k Keeper) checkAndRecordTEEReplay(
	ctx context.Context,
	attestation *types.TEEAttestation,
	config *types.TEEConfig,
	params *types.Params,
) error {
	if attestation == nil || config == nil {
		return nil
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	blockTime := sdkCtx.BlockTime()
	if blockTime.IsZero() {
		if params != nil && params.AllowSimulated {
			return nil
		}
		return fmt.Errorf("missing block time for replay registry checks")
	}

	nowUnix := blockTime.Unix()
	ttl := replayRegistryTTL(config, params)
	expiresAtUnix := blockTime.Add(ttl).Unix()

	quoteHash := sha256.Sum256(attestation.Quote)
	quoteHashHex := hex.EncodeToString(quoteHash[:])
	if err := k.checkReplayKeyAndWrite(
		ctx,
		k.TEEReplayQuotes,
		"quote:"+quoteHashHex,
		teeReplayRegistryEntry{
			RecordedAtUnix: nowUnix,
			ExpiresAtUnix:  expiresAtUnix,
			QuoteHashHex:   quoteHashHex,
		},
		nowUnix,
		"quote",
	); err != nil {
		return err
	}

	requireFreshNonce := config.RequireFreshNonce ||
		(attestation.Platform == types.TEEPlatformAWSNitro && params != nil && !params.AllowSimulated)

	if requireFreshNonce || len(attestation.Nonce) > 0 {
		if len(attestation.Nonce) == 0 {
			return fmt.Errorf("missing nonce for replay registry")
		}
		nonceHash := sha256.Sum256(attestation.Nonce)
		nonceHashHex := hex.EncodeToString(nonceHash[:])
		nonceKey := "nonce:" + attestation.Platform.String() + ":" + nonceHashHex
		if err := k.checkReplayKeyAndWrite(
			ctx,
			k.TEEReplayNonces,
			nonceKey,
			teeReplayRegistryEntry{
				RecordedAtUnix: nowUnix,
				ExpiresAtUnix:  expiresAtUnix,
				QuoteHashHex:   quoteHashHex,
			},
			nowUnix,
			"nonce",
		); err != nil {
			return err
		}
	}

	return nil
}

func replayRegistryTTL(config *types.TEEConfig, params *types.Params) time.Duration {
	if config != nil && config.MaxQuoteAge != nil && config.MaxQuoteAge.AsDuration() > 0 {
		if config.MaxQuoteAge.AsDuration() < minReplayRegistryTTL {
			return minReplayRegistryTTL
		}
		return config.MaxQuoteAge.AsDuration()
	}
	if params != nil && params.DefaultTeeQuoteMaxAge != nil && params.DefaultTeeQuoteMaxAge.AsDuration() > 0 {
		if params.DefaultTeeQuoteMaxAge.AsDuration() < minReplayRegistryTTL {
			return minReplayRegistryTTL
		}
		return params.DefaultTeeQuoteMaxAge.AsDuration()
	}
	return defaultReplayRegistryTTL
}

func (k Keeper) checkReplayKeyAndWrite(
	ctx context.Context,
	store collectionsStringMap,
	key string,
	entry teeReplayRegistryEntry,
	nowUnix int64,
	replayType string,
) error {
	raw, err := store.Get(ctx, key)
	if err == nil {
		existing, decodeErr := decodeTEEReplayRegistryEntry(raw)
		if decodeErr == nil && existing.ExpiresAtUnix >= nowUnix {
			return fmt.Errorf("%s replay detected", replayType)
		}
		_ = store.Remove(ctx, key)
	}

	encoded, err := encodeTEEReplayRegistryEntry(entry)
	if err != nil {
		return fmt.Errorf("encode replay registry entry: %w", err)
	}
	if err := store.Set(ctx, key, encoded); err != nil {
		return fmt.Errorf("store replay registry entry: %w", err)
	}
	return nil
}

type collectionsStringMap interface {
	Get(context.Context, string) (string, error)
	Set(context.Context, string, string) error
	Remove(context.Context, string) error
}

func encodeTEEReplayRegistryEntry(entry teeReplayRegistryEntry) (string, error) {
	bz, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	return string(bz), nil
}

func decodeTEEReplayRegistryEntry(raw string) (teeReplayRegistryEntry, error) {
	var entry teeReplayRegistryEntry
	if err := json.Unmarshal([]byte(raw), &entry); err != nil {
		return teeReplayRegistryEntry{}, err
	}
	return entry, nil
}
