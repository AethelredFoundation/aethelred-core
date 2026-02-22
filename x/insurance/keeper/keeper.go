package keeper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"cosmossdk.io/collections"
	"cosmossdk.io/core/store"
	sdkmath "cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/insurance/types"
)

// ValidatorSource provides validator candidates for tribunal selection.
type ValidatorSource interface {
	ListValidators(ctx context.Context) ([]string, error)
	IsValidatorSlashed(ctx context.Context, validator string) bool
}

// Keeper manages escrowed slashing cases and appeal tribunals.
type Keeper struct {
	cdc          codec.Codec
	storeService store.KVStoreService
	authority    string

	validatorSource ValidatorSource

	Escrows     collections.Map[string, string]
	Appeals     collections.Map[string, string]
	AppealVotes collections.Map[string, string]
	EscrowCount collections.Item[uint64]
	AppealCount collections.Item[uint64]
}

// NewKeeper creates a new insurance keeper.
func NewKeeper(
	cdc codec.Codec,
	storeService store.KVStoreService,
	authority string,
) Keeper {
	sb := collections.NewSchemaBuilder(storeService)

	return Keeper{
		cdc:             cdc,
		storeService:    storeService,
		authority:       authority,
		validatorSource: nil,
		Escrows: collections.NewMap(
			sb,
			collections.NewPrefix(types.EscrowKeyPrefix),
			"escrows",
			collections.StringKey,
			collections.StringValue,
		),
		Appeals: collections.NewMap(
			sb,
			collections.NewPrefix(types.AppealKeyPrefix),
			"appeals",
			collections.StringKey,
			collections.StringValue,
		),
		AppealVotes: collections.NewMap(
			sb,
			collections.NewPrefix(types.AppealVoteKeyPrefix),
			"appeal_votes",
			collections.StringKey,
			collections.StringValue,
		),
		EscrowCount: collections.NewItem(
			sb,
			collections.NewPrefix(types.EscrowCountKey),
			"escrow_count",
			collections.Uint64Value,
		),
		AppealCount: collections.NewItem(
			sb,
			collections.NewPrefix(types.AppealCountKey),
			"appeal_count",
			collections.Uint64Value,
		),
	}
}

// SetValidatorSource wires the validator source used for tribunal selection.
func (k *Keeper) SetValidatorSource(source ValidatorSource) {
	k.validatorSource = source
}

// GetAuthority returns the keeper authority address.
func (k Keeper) GetAuthority() string {
	return k.authority
}

// EscrowFraudSlash records a 100% fraud slash into a 14-day escrow bucket.
func (k Keeper) EscrowFraudSlash(
	ctx context.Context,
	validatorAddr string,
	amount sdkmath.Int,
	reason string,
	evidenceHash string,
) (string, error) {
	validatorAddr = strings.TrimSpace(validatorAddr)
	reason = strings.TrimSpace(reason)
	evidenceHash = strings.TrimSpace(evidenceHash)
	if validatorAddr == "" {
		return "", fmt.Errorf("validator address cannot be empty")
	}
	if !amount.IsPositive() {
		return "", fmt.Errorf("escrow amount must be positive")
	}
	if reason == "" {
		return "", fmt.Errorf("escrow reason cannot be empty")
	}
	if evidenceHash == "" {
		evidenceHash = "n/a"
	}

	sdkCtx, now := contextNow(ctx)
	next, err := k.nextEscrowID(ctx)
	if err != nil {
		return "", err
	}

	record := types.EscrowRecord{
		ID:               next,
		ValidatorAddress: validatorAddr,
		Amount:           amount.String(),
		Reason:           reason,
		EvidenceHash:     evidenceHash,
		CreatedAtUnix:    now.Unix(),
		ReleaseAtUnix:    now.Add(types.EscrowDurationDays * 24 * time.Hour).Unix(),
		Status:           types.EscrowStatusHeld,
	}
	if err := k.setEscrow(ctx, record); err != nil {
		return "", err
	}

	emitEventIfPossible(sdkCtx, sdk.NewEvent(
		"insurance_escrow_created",
		sdk.NewAttribute("escrow_id", record.ID),
		sdk.NewAttribute("validator", record.ValidatorAddress),
		sdk.NewAttribute("amount", record.Amount),
		sdk.NewAttribute("release_at_unix", fmt.Sprintf("%d", record.ReleaseAtUnix)),
	))

	return record.ID, nil
}

// MsgSubmitAppeal creates an appeal and assigns a randomized tribunal of five
// non-slashed validators.
func (k Keeper) MsgSubmitAppeal(
	ctx context.Context,
	msg types.MsgSubmitAppeal,
) (*types.AppealRecord, error) {
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	escrow, err := k.GetEscrow(ctx, msg.EscrowID)
	if err != nil {
		return nil, err
	}
	if escrow.ValidatorAddress != msg.ValidatorAddress {
		return nil, fmt.Errorf("escrow validator mismatch")
	}
	if escrow.Status != types.EscrowStatusHeld {
		return nil, fmt.Errorf("escrow %s is not in held state", escrow.ID)
	}
	if escrow.AppealID != "" {
		return nil, fmt.Errorf("escrow %s already has appeal %s", escrow.ID, escrow.AppealID)
	}

	tribunal, err := k.selectTribunal(ctx, msg.ValidatorAddress, msg.EscrowID)
	if err != nil {
		return nil, err
	}

	sdkCtx, now := contextNow(ctx)
	appealID, err := k.nextAppealID(ctx)
	if err != nil {
		return nil, err
	}

	appeal := types.AppealRecord{
		ID:               appealID,
		EscrowID:         msg.EscrowID,
		ValidatorAddress: msg.ValidatorAddress,
		TeeLogURI:        msg.TeeLogURI,
		EvidenceHash:     msg.EvidenceHash,
		Tribunal:         tribunal,
		SubmittedAtUnix:  now.Unix(),
		Status:           types.AppealStatusPending,
	}

	if err := k.setAppeal(ctx, appeal); err != nil {
		return nil, err
	}

	escrow.AppealID = appeal.ID
	if err := k.setEscrow(ctx, *escrow); err != nil {
		return nil, err
	}

	emitEventIfPossible(sdkCtx, sdk.NewEvent(
		"insurance_appeal_submitted",
		sdk.NewAttribute("appeal_id", appeal.ID),
		sdk.NewAttribute("escrow_id", appeal.EscrowID),
		sdk.NewAttribute("validator", appeal.ValidatorAddress),
	))

	return &appeal, nil
}

// CastTribunalVote records a tribunal vote and resolves the appeal on majority.
func (k Keeper) CastTribunalVote(
	ctx context.Context,
	appealID string,
	voter string,
	nonMalicious bool,
	notes string,
) error {
	appealID = strings.TrimSpace(appealID)
	voter = strings.TrimSpace(voter)
	if appealID == "" || voter == "" {
		return fmt.Errorf("appeal id and voter are required")
	}

	appeal, err := k.GetAppeal(ctx, appealID)
	if err != nil {
		return err
	}
	if appeal.Status != types.AppealStatusPending {
		return fmt.Errorf("appeal %s already resolved", appealID)
	}
	if !containsString(appeal.Tribunal, voter) {
		return fmt.Errorf("voter is not assigned to appeal tribunal")
	}

	voteKey := tribunalVoteKey(appealID, voter)
	if exists, err := k.AppealVotes.Has(ctx, voteKey); err == nil && exists {
		return fmt.Errorf("voter already voted")
	}

	_, now := contextNow(ctx)
	vote := types.TribunalVote{
		AppealID:        appealID,
		Voter:           voter,
		NonMalicious:    nonMalicious,
		Notes:           strings.TrimSpace(notes),
		SubmittedAtUnix: now.Unix(),
	}
	if err := k.setAppealVote(ctx, voteKey, vote); err != nil {
		return err
	}

	if nonMalicious {
		appeal.VotesFor++
	} else {
		appeal.VotesAgainst++
	}

	if appeal.VotesFor >= types.TribunalMajority {
		appeal.Status = types.AppealStatusApproved
		appeal.ResolvedAtUnix = now.Unix()
		if err := k.resolveEscrow(ctx, appeal.EscrowID, types.EscrowStatusReimbursed); err != nil {
			return err
		}
	} else if appeal.VotesAgainst >= types.TribunalMajority {
		appeal.Status = types.AppealStatusRejected
		appeal.ResolvedAtUnix = now.Unix()
		if err := k.resolveEscrow(ctx, appeal.EscrowID, types.EscrowStatusForfeited); err != nil {
			return err
		}
	}

	if err := k.setAppeal(ctx, *appeal); err != nil {
		return err
	}

	if sdkCtx, ok := unwrapSDKContext(ctx); ok {
		sdkCtx.EventManager().EmitEvent(
			sdk.NewEvent(
				"insurance_tribunal_vote",
				sdk.NewAttribute("appeal_id", appealID),
				sdk.NewAttribute("voter", voter),
				sdk.NewAttribute("non_malicious", fmt.Sprintf("%t", nonMalicious)),
				sdk.NewAttribute("votes_for", fmt.Sprintf("%d", appeal.VotesFor)),
				sdk.NewAttribute("votes_against", fmt.Sprintf("%d", appeal.VotesAgainst)),
				sdk.NewAttribute("status", string(appeal.Status)),
			),
		)
	}

	return nil
}

// ProcessEscrowExpiries marks stale unresolved escrows as forfeited.
func (k Keeper) ProcessEscrowExpiries(ctx context.Context) (int, error) {
	_, now := contextNow(ctx)
	nowUnix := now.Unix()
	expired := 0

	err := k.Escrows.Walk(ctx, nil, func(_ string, raw string) (bool, error) {
		record, err := decodeEscrow(raw)
		if err != nil {
			return false, err
		}
		if record.Status != types.EscrowStatusHeld {
			return false, nil
		}
		if record.ReleaseAtUnix > nowUnix {
			return false, nil
		}

		record.Status = types.EscrowStatusForfeited
		if err := k.setEscrow(ctx, record); err != nil {
			return false, err
		}
		expired++
		return false, nil
	})
	if err != nil {
		return expired, err
	}

	return expired, nil
}

// GetEscrow loads a single escrow record.
func (k Keeper) GetEscrow(ctx context.Context, escrowID string) (*types.EscrowRecord, error) {
	raw, err := k.Escrows.Get(ctx, escrowID)
	if err != nil {
		return nil, fmt.Errorf("escrow %s not found", escrowID)
	}
	record, err := decodeEscrow(raw)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// GetAppeal loads a single appeal record.
func (k Keeper) GetAppeal(ctx context.Context, appealID string) (*types.AppealRecord, error) {
	raw, err := k.Appeals.Get(ctx, appealID)
	if err != nil {
		return nil, fmt.Errorf("appeal %s not found", appealID)
	}
	record, err := decodeAppeal(raw)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

func (k Keeper) resolveEscrow(ctx context.Context, escrowID string, status types.EscrowStatus) error {
	escrow, err := k.GetEscrow(ctx, escrowID)
	if err != nil {
		return err
	}
	escrow.Status = status
	return k.setEscrow(ctx, *escrow)
}

func (k Keeper) selectTribunal(
	ctx context.Context,
	appellant string,
	anchor string,
) ([]string, error) {
	if k.validatorSource == nil {
		return nil, fmt.Errorf("validator source is not configured for tribunal selection")
	}

	validators, err := k.validatorSource.ListValidators(ctx)
	if err != nil {
		return nil, err
	}

	unique := make(map[string]struct{})
	filtered := make([]string, 0, len(validators))
	for _, validator := range validators {
		validator = strings.TrimSpace(validator)
		if validator == "" || validator == appellant {
			continue
		}
		if _, exists := unique[validator]; exists {
			continue
		}
		if k.validatorSource.IsValidatorSlashed(ctx, validator) {
			continue
		}
		if k.validatorHasHeldEscrow(ctx, validator) {
			continue
		}
		unique[validator] = struct{}{}
		filtered = append(filtered, validator)
	}

	if len(filtered) < types.TribunalSize {
		return nil, fmt.Errorf("insufficient eligible tribunal validators: got %d, need %d", len(filtered), types.TribunalSize)
	}

	sort.Strings(filtered)
	seed := selectionSeed(ctx, anchor)
	sort.SliceStable(filtered, func(i, j int) bool {
		left := deterministicRank(seed, filtered[i])
		right := deterministicRank(seed, filtered[j])
		if cmp := bytes.Compare(left[:], right[:]); cmp != 0 {
			return cmp < 0
		}
		return filtered[i] < filtered[j]
	})

	return append([]string(nil), filtered[:types.TribunalSize]...), nil
}

func deterministicRank(seed [32]byte, validator string) [32]byte {
	payload := append(seed[:], []byte(validator)...)
	return sha256.Sum256(payload)
}

func selectionSeed(ctx context.Context, anchor string) [32]byte {
	if sdkCtx, ok := unwrapSDKContext(ctx); ok {
		data := fmt.Sprintf("%d|%d|%s", sdkCtx.BlockHeight(), sdkCtx.BlockTime().Unix(), anchor)
		return sha256.Sum256([]byte(data))
	}
	return sha256.Sum256([]byte(anchor))
}

func (k Keeper) validatorHasHeldEscrow(ctx context.Context, validator string) bool {
	hasHeld := false
	_ = k.Escrows.Walk(ctx, nil, func(_ string, raw string) (bool, error) {
		record, err := decodeEscrow(raw)
		if err != nil {
			return false, nil
		}
		if record.ValidatorAddress == validator && record.Status == types.EscrowStatusHeld {
			hasHeld = true
			return true, nil
		}
		return false, nil
	})
	return hasHeld
}

func (k Keeper) nextEscrowID(ctx context.Context) (string, error) {
	count, err := k.EscrowCount.Get(ctx)
	if err != nil {
		count = 0
	}
	count++
	if err := k.EscrowCount.Set(ctx, count); err != nil {
		return "", err
	}
	return fmt.Sprintf("escrow-%d", count), nil
}

func (k Keeper) nextAppealID(ctx context.Context) (string, error) {
	count, err := k.AppealCount.Get(ctx)
	if err != nil {
		count = 0
	}
	count++
	if err := k.AppealCount.Set(ctx, count); err != nil {
		return "", err
	}
	return fmt.Sprintf("appeal-%d", count), nil
}

func (k Keeper) setEscrow(ctx context.Context, record types.EscrowRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return k.Escrows.Set(ctx, record.ID, string(raw))
}

func decodeEscrow(raw string) (types.EscrowRecord, error) {
	var record types.EscrowRecord
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		return types.EscrowRecord{}, fmt.Errorf("decode escrow: %w", err)
	}
	return record, nil
}

func (k Keeper) setAppeal(ctx context.Context, record types.AppealRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return k.Appeals.Set(ctx, record.ID, string(raw))
}

func decodeAppeal(raw string) (types.AppealRecord, error) {
	var record types.AppealRecord
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		return types.AppealRecord{}, fmt.Errorf("decode appeal: %w", err)
	}
	return record, nil
}

func (k Keeper) setAppealVote(ctx context.Context, voteKey string, record types.TribunalVote) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return k.AppealVotes.Set(ctx, voteKey, string(raw))
}

func tribunalVoteKey(appealID, voter string) string {
	return appealID + "|" + voter
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
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
