package keeper

import (
	"context"
	"fmt"
	"strconv"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// ---------------------------------------------------------------------------
// MsgUpdateParams -- manually defined until proto is regenerated.
// Once the proto toolchain produces this message, delete these types and
// import the generated ones from the types package instead.
// ---------------------------------------------------------------------------

// MsgUpdateParams defines a message for updating module parameters via governance.
// This type is defined here because the proto-generated code does not yet include it.
// Once proto is regenerated, this should be replaced with the generated type.
type MsgUpdateParams struct {
	// Authority is the address that controls the module (governance module account).
	Authority string

	// Params defines the module parameters to update.
	// Only non-zero/non-empty fields are applied (partial updates supported).
	Params types.Params

	// Has* flags specify which boolean fields are explicitly set in Params.
	// This avoids unintended default-to-false updates when fields are omitted.
	HasRequireTeeAttestation bool
	HasAllowZkmlFallback     bool
	HasAllowSimulated        bool
}

// MsgUpdateParamsResponse is the response type for MsgUpdateParams.
type MsgUpdateParamsResponse struct{}

// ---------------------------------------------------------------------------
// Parameter validation
// ---------------------------------------------------------------------------

// validProofTypes is the set of proof type strings accepted by the module.
var validProofTypes = map[string]struct{}{
	"tee":    {},
	"zkml":   {},
	"hybrid": {},
}

// ValidateParams performs comprehensive validation of module parameters.
// It returns an error describing the first violated constraint, or nil if all
// parameters are within acceptable bounds.
func ValidateParams(params *types.Params) error {
	if params == nil {
		return fmt.Errorf("params cannot be nil")
	}

	// MinValidators: [1, 100]
	if params.MinValidators < 1 || params.MinValidators > 100 {
		return fmt.Errorf("min_validators must be >= 1 and <= 100, got %d", params.MinValidators)
	}

	// ConsensusThreshold: [67, 100]
	// BFT safety REQUIRES > 2/3 majority to prevent Byzantine fault tolerance violations.
	// The minimum safe threshold is 67% (which represents >2/3 with integer math).
	// SECURITY: Values below 67% would allow Byzantine validators to reach false consensus.
	// This is a CRITICAL security parameter that cannot be weakened via governance.
	if params.ConsensusThreshold < 67 || params.ConsensusThreshold > 100 {
		return fmt.Errorf("SECURITY: consensus_threshold must be >= 67 (BFT requirement) and <= 100, got %d", params.ConsensusThreshold)
	}

	// JobTimeoutBlocks: >= 10 (minimum ~1 minute with 6s blocks)
	if params.JobTimeoutBlocks < 10 {
		return fmt.Errorf("job_timeout_blocks must be >= 10, got %d", params.JobTimeoutBlocks)
	}

	// BaseJobFee: must be a valid positive coin
	if err := validatePositiveCoin(params.BaseJobFee, "base_job_fee"); err != nil {
		return err
	}

	// VerificationReward: must be a valid positive coin
	if err := validatePositiveCoin(params.VerificationReward, "verification_reward"); err != nil {
		return err
	}

	// SlashingPenalty: must be a valid positive coin
	if err := validatePositiveCoin(params.SlashingPenalty, "slashing_penalty"); err != nil {
		return err
	}

	// MaxJobsPerBlock: [1, 1000]
	if params.MaxJobsPerBlock < 1 || params.MaxJobsPerBlock > 1000 {
		return fmt.Errorf("max_jobs_per_block must be >= 1 and <= 1000, got %d", params.MaxJobsPerBlock)
	}

	// AllowedProofTypes: non-empty, values in {"tee", "zkml", "hybrid"}
	if len(params.AllowedProofTypes) == 0 {
		return fmt.Errorf("allowed_proof_types must be non-empty")
	}
	for _, pt := range params.AllowedProofTypes {
		if _, ok := validProofTypes[pt]; !ok {
			return fmt.Errorf("allowed_proof_types contains invalid type %q; permitted values are tee, zkml, hybrid", pt)
		}
	}

	// Vote extension time bounds (seconds)
	if params.VoteExtensionMaxPastSkewSecs < 60 || params.VoteExtensionMaxPastSkewSecs > 86400 {
		return fmt.Errorf("vote_extension_max_past_skew_secs must be between 60 and 86400 seconds, got %d", params.VoteExtensionMaxPastSkewSecs)
	}
	if params.VoteExtensionMaxFutureSkewSecs < 1 || params.VoteExtensionMaxFutureSkewSecs > 3600 {
		return fmt.Errorf("vote_extension_max_future_skew_secs must be between 1 and 3600 seconds, got %d", params.VoteExtensionMaxFutureSkewSecs)
	}
	if params.VoteExtensionMaxFutureSkewSecs > params.VoteExtensionMaxPastSkewSecs {
		return fmt.Errorf("vote_extension_max_future_skew_secs cannot exceed vote_extension_max_past_skew_secs")
	}

	return nil
}

// validatePositiveCoin parses a coin string and checks that it represents a
// strictly positive amount.
func validatePositiveCoin(coinStr, fieldName string) error {
	if coinStr == "" {
		return fmt.Errorf("%s must not be empty", fieldName)
	}
	coin, err := sdk.ParseCoinNormalized(coinStr)
	if err != nil {
		return fmt.Errorf("%s is not a valid coin: %w", fieldName, err)
	}
	if !coin.IsPositive() {
		return fmt.Errorf("%s must be positive, got %s", fieldName, coinStr)
	}
	return nil
}

// ---------------------------------------------------------------------------
// MergeParams -- partial update support
// ---------------------------------------------------------------------------

// BoolFieldMask indicates which boolean fields should be applied from an update.
type BoolFieldMask struct {
	RequireTeeAttestation bool
	AllowZkmlFallback     bool
	AllowSimulated        bool
}

// MergeParams creates a new Params by overlaying non-zero/non-empty fields
// from update onto current. The merge semantics are:
//
//   - int64 fields: 0 means "don't change" (keep current value).
//   - string fields: "" means "don't change" (keep current value).
//   - bool fields: always copied from update (legacy behavior). Prefer
//     MergeParamsWithMask for field-mask semantics that avoid accidental
//     default-to-false updates.
//   - []string fields: nil or empty means "don't change" (keep current value).
//
// The returned Params is a fresh copy; neither current nor update is modified.
func MergeParams(current, update *types.Params) *types.Params {
	return MergeParamsWithMask(current, update, BoolFieldMask{
		RequireTeeAttestation: true,
		AllowZkmlFallback:     true,
		AllowSimulated:        true,
	})
}

// MergeParamsWithMask overlays non-zero/non-empty fields from update onto current,
// applying boolean fields only when their mask entry is true.
func MergeParamsWithMask(current, update *types.Params, mask BoolFieldMask) *types.Params {
	merged := &types.Params{
		// Start with current values
		MinValidators:                  current.MinValidators,
		ConsensusThreshold:             current.ConsensusThreshold,
		JobTimeoutBlocks:               current.JobTimeoutBlocks,
		BaseJobFee:                     current.BaseJobFee,
		VerificationReward:             current.VerificationReward,
		SlashingPenalty:                current.SlashingPenalty,
		MaxJobsPerBlock:                current.MaxJobsPerBlock,
		RequireTeeAttestation:          current.RequireTeeAttestation,
		AllowZkmlFallback:              current.AllowZkmlFallback,
		AllowSimulated:                 current.AllowSimulated,
		VoteExtensionMaxPastSkewSecs:   current.VoteExtensionMaxPastSkewSecs,
		VoteExtensionMaxFutureSkewSecs: current.VoteExtensionMaxFutureSkewSecs,
	}

	// Copy current AllowedProofTypes (deep copy)
	if len(current.AllowedProofTypes) > 0 {
		merged.AllowedProofTypes = make([]string, len(current.AllowedProofTypes))
		copy(merged.AllowedProofTypes, current.AllowedProofTypes)
	}

	// Apply non-zero int64 fields from update
	if update.MinValidators != 0 {
		merged.MinValidators = update.MinValidators
	}
	if update.ConsensusThreshold != 0 {
		merged.ConsensusThreshold = update.ConsensusThreshold
	}
	if update.JobTimeoutBlocks != 0 {
		merged.JobTimeoutBlocks = update.JobTimeoutBlocks
	}
	if update.MaxJobsPerBlock != 0 {
		merged.MaxJobsPerBlock = update.MaxJobsPerBlock
	}
	if update.VoteExtensionMaxPastSkewSecs != 0 {
		merged.VoteExtensionMaxPastSkewSecs = update.VoteExtensionMaxPastSkewSecs
	}
	if update.VoteExtensionMaxFutureSkewSecs != 0 {
		merged.VoteExtensionMaxFutureSkewSecs = update.VoteExtensionMaxFutureSkewSecs
	}

	// Apply non-empty string fields from update
	if update.BaseJobFee != "" {
		merged.BaseJobFee = update.BaseJobFee
	}
	if update.VerificationReward != "" {
		merged.VerificationReward = update.VerificationReward
	}
	if update.SlashingPenalty != "" {
		merged.SlashingPenalty = update.SlashingPenalty
	}

	// Apply bool fields only when explicitly flagged
	if mask.RequireTeeAttestation {
		merged.RequireTeeAttestation = update.RequireTeeAttestation
	}
	if mask.AllowZkmlFallback {
		merged.AllowZkmlFallback = update.AllowZkmlFallback
	}
	if mask.AllowSimulated {
		merged.AllowSimulated = update.AllowSimulated
	}

	// Apply non-empty []string fields from update
	if len(update.AllowedProofTypes) > 0 {
		merged.AllowedProofTypes = make([]string, len(update.AllowedProofTypes))
		copy(merged.AllowedProofTypes, update.AllowedProofTypes)
	}

	return merged
}

// ---------------------------------------------------------------------------
// DiffParams -- audit trail helpers
// ---------------------------------------------------------------------------

// ParamChangeRecord captures a full governance parameter change for audit purposes.
type ParamChangeRecord struct {
	Authority     string
	BlockHeight   int64
	Timestamp     time.Time
	ChangedFields []ParamFieldChange
}

// ParamFieldChange represents a single field difference between two Params.
type ParamFieldChange struct {
	Field    string
	OldValue string
	NewValue string
}

// DiffParams compares two Params structs field-by-field and returns a slice
// of ParamFieldChange for every field whose value differs. Both old and new
// values are formatted as strings for logging and event emission.
func DiffParams(old, new *types.Params) []ParamFieldChange {
	var changes []ParamFieldChange

	if old.MinValidators != new.MinValidators {
		changes = append(changes, ParamFieldChange{
			Field:    "min_validators",
			OldValue: strconv.FormatInt(old.MinValidators, 10),
			NewValue: strconv.FormatInt(new.MinValidators, 10),
		})
	}
	if old.ConsensusThreshold != new.ConsensusThreshold {
		changes = append(changes, ParamFieldChange{
			Field:    "consensus_threshold",
			OldValue: strconv.FormatInt(old.ConsensusThreshold, 10),
			NewValue: strconv.FormatInt(new.ConsensusThreshold, 10),
		})
	}
	if old.JobTimeoutBlocks != new.JobTimeoutBlocks {
		changes = append(changes, ParamFieldChange{
			Field:    "job_timeout_blocks",
			OldValue: strconv.FormatInt(old.JobTimeoutBlocks, 10),
			NewValue: strconv.FormatInt(new.JobTimeoutBlocks, 10),
		})
	}
	if old.BaseJobFee != new.BaseJobFee {
		changes = append(changes, ParamFieldChange{
			Field:    "base_job_fee",
			OldValue: old.BaseJobFee,
			NewValue: new.BaseJobFee,
		})
	}
	if old.VerificationReward != new.VerificationReward {
		changes = append(changes, ParamFieldChange{
			Field:    "verification_reward",
			OldValue: old.VerificationReward,
			NewValue: new.VerificationReward,
		})
	}
	if old.SlashingPenalty != new.SlashingPenalty {
		changes = append(changes, ParamFieldChange{
			Field:    "slashing_penalty",
			OldValue: old.SlashingPenalty,
			NewValue: new.SlashingPenalty,
		})
	}
	if old.MaxJobsPerBlock != new.MaxJobsPerBlock {
		changes = append(changes, ParamFieldChange{
			Field:    "max_jobs_per_block",
			OldValue: strconv.FormatInt(old.MaxJobsPerBlock, 10),
			NewValue: strconv.FormatInt(new.MaxJobsPerBlock, 10),
		})
	}
	if !stringSliceEqual(old.AllowedProofTypes, new.AllowedProofTypes) {
		changes = append(changes, ParamFieldChange{
			Field:    "allowed_proof_types",
			OldValue: fmt.Sprintf("%v", old.AllowedProofTypes),
			NewValue: fmt.Sprintf("%v", new.AllowedProofTypes),
		})
	}
	if old.RequireTeeAttestation != new.RequireTeeAttestation {
		changes = append(changes, ParamFieldChange{
			Field:    "require_tee_attestation",
			OldValue: strconv.FormatBool(old.RequireTeeAttestation),
			NewValue: strconv.FormatBool(new.RequireTeeAttestation),
		})
	}
	if old.AllowZkmlFallback != new.AllowZkmlFallback {
		changes = append(changes, ParamFieldChange{
			Field:    "allow_zkml_fallback",
			OldValue: strconv.FormatBool(old.AllowZkmlFallback),
			NewValue: strconv.FormatBool(new.AllowZkmlFallback),
		})
	}
	if old.AllowSimulated != new.AllowSimulated {
		changes = append(changes, ParamFieldChange{
			Field:    "allow_simulated",
			OldValue: strconv.FormatBool(old.AllowSimulated),
			NewValue: strconv.FormatBool(new.AllowSimulated),
		})
	}
	if old.VoteExtensionMaxPastSkewSecs != new.VoteExtensionMaxPastSkewSecs {
		changes = append(changes, ParamFieldChange{
			Field:    "vote_extension_max_past_skew_secs",
			OldValue: strconv.FormatInt(old.VoteExtensionMaxPastSkewSecs, 10),
			NewValue: strconv.FormatInt(new.VoteExtensionMaxPastSkewSecs, 10),
		})
	}
	if old.VoteExtensionMaxFutureSkewSecs != new.VoteExtensionMaxFutureSkewSecs {
		changes = append(changes, ParamFieldChange{
			Field:    "vote_extension_max_future_skew_secs",
			OldValue: strconv.FormatInt(old.VoteExtensionMaxFutureSkewSecs, 10),
			NewValue: strconv.FormatInt(new.VoteExtensionMaxFutureSkewSecs, 10),
		})
	}

	return changes
}

// stringSliceEqual reports whether two string slices contain the same elements
// in the same order.
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Event formatting
// ---------------------------------------------------------------------------

// FormatParamChangeEvent creates SDK events for a parameter update. It emits
// one top-level "params_updated" event and includes an attribute for each
// individual field change, making it straightforward to index and query
// parameter governance history.
func FormatParamChangeEvent(changes []ParamFieldChange) sdk.Events {
	if len(changes) == 0 {
		return nil
	}

	attrs := make([]sdk.Attribute, 0, len(changes)*2+1)
	attrs = append(attrs, sdk.NewAttribute("change_count", strconv.Itoa(len(changes))))

	for _, c := range changes {
		attrs = append(attrs,
			sdk.NewAttribute("changed_field", c.Field),
			sdk.NewAttribute(c.Field, c.NewValue),
		)
	}

	return sdk.Events{
		sdk.NewEvent("params_updated", attrs...),
	}
}

// ---------------------------------------------------------------------------
// UpdateParams handler (on msgServer)
// ---------------------------------------------------------------------------

// UpdateParams handles governance-driven parameter updates. Only the module
// authority (typically the governance module account) may invoke this handler.
//
// The update is applied as a partial merge: only non-zero / non-empty fields
// in msg.Params overwrite the current values. Bool fields are applied only
// when their corresponding msg.Has* flag is true (field-mask semantics).
//
// SECURITY: Enabling AllowSimulated is a one-way gate. Once disabled in
// production, it cannot be re-enabled through governance to prevent accidental
// or malicious activation of simulated proofs on a live network.
func (k msgServer) UpdateParams(goCtx context.Context, msg *MsgUpdateParams) (*MsgUpdateParamsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Step 1: Verify authority -- only governance may update parameters.
	if msg.Authority != k.GetAuthority() {
		return nil, fmt.Errorf("unauthorized: expected authority %s, got %s", k.GetAuthority(), msg.Authority)
	}

	// Step 2: Retrieve current parameters.
	currentParams, err := k.Keeper.GetParams(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current params: %w", err)
	}

	// SECURITY FIX (P2): Validate Has* flags for boolean param updates.
	// If a boolean in msg.Params differs from current but Has* flag is false,
	// this likely indicates a bug where the caller forgot to set the flag.
	// We error to prevent silent no-ops on intended governance updates.
	if msg.Params.RequireTeeAttestation != currentParams.RequireTeeAttestation && !msg.HasRequireTeeAttestation {
		return nil, fmt.Errorf(
			"require_tee_attestation differs from current (%v -> %v) but HasRequireTeeAttestation is false; "+
				"set the flag to confirm this is intentional",
			currentParams.RequireTeeAttestation, msg.Params.RequireTeeAttestation,
		)
	}
	if msg.Params.AllowZkmlFallback != currentParams.AllowZkmlFallback && !msg.HasAllowZkmlFallback {
		return nil, fmt.Errorf(
			"allow_zkml_fallback differs from current (%v -> %v) but HasAllowZkmlFallback is false; "+
				"set the flag to confirm this is intentional",
			currentParams.AllowZkmlFallback, msg.Params.AllowZkmlFallback,
		)
	}
	if msg.Params.AllowSimulated != currentParams.AllowSimulated && !msg.HasAllowSimulated {
		return nil, fmt.Errorf(
			"allow_simulated differs from current (%v -> %v) but HasAllowSimulated is false; "+
				"set the flag to confirm this is intentional",
			currentParams.AllowSimulated, msg.Params.AllowSimulated,
		)
	}

	// Step 3: Merge non-zero/non-empty fields from the update into current params.
	boolMask := BoolFieldMask{
		RequireTeeAttestation: msg.HasRequireTeeAttestation,
		AllowZkmlFallback:     msg.HasAllowZkmlFallback,
		AllowSimulated:        msg.HasAllowSimulated,
	}
	mergedParams := MergeParamsWithMask(currentParams, &msg.Params, boolMask)

	// Step 4: Validate the merged parameter set.
	if err := ValidateParams(mergedParams); err != nil {
		return nil, fmt.Errorf("invalid params after merge: %w", err)
	}

	// Step 5: SECURITY CHECK -- AllowSimulated is a one-way gate.
	// If simulation was previously disabled, it must not be re-enabled.
	if !currentParams.AllowSimulated && mergedParams.AllowSimulated {
		return nil, fmt.Errorf(
			"SECURITY: cannot enable AllowSimulated; simulation mode is a one-way gate and cannot be re-enabled once disabled",
		)
	}

	// Step 6: Persist the updated parameters.
	if err := k.Keeper.SetParams(ctx, mergedParams); err != nil {
		return nil, fmt.Errorf("failed to save params: %w", err)
	}

	// Step 7: Compute diff and emit events for observability.
	changes := DiffParams(currentParams, mergedParams)

	// Build and emit the audit record as SDK events.
	events := FormatParamChangeEvent(changes)
	if len(events) > 0 {
		ctx.EventManager().EmitEvents(events)
	}

	// Also emit an authority attribution event for indexers.
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			"params_updated",
			sdk.NewAttribute("authority", msg.Authority),
			sdk.NewAttribute("block_height", strconv.FormatInt(ctx.BlockHeight(), 10)),
		),
	)

	// Log the change summary for operator visibility.
	if len(changes) > 0 {
		ctx.Logger().Info(
			"module params updated via governance",
			"authority", msg.Authority,
			"changed_fields_count", len(changes),
			"block_height", ctx.BlockHeight(),
		)
	}

	if len(changes) > 0 && k.Keeper.auditLogger != nil {
		k.Keeper.auditLogger.AuditParamChange(ctx, msg.Authority, changes)
	}

	return &MsgUpdateParamsResponse{}, nil
}
