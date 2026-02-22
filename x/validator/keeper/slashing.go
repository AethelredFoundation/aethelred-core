package keeper

import (
	"context"
	"fmt"
	"time"

	sdkmath "cosmossdk.io/math"
	"github.com/aethelred/aethelred/x/validator/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SlashingCondition defines when a validator should be slashed
type SlashingCondition string

const (
	// SlashingConditionInvalidOutput - validator reported wrong output hash
	SlashingConditionInvalidOutput SlashingCondition = "invalid_output"

	// SlashingConditionFakeAttestation - validator submitted fake TEE attestation
	SlashingConditionFakeAttestation SlashingCondition = "fake_attestation"

	// SlashingConditionInvalidProof - validator submitted invalid zkML proof
	SlashingConditionInvalidProof SlashingCondition = "invalid_proof"

	// SlashingConditionDoubleSign - validator submitted conflicting results
	SlashingConditionDoubleSign SlashingCondition = "double_sign"

	// SlashingConditionDowntime - validator failed to respond
	SlashingConditionDowntime SlashingCondition = "downtime"

	// SlashingConditionCollusion - validators colluded to produce wrong result
	SlashingConditionCollusion SlashingCondition = "collusion"
)

// SlashingFractions defines the percentage to slash for each condition
var SlashingFractions = map[SlashingCondition]string{
	SlashingConditionInvalidOutput:   "1.00", // 100% slash + tombstone for fraudulent inference outputs
	SlashingConditionFakeAttestation: "1.00", // 100% slash - malicious/fraudulent
	SlashingConditionInvalidProof:    "0.10", // 10% slash
	SlashingConditionDoubleSign:      "0.50", // 50% slash - severe
	SlashingConditionDowntime:        "0.05", // 5% slash
	SlashingConditionCollusion:       "1.00", // 100% slash - most severe
}

// JailableConditions defines which conditions result in jailing
var JailableConditions = map[SlashingCondition]bool{
	SlashingConditionInvalidOutput:   true,
	SlashingConditionFakeAttestation: true,
	SlashingConditionDoubleSign:      true,
	SlashingConditionDowntime:        true,
	SlashingConditionCollusion:       true,
}

// TombstoneConditions defines which conditions permanently ban validators.
var TombstoneConditions = map[SlashingCondition]bool{
	SlashingConditionInvalidOutput:   true,
	SlashingConditionFakeAttestation: true,
	SlashingConditionCollusion:       true,
}

const downtimeJailDuration = time.Hour

// SlashingParams contains parameters for slashing
type SlashingParams struct {
	// MinReportsForSlashing is the minimum reports needed before slashing
	MinReportsForSlashing int

	// MaxMissedBlocksForDowntime is the max blocks before downtime slashing
	MaxMissedBlocksForDowntime int64

	// DoubleSignWindow is the window for detecting double signing
	DoubleSignWindow int64

	// SlashingReportExpiry is how long slashing evidence is valid
	SlashingReportExpiry time.Duration
}

// DefaultSlashingParams returns default slashing parameters
func DefaultSlashingParams() SlashingParams {
	return SlashingParams{
		MinReportsForSlashing:      3,
		MaxMissedBlocksForDowntime: 100,
		DoubleSignWindow:           10,
		SlashingReportExpiry:       24 * time.Hour,
	}
}

// SlashingReport represents a report of misbehavior
type SlashingReport struct {
	// ReporterAddress is who reported the misbehavior
	ReporterAddress string `json:"reporter_address"`

	// ValidatorAddress is the accused validator
	ValidatorAddress string `json:"validator_address"`

	// Condition is the type of misbehavior
	Condition SlashingCondition `json:"condition"`

	// JobID related to the misbehavior (if applicable)
	JobID string `json:"job_id,omitempty"`

	// Evidence contains proof of misbehavior
	Evidence SlashingEvidence `json:"evidence"`

	// Height at which misbehavior occurred
	Height int64 `json:"height"`

	// Timestamp when reported
	Timestamp time.Time `json:"timestamp"`

	// Status of the report
	Status string `json:"status"`
}

// SlashingEvidence contains evidence of misbehavior
type SlashingEvidence struct {
	// ExpectedOutput is what the output should have been
	ExpectedOutput []byte `json:"expected_output,omitempty"`

	// ActualOutput is what the validator reported
	ActualOutput []byte `json:"actual_output,omitempty"`

	// ConflictingResults for double-sign detection
	ConflictingResults []OutputWithTimestamp `json:"conflicting_results,omitempty"`

	// InvalidAttestation is the fake attestation data
	InvalidAttestation []byte `json:"invalid_attestation,omitempty"`

	// InvalidProof is the invalid zkML proof
	InvalidProof []byte `json:"invalid_proof,omitempty"`

	// MissedBlocks for downtime detection
	MissedBlocks []int64 `json:"missed_blocks,omitempty"`

	// AdditionalData for any other evidence
	AdditionalData map[string]string `json:"additional_data,omitempty"`
}

// OutputWithTimestamp represents an output with its timestamp
type OutputWithTimestamp struct {
	OutputHash []byte    `json:"output_hash"`
	Timestamp  time.Time `json:"timestamp"`
	Height     int64     `json:"height"`
}

// SlashDowntime applies the graduated downtime penalty (5% + 1 hour jail).
func (k Keeper) SlashDowntime(
	ctx context.Context,
	validatorAddr string,
	missedBlocks []int64,
) error {
	return k.SlashValidator(
		ctx,
		validatorAddr,
		SlashingConditionDowntime,
		SlashingEvidence{MissedBlocks: missedBlocks},
		"",
	)
}

// SlashFraud applies the fraud penalty (100% slash + permanent tombstone).
func (k Keeper) SlashFraud(
	ctx context.Context,
	validatorAddr string,
	jobID string,
	expectedOutput []byte,
	actualOutput []byte,
) error {
	return k.SlashValidator(
		ctx,
		validatorAddr,
		SlashingConditionInvalidOutput,
		SlashingEvidence{
			ExpectedOutput: expectedOutput,
			ActualOutput:   actualOutput,
		},
		jobID,
	)
}

// SlashValidator slashes a validator for misbehavior
func (k Keeper) SlashValidator(
	ctx context.Context,
	validatorAddr string,
	condition SlashingCondition,
	evidence SlashingEvidence,
	jobID string,
) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	if tombstoned, err := k.TombstonedValidators.Has(ctx, validatorAddr); err == nil && tombstoned {
		return fmt.Errorf("validator %s is permanently tombstoned", validatorAddr)
	}

	// Get the slash fraction for this condition
	fractionStr, ok := SlashingFractions[condition]
	if !ok {
		return fmt.Errorf("unknown slashing condition: %s", condition)
	}

	fraction, err := sdkmath.LegacyNewDecFromStr(fractionStr)
	if err != nil {
		return fmt.Errorf("invalid slash fraction: %w", err)
	}

	// Check if this condition results in jailing
	shouldJail := JailableConditions[condition]
	shouldTombstone := TombstoneConditions[condition]

	// Record the slashing
	record := &types.SlashingRecord{
		ValidatorAddress: validatorAddr,
		Height:           sdkCtx.BlockHeight(),
		Reason:           string(condition),
		SlashFraction:    fractionStr,
		Jailed:           shouldJail,
		Timestamp:        timestamppb.Now(),
		JobId:            jobID,
	}

	recordKey := fmt.Sprintf("%s:%d", validatorAddr, sdkCtx.BlockHeight())
	if err := k.SlashingRecords.Set(ctx, recordKey, *record); err != nil {
		return fmt.Errorf("failed to record slashing: %w", err)
	}

	// Update validator's reputation
	capability, err := k.GetHardwareCapability(ctx, validatorAddr)
	if err == nil {
		if capability.Status == nil {
			capability.Status = &types.CapabilityStatus{}
		}
		// Slash reputation based on condition severity
		reputationPenalty := int64(float64(capability.Status.ReputationScore) * float64(fraction.MustFloat64()))
		capability.Status.ReputationScore -= reputationPenalty
		if capability.Status.ReputationScore < 0 {
			capability.Status.ReputationScore = 0
		}

		if shouldJail {
			capability.Status.Online = false
		}

		_ = k.HardwareCapabilities.Set(ctx, validatorAddr, *capability)
	}

	if shouldJail {
		jailUntil := sdkCtx.BlockTime().Add(downtimeJailDuration).Unix()
		if condition == SlashingConditionDowntime {
			_ = k.ValidatorJailUntil.Set(ctx, validatorAddr, jailUntil)
		}
	}
	if shouldTombstone {
		_ = k.TombstonedValidators.Set(ctx, validatorAddr)
		_ = k.ValidatorJailUntil.Remove(ctx, validatorAddr)
	}

	// In production: call staking/slashing keeper to actually slash tokens
	// For MVP, we just record the event and update reputation

	k.logger.Error("Validator slashed",
		"validator", validatorAddr,
		"condition", condition,
		"fraction", fractionStr,
		"jailed", shouldJail,
		"tombstoned", shouldTombstone,
		"job_id", jobID,
	)

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"validator_slashed",
			sdk.NewAttribute("validator_address", validatorAddr),
			sdk.NewAttribute("condition", string(condition)),
			sdk.NewAttribute("slash_fraction", fractionStr),
			sdk.NewAttribute("jailed", fmt.Sprintf("%t", shouldJail)),
			sdk.NewAttribute("tombstoned", fmt.Sprintf("%t", shouldTombstone)),
			sdk.NewAttribute("job_id", jobID),
		),
	)

	return nil
}

// ReportMisbehavior files a report of validator misbehavior
func (k Keeper) ReportMisbehavior(ctx context.Context, report *SlashingReport) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Validate the report
	if err := k.validateSlashingReport(ctx, report); err != nil {
		return fmt.Errorf("invalid slashing report: %w", err)
	}

	report.Timestamp = time.Now().UTC()
	report.Height = sdkCtx.BlockHeight()
	report.Status = "pending"

	// For simplicity in MVP, immediately process the report
	// In production, this would go through a dispute resolution process
	return k.SlashValidator(ctx, report.ValidatorAddress, report.Condition, report.Evidence, report.JobID)
}

// validateSlashingReport validates a slashing report
func (k Keeper) validateSlashingReport(ctx context.Context, report *SlashingReport) error {
	if len(report.ValidatorAddress) == 0 {
		return fmt.Errorf("validator address cannot be empty")
	}

	if len(report.ReporterAddress) == 0 {
		return fmt.Errorf("reporter address cannot be empty")
	}

	// Validate condition-specific evidence
	switch report.Condition {
	case SlashingConditionInvalidOutput:
		if len(report.Evidence.ExpectedOutput) == 0 || len(report.Evidence.ActualOutput) == 0 {
			return fmt.Errorf("invalid output condition requires expected and actual outputs")
		}

	case SlashingConditionFakeAttestation:
		if len(report.Evidence.InvalidAttestation) == 0 {
			return fmt.Errorf("fake attestation condition requires attestation data")
		}

	case SlashingConditionInvalidProof:
		if len(report.Evidence.InvalidProof) == 0 {
			return fmt.Errorf("invalid proof condition requires proof data")
		}

	case SlashingConditionDoubleSign:
		if len(report.Evidence.ConflictingResults) < 2 {
			return fmt.Errorf("double sign condition requires at least 2 conflicting results")
		}

	case SlashingConditionDowntime:
		if len(report.Evidence.MissedBlocks) == 0 {
			return fmt.Errorf("downtime condition requires missed blocks")
		}
	}

	return nil
}

// DetectInvalidOutput checks if a validator reported wrong output
func (k Keeper) DetectInvalidOutput(
	ctx context.Context,
	validatorAddr string,
	jobID string,
	reportedOutput []byte,
	consensusOutput []byte,
) bool {
	// If outputs don't match and consensus was reached, this is invalid
	if len(reportedOutput) != len(consensusOutput) {
		return true
	}

	for i := range reportedOutput {
		if reportedOutput[i] != consensusOutput[i] {
			return true
		}
	}

	return false
}

// DetectDoubleSign checks if a validator submitted conflicting results
func (k Keeper) DetectDoubleSign(
	ctx context.Context,
	validatorAddr string,
	jobID string,
	results []OutputWithTimestamp,
) bool {
	if len(results) < 2 {
		return false
	}

	// Check if there are different outputs for the same job
	firstOutput := results[0].OutputHash
	for i := 1; i < len(results); i++ {
		if len(firstOutput) != len(results[i].OutputHash) {
			return true
		}
		for j := range firstOutput {
			if firstOutput[j] != results[i].OutputHash[j] {
				return true
			}
		}
	}

	return false
}

// GetSlashingRecords returns all slashing records for a validator
func (k Keeper) GetSlashingRecords(ctx context.Context, validatorAddr string) []*types.SlashingRecord {
	var records []*types.SlashingRecord

	_ = k.SlashingRecords.Walk(ctx, nil, func(key string, record types.SlashingRecord) (bool, error) {
		if record.ValidatorAddress == validatorAddr {
			recordCopy := record
			records = append(records, &recordCopy)
		}
		return false, nil
	})

	return records
}

// GetRecentSlashingRecords returns recent slashing records
func (k Keeper) GetRecentSlashingRecords(ctx context.Context, limit int) []*types.SlashingRecord {
	var records []*types.SlashingRecord

	_ = k.SlashingRecords.Walk(ctx, nil, func(key string, record types.SlashingRecord) (bool, error) {
		recordCopy := record
		records = append(records, &recordCopy)
		return len(records) >= limit, nil
	})

	return records
}

// ProcessEndBlock handles end-of-block slashing checks
func (k Keeper) ProcessEndBlock(ctx context.Context) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Check for downtime
	params := DefaultSlashingParams()
	k.CheckInactiveValidators(ctx, time.Duration(params.MaxMissedBlocksForDowntime)*6*time.Second) // ~6 seconds per block

	k.logger.Debug("End block slashing checks completed",
		"height", sdkCtx.BlockHeight(),
	)

	return nil
}
