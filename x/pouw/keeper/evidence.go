package keeper

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"cosmossdk.io/log"
	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// ---------------------------------------------------------------------------
// Evidence types (local to the pouw module)
// ---------------------------------------------------------------------------

// SlashingEvidenceRecord tracks evidence of validator misbehavior detected
// during consensus. These records are self-contained so they can be forwarded
// to the validator module's slashing system by the ABCI layer without
// creating a circular dependency between pouw and validator keepers.
type SlashingEvidenceRecord struct {
	ValidatorAddress string
	Condition        string // Maps to validator keeper SlashingCondition constants
	JobID            string
	BlockHeight      int64
	Timestamp        time.Time

	// Evidence data
	ExpectedOutput     []byte
	ActualOutput       []byte
	ConflictingOutputs []ConflictingOutput

	// Metadata
	DetectedBy string // "consensus", "vote_extension", "end_block"
	Severity   string // "low", "medium", "high", "critical"
	Processed  bool
}

// ConflictingOutput represents a single output entry used as evidence
// for double-sign or collusion detection.
type ConflictingOutput struct {
	OutputHash []byte
	Timestamp  time.Time
	Height     int64
}

// ---------------------------------------------------------------------------
// EvidenceCollector
// ---------------------------------------------------------------------------

// EvidenceCollector bridges consensus results to validator-level slashing by
// scanning vote extensions for misbehaviour after a consensus round.
type EvidenceCollector struct {
	logger log.Logger
	keeper *Keeper
}

// NewEvidenceCollector creates a new EvidenceCollector.
func NewEvidenceCollector(logger log.Logger, keeper *Keeper) *EvidenceCollector {
	return &EvidenceCollector{
		logger: logger,
		keeper: keeper,
	}
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

// CollectEvidenceFromConsensus is called after consensus is reached for one or
// more jobs. It compares each validator's output against the consensus output
// and looks for double-signing and collusion patterns.
func (ec *EvidenceCollector) CollectEvidenceFromConsensus(
	ctx sdk.Context,
	aggregated map[string]*AggregatedResult,
	allVotes []VoteExtensionWire,
) []SlashingEvidenceRecord {
	var allEvidence []SlashingEvidenceRecord

	for jobID, result := range aggregated {
		if !result.HasConsensus {
			continue
		}

		consensusOutput := result.OutputHash

		// Detect validators that submitted an incorrect output.
		invalidOutputEvidence := ec.DetectInvalidOutputs(ctx, jobID, consensusOutput, allVotes)
		allEvidence = append(allEvidence, invalidOutputEvidence...)

		// Detect validators that submitted multiple different outputs (double sign).
		doubleSignEvidence := ec.DetectDoubleSigners(ctx, jobID, allVotes)
		allEvidence = append(allEvidence, doubleSignEvidence...)

		// Detect groups of validators that may be colluding.
		totalVoters := countDistinctVoters(allVotes)
		collusionEvidence := ec.DetectColludingValidators(ctx, jobID, consensusOutput, allVotes, totalVoters)
		allEvidence = append(allEvidence, collusionEvidence...)
	}

	if len(allEvidence) > 0 {
		ec.logger.Warn("Evidence collected from consensus",
			"total_records", len(allEvidence),
			"height", ctx.BlockHeight(),
		)
	}

	return allEvidence
}

// ---------------------------------------------------------------------------
// Invalid output detection
// ---------------------------------------------------------------------------

// DetectInvalidOutputs iterates through all vote extensions and flags any
// validator whose successful verification output differs from the consensus
// output for the given job.
func (ec *EvidenceCollector) DetectInvalidOutputs(
	ctx sdk.Context,
	jobID string,
	consensusOutput []byte,
	allVotes []VoteExtensionWire,
) []SlashingEvidenceRecord {
	var evidence []SlashingEvidenceRecord
	blockTime := ctx.BlockTime()
	blockHeight := ctx.BlockHeight()

	for i := range allVotes {
		ext := &allVotes[i]
		validatorAddr := extractValidatorAddress(ext)
		if validatorAddr == "" {
			continue
		}

		for _, v := range ext.Verifications {
			if v.JobID != jobID || !v.Success {
				continue
			}

			if bytes.Equal(v.OutputHash, consensusOutput) {
				continue
			}

			// Mismatch detected -- build evidence.
			record := SlashingEvidenceRecord{
				ValidatorAddress: validatorAddr,
				Condition:        "invalid_output",
				JobID:            jobID,
				BlockHeight:      blockHeight,
				Timestamp:        blockTime,
				ExpectedOutput:   consensusOutput,
				ActualOutput:     v.OutputHash,
				DetectedBy:       "consensus",
				Severity:         "high",
			}

			evidence = append(evidence, record)

			ec.logger.Warn("Invalid output detected",
				"validator", validatorAddr,
				"job_id", jobID,
				"expected", hex.EncodeToString(consensusOutput),
				"actual", hex.EncodeToString(v.OutputHash),
			)
		}
	}

	return evidence
}

// ---------------------------------------------------------------------------
// Double-sign detection
// ---------------------------------------------------------------------------

// DetectDoubleSigners looks for validators that submitted two or more distinct
// output hashes for the same job within the same vote extension set.
func (ec *EvidenceCollector) DetectDoubleSigners(
	ctx sdk.Context,
	jobID string,
	allVotes []VoteExtensionWire,
) []SlashingEvidenceRecord {
	var evidence []SlashingEvidenceRecord
	blockTime := ctx.BlockTime()
	blockHeight := ctx.BlockHeight()

	// Collect all outputs per validator for this job.
	type outputEntry struct {
		hash      []byte
		timestamp time.Time
		height    int64
	}
	validatorOutputs := make(map[string][]outputEntry)

	for i := range allVotes {
		ext := &allVotes[i]
		validatorAddr := extractValidatorAddress(ext)
		if validatorAddr == "" {
			continue
		}

		for _, v := range ext.Verifications {
			if v.JobID != jobID || !v.Success {
				continue
			}

			validatorOutputs[validatorAddr] = append(validatorOutputs[validatorAddr], outputEntry{
				hash:      v.OutputHash,
				timestamp: ext.Timestamp,
				height:    ext.Height,
			})
		}
	}

	// Check each validator for conflicting outputs.
	for validatorAddr, outputs := range validatorOutputs {
		if len(outputs) < 2 {
			continue
		}

		// Deduplicate by output hash to see if there are genuinely different outputs.
		uniqueHashes := make(map[string]bool)
		for _, o := range outputs {
			uniqueHashes[hex.EncodeToString(o.hash)] = true
		}

		if len(uniqueHashes) < 2 {
			// All outputs are the same -- no double sign.
			continue
		}

		// Build conflicting outputs list.
		var conflicting []ConflictingOutput
		for _, o := range outputs {
			conflicting = append(conflicting, ConflictingOutput{
				OutputHash: o.hash,
				Timestamp:  o.timestamp,
				Height:     o.height,
			})
		}

		record := SlashingEvidenceRecord{
			ValidatorAddress:   validatorAddr,
			Condition:          "double_sign",
			JobID:              jobID,
			BlockHeight:        blockHeight,
			Timestamp:          blockTime,
			ConflictingOutputs: conflicting,
			DetectedBy:         "consensus",
			Severity:           "critical",
		}

		evidence = append(evidence, record)

		ec.logger.Error("Double sign detected",
			"validator", validatorAddr,
			"job_id", jobID,
			"distinct_outputs", len(uniqueHashes),
		)
	}

	return evidence
}

// ---------------------------------------------------------------------------
// Collusion detection
// ---------------------------------------------------------------------------

// DetectColludingValidators identifies groups of 2+ validators that all
// submitted the same incorrect output (i.e. an output different from the
// consensus output). Such a cluster may indicate collusion.
func (ec *EvidenceCollector) DetectColludingValidators(
	ctx sdk.Context,
	jobID string,
	consensusOutput []byte,
	allVotes []VoteExtensionWire,
	totalVoters int,
) []SlashingEvidenceRecord {
	var evidence []SlashingEvidenceRecord
	blockTime := ctx.BlockTime()
	blockHeight := ctx.BlockHeight()

	// Group validators by the wrong output they submitted.
	wrongClusters := make(map[string][]string) // hex(outputHash) -> list of validator addresses
	consensusHex := hex.EncodeToString(consensusOutput)

	for i := range allVotes {
		ext := &allVotes[i]
		validatorAddr := extractValidatorAddress(ext)
		if validatorAddr == "" {
			continue
		}

		for _, v := range ext.Verifications {
			if v.JobID != jobID || !v.Success {
				continue
			}

			outputHex := hex.EncodeToString(v.OutputHash)
			if outputHex == consensusHex {
				continue
			}

			wrongClusters[outputHex] = append(wrongClusters[outputHex], validatorAddr)
		}
	}

	// Flag clusters with 2+ validators as potential collusion.
	for outputHex, validators := range wrongClusters {
		if len(validators) < 2 {
			continue
		}

		outputHash, err := hex.DecodeString(outputHex)
		if err != nil {
			ec.logger.Error("Failed to decode output hash in collusion detection",
				"output_hex", outputHex,
				"error", err,
			)
			continue
		}

		for _, validatorAddr := range validators {
			record := SlashingEvidenceRecord{
				ValidatorAddress: validatorAddr,
				Condition:        "collusion",
				JobID:            jobID,
				BlockHeight:      blockHeight,
				Timestamp:        blockTime,
				ExpectedOutput:   consensusOutput,
				ActualOutput:     outputHash,
				DetectedBy:       "consensus",
				Severity:         "critical",
			}

			evidence = append(evidence, record)
		}

		ec.logger.Error("Potential collusion detected",
			"job_id", jobID,
			"wrong_output", outputHex[:16],
			"colluding_validators", len(validators),
			"total_voters", totalVoters,
		)
	}

	return evidence
}

// ---------------------------------------------------------------------------
// Penalty application
// ---------------------------------------------------------------------------

// ApplySlashingPenalties applies economic penalties for each evidence record.
// For each record it:
//  1. Parses the base slashing penalty from module params.
//  2. Scales the penalty by the severity multiplier.
//  3. Sends coins from the validator account to the pouw module, then burns them.
//  4. Emits an event and marks the record as processed.
//
// Returns a slice of errors (nil entries indicate success).
func (ec *EvidenceCollector) ApplySlashingPenalties(
	ctx sdk.Context,
	evidenceRecords []SlashingEvidenceRecord,
) []error {
	errs := make([]error, len(evidenceRecords))

	// Retrieve the base slashing penalty from module params.
	params, _ := ec.keeper.GetParams(ctx)
	basePenalty, parseErr := sdk.ParseCoinNormalized(params.SlashingPenalty)
	if parseErr != nil {
		// If the penalty string is unparseable, use a sensible default.
		basePenalty = sdk.NewInt64Coin("uaeth", 10000)
		ec.logger.Warn("Failed to parse slashing penalty from params, using default",
			"error", parseErr,
			"default", basePenalty.String(),
		)
	}

	for i := range evidenceRecords {
		record := &evidenceRecords[i]

		// Scale penalty by severity.
		multiplier := SeverityMultiplier(record.Severity)
		scaledAmount := multiplier.MulInt(basePenalty.Amount).TruncateInt()
		if scaledAmount.IsZero() {
			record.Processed = true
			continue
		}
		penaltyCoins := sdk.NewCoins(sdk.NewCoin(basePenalty.Denom, scaledAmount))

		// Resolve validator address.
		valAddr, addrErr := sdk.AccAddressFromBech32(record.ValidatorAddress)
		if addrErr != nil {
			errs[i] = fmt.Errorf("invalid validator address %s: %w", record.ValidatorAddress, addrErr)
			ec.logger.Error("Skipping slashing for invalid address",
				"validator", record.ValidatorAddress,
				"error", addrErr,
			)
			continue
		}

		// Check balance.
		spendable := ec.keeper.bankKeeper.SpendableCoins(ctx, valAddr)
		if !spendable.IsAllGTE(penaltyCoins) {
			errs[i] = fmt.Errorf("validator %s has insufficient funds for slashing: need %s, have %s",
				record.ValidatorAddress, penaltyCoins.String(), spendable.String())
			ec.logger.Warn("Validator has insufficient funds for evidence slashing",
				"validator", record.ValidatorAddress,
				"required", penaltyCoins.String(),
				"available", spendable.String(),
			)
			continue
		}

		// Transfer from validator to module.
		if sendErr := ec.keeper.bankKeeper.SendCoinsFromAccountToModule(
			ctx, valAddr, types.ModuleName, penaltyCoins,
		); sendErr != nil {
			errs[i] = fmt.Errorf("failed to collect penalty from %s: %w", record.ValidatorAddress, sendErr)
			ec.logger.Error("Failed to collect slashing penalty",
				"validator", record.ValidatorAddress,
				"error", sendErr,
			)
			continue
		}

		// Burn the collected tokens.
		if burnErr := ec.keeper.bankKeeper.BurnCoins(ctx, types.ModuleName, penaltyCoins); burnErr != nil {
			errs[i] = fmt.Errorf("failed to burn penalty tokens for %s: %w", record.ValidatorAddress, burnErr)
			ec.logger.Error("Failed to burn slashed tokens",
				"validator", record.ValidatorAddress,
				"error", burnErr,
			)
			continue
		}

		// Emit event.
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				"evidence_slashing_applied",
				sdk.NewAttribute("validator", record.ValidatorAddress),
				sdk.NewAttribute("condition", record.Condition),
				sdk.NewAttribute("severity", record.Severity),
				sdk.NewAttribute("penalty_amount", penaltyCoins.String()),
				sdk.NewAttribute("job_id", record.JobID),
				sdk.NewAttribute("block_height", fmt.Sprintf("%d", record.BlockHeight)),
				sdk.NewAttribute("detected_by", record.DetectedBy),
			),
		)

		record.Processed = true

		ec.logger.Info("Slashing penalty applied",
			"validator", record.ValidatorAddress,
			"condition", record.Condition,
			"severity", record.Severity,
			"penalty", penaltyCoins.String(),
			"job_id", record.JobID,
		)
		if ec.keeper != nil && ec.keeper.auditLogger != nil {
			ec.keeper.auditLogger.AuditSlashingApplied(ctx, record.ValidatorAddress, record.Condition, record.Severity, penaltyCoins.String(), record.JobID)
		}
	}

	return errs
}

// ---------------------------------------------------------------------------
// Missed Block Tracking
// ---------------------------------------------------------------------------

// MissedBlockTracker tracks validator participation for downtime detection.
// This is integrated with the EvidenceCollector to generate slashing evidence
// for validators that miss too many consecutive blocks.
type MissedBlockTracker struct {
	// missedCounts tracks consecutive missed blocks per validator
	missedCounts map[string]int64

	// lastSignedHeight tracks the last block each validator signed
	lastSignedHeight map[string]int64

	// threshold is the number of consecutive missed blocks before evidence is generated
	threshold int64
}

// NewMissedBlockTracker creates a new missed block tracker.
func NewMissedBlockTracker(threshold int64) *MissedBlockTracker {
	if threshold <= 0 {
		threshold = 100 // Default: ~10 minutes at 6s blocks
	}
	return &MissedBlockTracker{
		missedCounts:     make(map[string]int64),
		lastSignedHeight: make(map[string]int64),
		threshold:        threshold,
	}
}

// RecordSignature records that a validator signed a block at the given height.
func (m *MissedBlockTracker) RecordSignature(validatorAddr string, height int64) {
	m.missedCounts[validatorAddr] = 0 // Reset consecutive misses
	m.lastSignedHeight[validatorAddr] = height
}

// RecordMiss records that a validator missed a block at the given height.
// Returns true if the validator has now exceeded the threshold.
func (m *MissedBlockTracker) RecordMiss(validatorAddr string, height int64) bool {
	m.missedCounts[validatorAddr]++
	return m.missedCounts[validatorAddr] >= m.threshold
}

// GetMissedCount returns the current consecutive missed block count for a validator.
func (m *MissedBlockTracker) GetMissedCount(validatorAddr string) int64 {
	return m.missedCounts[validatorAddr]
}

// GetLastSignedHeight returns the last height at which the validator signed.
func (m *MissedBlockTracker) GetLastSignedHeight(validatorAddr string) int64 {
	return m.lastSignedHeight[validatorAddr]
}

// GetThreshold returns the configured threshold.
func (m *MissedBlockTracker) GetThreshold() int64 {
	return m.threshold
}

// Reset resets the missed count for a validator (e.g., after they come back online).
func (m *MissedBlockTracker) Reset(validatorAddr string) {
	m.missedCounts[validatorAddr] = 0
}

// ---------------------------------------------------------------------------
// End-block evidence processing
// ---------------------------------------------------------------------------

// ProcessEndBlockEvidence is called at the end of each block to perform
// periodic evidence checks such as downtime detection.
//
// It checks for validators that have missed too many consecutive blocks
// and generates slashing evidence for them.
func (ec *EvidenceCollector) ProcessEndBlockEvidence(ctx sdk.Context) error {
	ec.logger.Debug("Processing end-block evidence checks",
		"height", ctx.BlockHeight(),
	)

	// Get missed block threshold from liveness tracker (or use default)
	// Default: 100 consecutive blocks (~10 minutes at 6s blocks)
	threshold := int64(100)
	if ec.keeper != nil && ec.keeper.livenessTracker != nil {
		threshold = ec.keeper.livenessTracker.GetThreshold()
	}

	// Process missed block evidence using the liveness tracker from remediation.go
	missedValidators := ec.checkMissedBlocks(ctx, threshold)

	var evidence []SlashingEvidenceRecord
	for _, mv := range missedValidators {
		record := SlashingEvidenceRecord{
			ValidatorAddress: mv.ValidatorAddr,
			Condition:        "downtime",
			JobID:            "", // Downtime is not job-specific
			BlockHeight:      ctx.BlockHeight(),
			Timestamp:        ctx.BlockTime(),
			DetectedBy:       "end_block",
			Severity:         "low", // Downtime has lowest severity
		}
		evidence = append(evidence, record)

		ec.logger.Warn("Validator downtime detected",
			"validator", mv.ValidatorAddr,
			"consecutive_misses", mv.ConsecutiveMisses,
			"threshold", threshold,
		)
	}
	if ec.keeper != nil && ec.keeper.auditLogger != nil {
		for _, record := range evidence {
			ec.keeper.auditLogger.AuditEvidenceDetected(ctx, record.ValidatorAddress, record.Condition, record.DetectedBy, record.JobID)
		}
	}

	// Apply penalties if any evidence was collected
	if len(evidence) > 0 {
		errs := ec.ApplySlashingPenalties(ctx, evidence)
		for i, err := range errs {
			if err != nil {
				ec.logger.Error("Failed to apply downtime penalty",
					"validator", evidence[i].ValidatorAddress,
					"error", err,
				)
			}
		}
	}

	return nil
}

// MissedBlockInfo contains information about a validator that has missed blocks.
type MissedBlockInfo struct {
	ValidatorAddr     string
	ConsecutiveMisses int64
	LastActiveBlock   int64
}

// checkMissedBlocks checks for validators that have exceeded the missed block threshold.
// This integrates with the LivenessTracker from remediation.go if available.
func (ec *EvidenceCollector) checkMissedBlocks(ctx sdk.Context, threshold int64) []MissedBlockInfo {
	var result []MissedBlockInfo

	// If we have access to the LivenessTracker through the keeper, use it
	if ec.keeper != nil && ec.keeper.livenessTracker != nil {
		unresponsive := ec.keeper.livenessTracker.GetUnresponsiveValidators()
		for _, addr := range unresponsive {
			record, ok := ec.keeper.livenessTracker.GetRecord(addr)
			if ok && record.ConsecutiveMisses >= threshold {
				result = append(result, MissedBlockInfo{
					ValidatorAddr:     addr,
					ConsecutiveMisses: record.ConsecutiveMisses,
					LastActiveBlock:   record.LastActiveBlock,
				})
			}
		}
	}

	return result
}

// ---------------------------------------------------------------------------
// Severity multiplier
// ---------------------------------------------------------------------------

// SeverityMultiplier returns the penalty scaling factor for a given severity
// level. Unknown severities default to 1.0x.
func SeverityMultiplier(severity string) sdkmath.LegacyDec {
	switch severity {
	case "low":
		return sdkmath.LegacyNewDecWithPrec(25, 2) // 0.25
	case "medium":
		return sdkmath.LegacyNewDecWithPrec(50, 2) // 0.50
	case "high":
		return sdkmath.LegacyOneDec() // 1.0
	case "critical":
		return sdkmath.LegacyNewDec(2) // 2.0
	default:
		return sdkmath.LegacyOneDec() // 1.0
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// extractValidatorAddress parses the ValidatorAddress string out of a
// VoteExtensionWire's json.RawMessage field.
func extractValidatorAddress(ext *VoteExtensionWire) string {
	if ext == nil || len(ext.ValidatorAddress) == 0 {
		return ""
	}
	var addr string
	if err := json.Unmarshal(ext.ValidatorAddress, &addr); err != nil {
		return ""
	}
	return addr
}

// countDistinctVoters returns the number of unique validator addresses across
// a set of vote extensions.
func countDistinctVoters(votes []VoteExtensionWire) int {
	seen := make(map[string]bool)
	for i := range votes {
		addr := extractValidatorAddress(&votes[i])
		if addr != "" {
			seen[addr] = true
		}
	}
	return len(seen)
}
