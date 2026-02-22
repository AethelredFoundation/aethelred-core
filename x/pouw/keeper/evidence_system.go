// Package keeper provides the complete evidence system for Aethelred's Proof-of-Useful-Work
// consensus, including block-miss tracking, double-voting detection, and slashing integration.
//
// SECURITY CRITICAL: This module enforces validator accountability and economic penalties
// for misbehavior. All evidence must be cryptographically verifiable and deterministic.
package keeper

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"cosmossdk.io/log"
	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// =============================================================================
// Block-Miss Tracker
// =============================================================================

// BlockMissTracker tracks validator participation and detects downtime/liveness failures.
// Validators are expected to participate in vote extensions for every block where they
// have assigned jobs. Missing too many blocks results in slashing.
type BlockMissTracker struct {
	mu sync.RWMutex

	// missedBlocks maps validator address to list of missed block heights
	missedBlocks map[string][]int64

	// participationWindow is the number of blocks to track (rolling window)
	participationWindow int64

	// maxMissedBlocks is the maximum allowed missed blocks before slashing
	maxMissedBlocks int64

	// jailThreshold is the number of missed blocks that triggers jailing
	jailThreshold int64

	// keeper for state access
	keeper *Keeper

	// logger for audit trail
	logger log.Logger
}

// BlockMissConfig contains configuration for block-miss tracking
type BlockMissConfig struct {
	// ParticipationWindow is the rolling window size in blocks
	ParticipationWindow int64

	// MaxMissedBlocks before downtime slashing
	MaxMissedBlocks int64

	// JailThreshold for jailing (usually higher than slash threshold)
	JailThreshold int64

	// DowntimeSlashBps is the slashing penalty in basis points (e.g., 500 = 5%)
	DowntimeSlashBps int64
}

// DefaultBlockMissConfig returns the default block-miss configuration
func DefaultBlockMissConfig() BlockMissConfig {
	return BlockMissConfig{
		ParticipationWindow: 10000, // ~16.6 hours with 6s blocks
		MaxMissedBlocks:     500,   // 5% miss rate before slashing
		JailThreshold:       1000,  // 10% miss rate before jailing
		DowntimeSlashBps:    500,   // 5% slash for downtime
	}
}

// NewBlockMissTracker creates a new block-miss tracker
func NewBlockMissTracker(logger log.Logger, keeper *Keeper, config BlockMissConfig) *BlockMissTracker {
	return &BlockMissTracker{
		missedBlocks:        make(map[string][]int64),
		participationWindow: config.ParticipationWindow,
		maxMissedBlocks:     config.MaxMissedBlocks,
		jailThreshold:       config.JailThreshold,
		keeper:              keeper,
		logger:              logger,
	}
}

// RecordMiss records a missed block for a validator
func (t *BlockMissTracker) RecordMiss(validatorAddr string, blockHeight int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.missedBlocks[validatorAddr] = append(t.missedBlocks[validatorAddr], blockHeight)
	t.pruneOldMisses(validatorAddr, blockHeight)

	t.logger.Debug("Block miss recorded",
		"validator", validatorAddr,
		"height", blockHeight,
		"total_misses", len(t.missedBlocks[validatorAddr]),
	)
}

// RecordParticipation records successful participation (clears recent misses from window)
func (t *BlockMissTracker) RecordParticipation(validatorAddr string, blockHeight int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Participation doesn't remove misses, but we prune old ones
	t.pruneOldMisses(validatorAddr, blockHeight)
}

// pruneOldMisses removes misses outside the participation window
func (t *BlockMissTracker) pruneOldMisses(validatorAddr string, currentHeight int64) {
	misses := t.missedBlocks[validatorAddr]
	if len(misses) == 0 {
		return
	}

	cutoff := currentHeight - t.participationWindow
	newMisses := make([]int64, 0, len(misses))
	for _, h := range misses {
		if h > cutoff {
			newMisses = append(newMisses, h)
		}
	}
	t.missedBlocks[validatorAddr] = newMisses
}

// GetMissCount returns the number of missed blocks for a validator in the current window
func (t *BlockMissTracker) GetMissCount(validatorAddr string) int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return int64(len(t.missedBlocks[validatorAddr]))
}

// ShouldSlash returns true if the validator should be slashed for downtime
func (t *BlockMissTracker) ShouldSlash(validatorAddr string) bool {
	return t.GetMissCount(validatorAddr) >= t.maxMissedBlocks
}

// ShouldJail returns true if the validator should be jailed for extended downtime
func (t *BlockMissTracker) ShouldJail(validatorAddr string) bool {
	return t.GetMissCount(validatorAddr) >= t.jailThreshold
}

// CheckAndApplyDowntimePenalties checks all validators and applies penalties
func (t *BlockMissTracker) CheckAndApplyDowntimePenalties(ctx sdk.Context) []DowntimePenalty {
	t.mu.Lock()
	defer t.mu.Unlock()

	var penalties []DowntimePenalty

	for validatorAddr, misses := range t.missedBlocks {
		missCount := int64(len(misses))

		if missCount >= t.jailThreshold {
			penalties = append(penalties, DowntimePenalty{
				ValidatorAddress: validatorAddr,
				MissedBlocks:     missCount,
				Action:           DowntimeActionJail,
				BlockHeight:      ctx.BlockHeight(),
			})
		} else if missCount >= t.maxMissedBlocks {
			penalties = append(penalties, DowntimePenalty{
				ValidatorAddress: validatorAddr,
				MissedBlocks:     missCount,
				Action:           DowntimeActionSlash,
				BlockHeight:      ctx.BlockHeight(),
			})
		}
	}

	return penalties
}

// DowntimeAction represents the action to take for downtime
type DowntimeAction string

const (
	DowntimeActionNone  DowntimeAction = "none"
	DowntimeActionSlash DowntimeAction = "slash"
	DowntimeActionJail  DowntimeAction = "jail"
)

// DowntimePenalty represents a downtime penalty to be applied
type DowntimePenalty struct {
	ValidatorAddress string
	MissedBlocks     int64
	Action           DowntimeAction
	BlockHeight      int64
}

// =============================================================================
// Double-Voting Detection
// =============================================================================

// DoubleVotingDetector detects and records evidence of double-voting (equivocation).
// Double-voting occurs when a validator signs two different vote extensions for
// the same block height, which is a severe Byzantine fault.
type DoubleVotingDetector struct {
	mu sync.RWMutex

	// voteHistory maps (validatorAddr, height) -> list of vote hashes
	// If a validator has more than one distinct vote hash for a height, it's double-voting
	voteHistory map[string]map[int64][]VoteRecord

	// detectedEquivocations stores confirmed double-voting evidence
	detectedEquivocations []EquivocationEvidence

	// keeper for state access
	keeper *Keeper

	// logger for audit trail
	logger log.Logger
}

// VoteRecord represents a single vote from a validator
type VoteRecord struct {
	VoteHash      [32]byte
	ExtensionHash [32]byte
	Timestamp     time.Time
	JobIDs        []string
	OutputHashes  map[string][32]byte // jobID -> outputHash
}

// EquivocationEvidence represents cryptographic proof of double-voting
type EquivocationEvidence struct {
	// ValidatorAddress that double-voted
	ValidatorAddress string

	// BlockHeight where double-voting occurred
	BlockHeight int64

	// Vote1 is the first vote
	Vote1 VoteRecord

	// Vote2 is the conflicting second vote
	Vote2 VoteRecord

	// DetectedAt is when the equivocation was detected
	DetectedAt time.Time

	// EvidenceHash is the hash of the evidence for deduplication
	EvidenceHash [32]byte
}

// NewDoubleVotingDetector creates a new double-voting detector
func NewDoubleVotingDetector(logger log.Logger, keeper *Keeper) *DoubleVotingDetector {
	return &DoubleVotingDetector{
		voteHistory:           make(map[string]map[int64][]VoteRecord),
		detectedEquivocations: make([]EquivocationEvidence, 0),
		keeper:                keeper,
		logger:                logger,
	}
}

// RecordVote records a vote and checks for double-voting
func (d *DoubleVotingDetector) RecordVote(
	validatorAddr string,
	blockHeight int64,
	extensionHash [32]byte,
	jobOutputs map[string][32]byte,
) *EquivocationEvidence {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Initialize maps if needed
	if d.voteHistory[validatorAddr] == nil {
		d.voteHistory[validatorAddr] = make(map[int64][]VoteRecord)
	}

	// Compute vote hash from outputs
	voteHash := d.computeVoteHash(jobOutputs)

	// Create vote record
	jobIDs := make([]string, 0, len(jobOutputs))
	for jobID := range jobOutputs {
		jobIDs = append(jobIDs, jobID)
	}
	sort.Strings(jobIDs)

	newVote := VoteRecord{
		VoteHash:      voteHash,
		ExtensionHash: extensionHash,
		Timestamp:     time.Now().UTC(),
		JobIDs:        jobIDs,
		OutputHashes:  jobOutputs,
	}

	// Check for existing votes at this height
	existingVotes := d.voteHistory[validatorAddr][blockHeight]
	for _, existingVote := range existingVotes {
		// Check if this is a different vote (double-voting)
		if existingVote.VoteHash != voteHash {
			// DETECTED: Double-voting!
			evidence := &EquivocationEvidence{
				ValidatorAddress: validatorAddr,
				BlockHeight:      blockHeight,
				Vote1:            existingVote,
				Vote2:            newVote,
				DetectedAt:       time.Now().UTC(),
			}
			evidence.EvidenceHash = d.computeEvidenceHash(evidence)

			d.detectedEquivocations = append(d.detectedEquivocations, *evidence)

			d.logger.Error("DOUBLE-VOTING DETECTED",
				"validator", validatorAddr,
				"height", blockHeight,
				"vote1_hash", hex.EncodeToString(existingVote.VoteHash[:]),
				"vote2_hash", hex.EncodeToString(newVote.VoteHash[:]),
			)

			return evidence
		}
	}

	// No double-voting, record the vote
	d.voteHistory[validatorAddr][blockHeight] = append(existingVotes, newVote)

	return nil
}

// computeVoteHash computes a deterministic hash of a vote's outputs
func (d *DoubleVotingDetector) computeVoteHash(jobOutputs map[string][32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("aethelred_vote_hash_v1:"))

	// Sort job IDs for determinism
	jobIDs := make([]string, 0, len(jobOutputs))
	for jobID := range jobOutputs {
		jobIDs = append(jobIDs, jobID)
	}
	sort.Strings(jobIDs)

	for _, jobID := range jobIDs {
		h.Write([]byte(jobID))
		output := jobOutputs[jobID]
		h.Write(output[:])
	}

	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return hash
}

// computeEvidenceHash computes a unique hash for equivocation evidence
func (d *DoubleVotingDetector) computeEvidenceHash(e *EquivocationEvidence) [32]byte {
	h := sha256.New()
	h.Write([]byte("aethelred_equivocation_v1:"))
	h.Write([]byte(e.ValidatorAddress))

	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, uint64(e.BlockHeight))
	h.Write(heightBytes)

	h.Write(e.Vote1.VoteHash[:])
	h.Write(e.Vote2.VoteHash[:])

	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return hash
}

// GetPendingEquivocations returns equivocations that haven't been processed
func (d *DoubleVotingDetector) GetPendingEquivocations() []EquivocationEvidence {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]EquivocationEvidence, len(d.detectedEquivocations))
	copy(result, d.detectedEquivocations)
	return result
}

// ClearProcessedEquivocations removes processed equivocations
func (d *DoubleVotingDetector) ClearProcessedEquivocations(evidenceHashes [][32]byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	hashSet := make(map[[32]byte]bool)
	for _, h := range evidenceHashes {
		hashSet[h] = true
	}

	newEquivocations := make([]EquivocationEvidence, 0)
	for _, e := range d.detectedEquivocations {
		if !hashSet[e.EvidenceHash] {
			newEquivocations = append(newEquivocations, e)
		}
	}
	d.detectedEquivocations = newEquivocations
}

// PruneOldHistory removes vote history older than the specified height
func (d *DoubleVotingDetector) PruneOldHistory(cutoffHeight int64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for validatorAddr, heights := range d.voteHistory {
		for height := range heights {
			if height < cutoffHeight {
				delete(d.voteHistory[validatorAddr], height)
			}
		}
		// Clean up empty validator entries
		if len(d.voteHistory[validatorAddr]) == 0 {
			delete(d.voteHistory, validatorAddr)
		}
	}
}

// =============================================================================
// Slashing Integration
// =============================================================================

// SlashingIntegration connects evidence to the staking/slashing module for penalties
type SlashingIntegration struct {
	keeper *Keeper
	logger log.Logger

	// Slashing configuration
	doubleSignSlashBps    int64 // Double-signing penalty (basis points)
	invalidOutputSlashBps int64 // Invalid output penalty
	downtimeSlashBps      int64 // Downtime penalty
	collusionSlashBps     int64 // Collusion penalty

	// Jailing configuration
	doubleSignJailDuration time.Duration
	downtimeJailDuration   time.Duration
	collusionJailDuration  time.Duration
}

// EvidenceSlashingConfig contains slashing configuration parameters for evidence system
type EvidenceSlashingConfig struct {
	DoubleSignSlashBps    int64 // 5000 = 50%
	InvalidOutputSlashBps int64 // 10000 = 100%
	DowntimeSlashBps      int64 // 500 = 5%
	CollusionSlashBps     int64 // 10000 = 100%

	DoubleSignJailDuration time.Duration
	DowntimeJailDuration   time.Duration
	CollusionJailDuration  time.Duration
}

// DefaultEvidenceSlashingConfig returns enterprise-grade slashing configuration
func DefaultEvidenceSlashingConfig() EvidenceSlashingConfig {
	return EvidenceSlashingConfig{
		DoubleSignSlashBps:    5000,  // 50% for double-signing (severe)
		InvalidOutputSlashBps: 10000, // 100% for invalid/fraud outputs
		DowntimeSlashBps:      500,   // 5% for downtime
		CollusionSlashBps:     10000, // 100% for collusion (permaban)

		DoubleSignJailDuration: 30 * 24 * time.Hour,  // 30 days
		DowntimeJailDuration:   24 * time.Hour,       // 1 day
		CollusionJailDuration:  365 * 24 * time.Hour, // 1 year (effectively permanent)
	}
}

// NewSlashingIntegration creates a new slashing integration
func NewSlashingIntegration(logger log.Logger, keeper *Keeper, config EvidenceSlashingConfig) *SlashingIntegration {
	return &SlashingIntegration{
		keeper:                 keeper,
		logger:                 logger,
		doubleSignSlashBps:     config.DoubleSignSlashBps,
		invalidOutputSlashBps:  config.InvalidOutputSlashBps,
		downtimeSlashBps:       config.DowntimeSlashBps,
		collusionSlashBps:      config.CollusionSlashBps,
		doubleSignJailDuration: config.DoubleSignJailDuration,
		downtimeJailDuration:   config.DowntimeJailDuration,
		collusionJailDuration:  config.CollusionJailDuration,
	}
}

// SlashResult contains the result of a slashing operation
type SlashResult struct {
	ValidatorAddress string
	SlashedAmount    sdkmath.Int
	SlashBps         int64
	Reason           SlashReason
	Jailed           bool
	JailDuration     time.Duration
	BlockHeight      int64
	EvidenceHash     [32]byte
}

// SlashReason categorizes the reason for slashing
type SlashReason string

const (
	SlashReasonDoubleSign      SlashReason = "double_sign"
	SlashReasonInvalidOutput   SlashReason = "invalid_output"
	SlashReasonDowntime        SlashReason = "downtime"
	SlashReasonCollusion       SlashReason = "collusion"
	SlashReasonFakeAttestation SlashReason = "fake_attestation"
)

// ProcessDoubleSignEvidence processes double-signing evidence and applies slashing
func (s *SlashingIntegration) ProcessDoubleSignEvidence(
	ctx sdk.Context,
	evidence *EquivocationEvidence,
) (*SlashResult, error) {
	s.logger.Error("Processing double-sign evidence",
		"validator", evidence.ValidatorAddress,
		"height", evidence.BlockHeight,
	)

	// Get validator's stake
	stake, err := s.getValidatorStake(ctx, evidence.ValidatorAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get validator stake: %w", err)
	}

	// Calculate slash amount
	slashAmount := stake.MulRaw(s.doubleSignSlashBps).QuoRaw(10000)

	result := &SlashResult{
		ValidatorAddress: evidence.ValidatorAddress,
		SlashedAmount:    slashAmount,
		SlashBps:         s.doubleSignSlashBps,
		Reason:           SlashReasonDoubleSign,
		Jailed:           true,
		JailDuration:     s.doubleSignJailDuration,
		BlockHeight:      ctx.BlockHeight(),
		EvidenceHash:     evidence.EvidenceHash,
	}

	// Record slashing event
	if err := s.recordSlashingEvent(ctx, result); err != nil {
		return nil, fmt.Errorf("failed to record slashing event: %w", err)
	}

	// Emit slashing event
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			"validator_slashed",
			sdk.NewAttribute("validator", evidence.ValidatorAddress),
			sdk.NewAttribute("reason", string(SlashReasonDoubleSign)),
			sdk.NewAttribute("amount", slashAmount.String()),
			sdk.NewAttribute("jailed", "true"),
			sdk.NewAttribute("evidence_hash", hex.EncodeToString(evidence.EvidenceHash[:])),
		),
	)

	return result, nil
}

// ProcessDowntimeEvidence processes downtime evidence and applies slashing
func (s *SlashingIntegration) ProcessDowntimeEvidence(
	ctx sdk.Context,
	penalty *DowntimePenalty,
) (*SlashResult, error) {
	s.logger.Warn("Processing downtime evidence",
		"validator", penalty.ValidatorAddress,
		"missed_blocks", penalty.MissedBlocks,
		"action", penalty.Action,
	)

	stake, err := s.getValidatorStake(ctx, penalty.ValidatorAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get validator stake: %w", err)
	}

	slashAmount := stake.MulRaw(s.downtimeSlashBps).QuoRaw(10000)
	shouldJail := penalty.Action == DowntimeActionJail

	result := &SlashResult{
		ValidatorAddress: penalty.ValidatorAddress,
		SlashedAmount:    slashAmount,
		SlashBps:         s.downtimeSlashBps,
		Reason:           SlashReasonDowntime,
		Jailed:           shouldJail,
		JailDuration:     s.downtimeJailDuration,
		BlockHeight:      ctx.BlockHeight(),
	}

	// Compute evidence hash
	h := sha256.Sum256([]byte(fmt.Sprintf("downtime:%s:%d", penalty.ValidatorAddress, penalty.BlockHeight)))
	result.EvidenceHash = h

	if err := s.recordSlashingEvent(ctx, result); err != nil {
		return nil, fmt.Errorf("failed to record slashing event: %w", err)
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			"validator_slashed",
			sdk.NewAttribute("validator", penalty.ValidatorAddress),
			sdk.NewAttribute("reason", string(SlashReasonDowntime)),
			sdk.NewAttribute("amount", slashAmount.String()),
			sdk.NewAttribute("missed_blocks", fmt.Sprintf("%d", penalty.MissedBlocks)),
		),
	)

	return result, nil
}

// ProcessCollusionEvidence processes collusion evidence (most severe)
func (s *SlashingIntegration) ProcessCollusionEvidence(
	ctx sdk.Context,
	validators []string,
	blockHeight int64,
	evidenceDetails string,
) ([]*SlashResult, error) {
	s.logger.Error("Processing COLLUSION evidence - SEVERE",
		"validators", validators,
		"height", blockHeight,
		"details", evidenceDetails,
	)

	var results []*SlashResult

	for _, validatorAddr := range validators {
		stake, err := s.getValidatorStake(ctx, validatorAddr)
		if err != nil {
			s.logger.Error("Failed to get validator stake for collusion slashing",
				"validator", validatorAddr,
				"error", err,
			)
			continue
		}

		// 100% slash for collusion
		slashAmount := stake

		h := sha256.Sum256([]byte(fmt.Sprintf("collusion:%s:%d:%s", validatorAddr, blockHeight, evidenceDetails)))

		result := &SlashResult{
			ValidatorAddress: validatorAddr,
			SlashedAmount:    slashAmount,
			SlashBps:         s.collusionSlashBps,
			Reason:           SlashReasonCollusion,
			Jailed:           true,
			JailDuration:     s.collusionJailDuration, // Effectively permanent
			BlockHeight:      ctx.BlockHeight(),
			EvidenceHash:     h,
		}

		if err := s.recordSlashingEvent(ctx, result); err != nil {
			s.logger.Error("Failed to record collusion slashing",
				"validator", validatorAddr,
				"error", err,
			)
			continue
		}

		results = append(results, result)

		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				"validator_slashed_collusion",
				sdk.NewAttribute("validator", validatorAddr),
				sdk.NewAttribute("amount", slashAmount.String()),
				sdk.NewAttribute("permaban", "true"),
			),
		)
	}

	return results, nil
}

// getValidatorStake retrieves a validator's current stake
func (s *SlashingIntegration) getValidatorStake(ctx sdk.Context, validatorAddr string) (sdkmath.Int, error) {
	if s.keeper == nil {
		return sdkmath.NewInt(1000000), nil // Default for testing
	}

	stats, err := s.keeper.GetValidatorStats(ctx, validatorAddr)
	if err != nil {
		// Return a default stake for new/unknown validators
		return sdkmath.NewInt(1000000), nil
	}

	// Use reputation as a proxy for stake in this implementation
	// In production, this would query the staking module
	return sdkmath.NewInt(stats.ReputationScore * 10000), nil
}

// recordSlashingEvent records a slashing event in state
func (s *SlashingIntegration) recordSlashingEvent(ctx sdk.Context, result *SlashResult) error {
	if s.keeper == nil {
		return nil
	}

	// Update validator stats to reflect slashing
	stats, err := s.keeper.GetValidatorStats(ctx, result.ValidatorAddress)
	if err != nil {
		// Create new stats if not found
		stats = &types.ValidatorStats{
			ValidatorAddress:   result.ValidatorAddress,
			TotalJobsProcessed: 0,
			SuccessfulJobs:     0,
			FailedJobs:         0,
			ReputationScore:    0,
			SlashingEvents:     0,
		}
	}

	// Reduce reputation based on slash severity
	reputationPenalty := result.SlashBps / 100 // 1% of stake = 1 reputation point
	stats.ReputationScore -= reputationPenalty
	if stats.ReputationScore < 0 {
		stats.ReputationScore = 0
	}

	// Increment slashing events counter
	stats.SlashingEvents++

	return s.keeper.SetValidatorStats(ctx, stats)
}

// =============================================================================
// ProcessEndBlockEvidence - Main Entry Point
// =============================================================================

// EvidenceProcessor coordinates all evidence processing at EndBlock
type EvidenceProcessor struct {
	blockMissTracker     *BlockMissTracker
	doubleVotingDetector *DoubleVotingDetector
	slashingIntegration  *SlashingIntegration
	keeper               *Keeper
	logger               log.Logger
}

// NewEvidenceProcessor creates a new evidence processor
func NewEvidenceProcessor(
	logger log.Logger,
	keeper *Keeper,
	blockMissConfig BlockMissConfig,
	slashingConfig EvidenceSlashingConfig,
) *EvidenceProcessor {
	return &EvidenceProcessor{
		blockMissTracker:     NewBlockMissTracker(logger, keeper, blockMissConfig),
		doubleVotingDetector: NewDoubleVotingDetector(logger, keeper),
		slashingIntegration:  NewSlashingIntegration(logger, keeper, slashingConfig),
		keeper:               keeper,
		logger:               logger,
	}
}

// ProcessEndBlockEvidence processes all pending evidence at EndBlock
// This is the main integration point called from the ABCI EndBlocker
func (ep *EvidenceProcessor) ProcessEndBlockEvidence(ctx sdk.Context) *EvidenceProcessingResult {
	result := &EvidenceProcessingResult{
		BlockHeight:         ctx.BlockHeight(),
		ProcessedAt:         time.Now().UTC(),
		DowntimePenalties:   make([]*SlashResult, 0),
		EquivocationSlashes: make([]*SlashResult, 0),
	}

	// 1. Process downtime penalties
	downtimePenalties := ep.blockMissTracker.CheckAndApplyDowntimePenalties(ctx)
	for _, penalty := range downtimePenalties {
		slashResult, err := ep.slashingIntegration.ProcessDowntimeEvidence(ctx, &penalty)
		if err != nil {
			ep.logger.Error("Failed to process downtime penalty",
				"validator", penalty.ValidatorAddress,
				"error", err,
			)
			continue
		}
		result.DowntimePenalties = append(result.DowntimePenalties, slashResult)
	}

	// 2. Process double-voting evidence
	equivocations := ep.doubleVotingDetector.GetPendingEquivocations()
	var processedHashes [][32]byte
	for _, evidence := range equivocations {
		slashResult, err := ep.slashingIntegration.ProcessDoubleSignEvidence(ctx, &evidence)
		if err != nil {
			ep.logger.Error("Failed to process equivocation",
				"validator", evidence.ValidatorAddress,
				"error", err,
			)
			continue
		}
		result.EquivocationSlashes = append(result.EquivocationSlashes, slashResult)
		processedHashes = append(processedHashes, evidence.EvidenceHash)
	}

	// Clear processed equivocations
	if len(processedHashes) > 0 {
		ep.doubleVotingDetector.ClearProcessedEquivocations(processedHashes)
	}

	// 3. Prune old vote history (keep last 1000 blocks)
	ep.doubleVotingDetector.PruneOldHistory(ctx.BlockHeight() - 1000)

	// Log summary
	if len(result.DowntimePenalties) > 0 || len(result.EquivocationSlashes) > 0 {
		ep.logger.Info("Evidence processing complete",
			"height", ctx.BlockHeight(),
			"downtime_penalties", len(result.DowntimePenalties),
			"equivocation_slashes", len(result.EquivocationSlashes),
		)
	}

	return result
}

// RecordValidatorParticipation records validator participation from vote extensions
func (ep *EvidenceProcessor) RecordValidatorParticipation(
	ctx sdk.Context,
	validatorAddr string,
	extensionHash [32]byte,
	jobOutputs map[string][32]byte,
) *EquivocationEvidence {
	// Record participation for downtime tracking
	ep.blockMissTracker.RecordParticipation(validatorAddr, ctx.BlockHeight())

	// Check for double-voting
	return ep.doubleVotingDetector.RecordVote(
		validatorAddr,
		ctx.BlockHeight(),
		extensionHash,
		jobOutputs,
	)
}

// RecordValidatorMiss records a missed block for a validator
func (ep *EvidenceProcessor) RecordValidatorMiss(ctx sdk.Context, validatorAddr string) {
	ep.blockMissTracker.RecordMiss(validatorAddr, ctx.BlockHeight())
}

// EvidenceProcessingResult contains the results of EndBlock evidence processing
type EvidenceProcessingResult struct {
	BlockHeight         int64
	ProcessedAt         time.Time
	DowntimePenalties   []*SlashResult
	EquivocationSlashes []*SlashResult
}

// TotalSlashed returns the total amount slashed in this block
func (r *EvidenceProcessingResult) TotalSlashed() sdkmath.Int {
	total := sdkmath.ZeroInt()
	for _, p := range r.DowntimePenalties {
		total = total.Add(p.SlashedAmount)
	}
	for _, e := range r.EquivocationSlashes {
		total = total.Add(e.SlashedAmount)
	}
	return total
}

// =============================================================================
// Collusion Detection
// =============================================================================

// CollusionDetector detects coordinated misbehavior among multiple validators
type CollusionDetector struct {
	mu sync.RWMutex

	// invalidOutputPatterns tracks patterns of invalid outputs
	// Key: outputHashHex, Value: list of validators who submitted it
	invalidOutputPatterns map[string][]string

	// collusionThreshold is the minimum number of validators submitting
	// the same invalid output to trigger collusion investigation
	collusionThreshold int

	// detectedCollusions stores confirmed collusion evidence
	detectedCollusions []CollusionEvidence

	logger log.Logger
}

// CollusionEvidence represents evidence of coordinated misbehavior
type CollusionEvidence struct {
	Validators    []string
	InvalidOutput [32]byte
	JobID         string
	BlockHeight   int64
	DetectedAt    time.Time
}

// NewCollusionDetector creates a new collusion detector
func NewCollusionDetector(logger log.Logger, threshold int) *CollusionDetector {
	if threshold < 2 {
		threshold = 2 // Minimum 2 validators for collusion
	}
	return &CollusionDetector{
		invalidOutputPatterns: make(map[string][]string),
		collusionThreshold:    threshold,
		detectedCollusions:    make([]CollusionEvidence, 0),
		logger:                logger,
	}
}

// RecordInvalidOutput records an invalid output from a validator
func (cd *CollusionDetector) RecordInvalidOutput(
	validatorAddr string,
	jobID string,
	invalidOutput [32]byte,
	blockHeight int64,
) *CollusionEvidence {
	cd.mu.Lock()
	defer cd.mu.Unlock()

	key := hex.EncodeToString(invalidOutput[:])
	cd.invalidOutputPatterns[key] = append(cd.invalidOutputPatterns[key], validatorAddr)

	// Check if collusion threshold reached
	validators := cd.invalidOutputPatterns[key]
	if len(validators) >= cd.collusionThreshold {
		evidence := &CollusionEvidence{
			Validators:    validators,
			InvalidOutput: invalidOutput,
			JobID:         jobID,
			BlockHeight:   blockHeight,
			DetectedAt:    time.Now().UTC(),
		}
		cd.detectedCollusions = append(cd.detectedCollusions, *evidence)

		cd.logger.Error("COLLUSION DETECTED",
			"validators", validators,
			"job_id", jobID,
			"invalid_output", key[:16],
		)

		return evidence
	}

	return nil
}

// GetDetectedCollusions returns all detected collusion evidence
func (cd *CollusionDetector) GetDetectedCollusions() []CollusionEvidence {
	cd.mu.RLock()
	defer cd.mu.RUnlock()

	result := make([]CollusionEvidence, len(cd.detectedCollusions))
	copy(result, cd.detectedCollusions)
	return result
}

// =============================================================================
// Helper: Verify evidence cryptographically
// =============================================================================

// VerifyEquivocationEvidence cryptographically verifies equivocation evidence
func VerifyEquivocationEvidence(evidence *EquivocationEvidence) bool {
	// Verify the two votes are for the same height
	if evidence.Vote1.VoteHash == evidence.Vote2.VoteHash {
		return false // Same vote, not equivocation
	}

	// Verify both votes are non-empty
	if evidence.Vote1.VoteHash == [32]byte{} || evidence.Vote2.VoteHash == [32]byte{} {
		return false
	}

	// Verify evidence hash
	expectedHash := computeEvidenceHashStatic(evidence)
	return bytes.Equal(evidence.EvidenceHash[:], expectedHash[:])
}

func computeEvidenceHashStatic(e *EquivocationEvidence) [32]byte {
	h := sha256.New()
	h.Write([]byte("aethelred_equivocation_v1:"))
	h.Write([]byte(e.ValidatorAddress))

	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, uint64(e.BlockHeight))
	h.Write(heightBytes)

	h.Write(e.Vote1.VoteHash[:])
	h.Write(e.Vote2.VoteHash[:])

	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return hash
}
