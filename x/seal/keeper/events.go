package keeper

import (
	"encoding/hex"
	"fmt"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/seal/types"
)

// Event type constants
const (
	EventTypeSealCreated       = "seal_created"
	EventTypeSealVerified      = "seal_verified"
	EventTypeSealActivated     = "seal_activated"
	EventTypeSealRevoked       = "seal_revoked"
	EventTypeSealExpired       = "seal_expired"
	EventTypeSealAccessed      = "seal_accessed"
	EventTypeSealExported      = "seal_exported"
	EventTypeSealDisputed      = "seal_disputed"
	EventTypeModelRegistered   = "model_registered"
	EventTypeConsensusReached  = "consensus_reached"
	EventTypeVerificationFailed = "verification_failed"

	// Attribute keys
	AttributeKeySealID            = "seal_id"
	AttributeKeyJobID             = "job_id"
	AttributeKeyModelHash         = "model_hash"
	AttributeKeyInputHash         = "input_hash"
	AttributeKeyOutputHash        = "output_hash"
	AttributeKeyRequestedBy       = "requested_by"
	AttributeKeyPurpose           = "purpose"
	AttributeKeyVerificationType  = "verification_type"
	AttributeKeyValidatorCount    = "validator_count"
	AttributeKeyBlockHeight       = "block_height"
	AttributeKeyTimestamp         = "timestamp"
	AttributeKeyStatus            = "status"
	AttributeKeyReason            = "reason"
	AttributeKeyActor             = "actor"
	AttributeKeyChainID           = "chain_id"
	AttributeKeyComplianceFrameworks = "compliance_frameworks"
	AttributeKeyHasZKProof        = "has_zk_proof"
)

// SealEventEmitter handles emission of seal-related events
type SealEventEmitter struct {
	// Event handlers (for indexing)
	handlers []SealEventHandler
}

// SealEventHandler is called when events are emitted
type SealEventHandler func(event SealEvent)

// SealEvent represents a seal-related event
type SealEvent struct {
	Type        string            `json:"type"`
	SealID      string            `json:"seal_id"`
	BlockHeight int64             `json:"block_height"`
	Timestamp   time.Time         `json:"timestamp"`
	Attributes  map[string]string `json:"attributes"`
}

// NewSealEventEmitter creates a new event emitter
func NewSealEventEmitter() *SealEventEmitter {
	return &SealEventEmitter{
		handlers: make([]SealEventHandler, 0),
	}
}

// RegisterHandler registers an event handler
func (e *SealEventEmitter) RegisterHandler(handler SealEventHandler) {
	e.handlers = append(e.handlers, handler)
}

// notifyHandlers calls all registered handlers
func (e *SealEventEmitter) notifyHandlers(event SealEvent) {
	for _, handler := range e.handlers {
		handler(event)
	}
}

// EmitSealCreated emits a seal created event
func EmitSealCreated(ctx sdk.Context, seal *types.DigitalSeal) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	if seal.Timestamp != nil {
		timestamp = seal.Timestamp.AsTime().UTC().Format(time.RFC3339)
	}

	attrs := []sdk.Attribute{
		sdk.NewAttribute(AttributeKeySealID, seal.Id),
		sdk.NewAttribute(AttributeKeyModelHash, truncateHex(seal.ModelCommitment)),
		sdk.NewAttribute(AttributeKeyInputHash, truncateHex(seal.InputCommitment)),
		sdk.NewAttribute(AttributeKeyOutputHash, truncateHex(seal.OutputCommitment)),
		sdk.NewAttribute(AttributeKeyRequestedBy, seal.RequestedBy),
		sdk.NewAttribute(AttributeKeyPurpose, seal.Purpose),
		sdk.NewAttribute(AttributeKeyVerificationType, seal.GetVerificationType()),
		sdk.NewAttribute(AttributeKeyValidatorCount, fmt.Sprintf("%d", len(seal.ValidatorSet))),
		sdk.NewAttribute(AttributeKeyBlockHeight, fmt.Sprintf("%d", seal.BlockHeight)),
		sdk.NewAttribute(AttributeKeyTimestamp, timestamp),
		sdk.NewAttribute(AttributeKeyStatus, seal.Status.String()),
	}

	// Add zkML proof indicator
	if seal.ZkProof != nil {
		attrs = append(attrs, sdk.NewAttribute(AttributeKeyHasZKProof, "true"))
	} else {
		attrs = append(attrs, sdk.NewAttribute(AttributeKeyHasZKProof, "false"))
	}

	// Add compliance frameworks
	if seal.RegulatoryInfo != nil && len(seal.RegulatoryInfo.ComplianceFrameworks) > 0 {
		frameworks := ""
		for i, f := range seal.RegulatoryInfo.ComplianceFrameworks {
			if i > 0 {
				frameworks += ","
			}
			frameworks += f
		}
		attrs = append(attrs, sdk.NewAttribute(AttributeKeyComplianceFrameworks, frameworks))
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(EventTypeSealCreated, attrs...),
	)
}

// EmitSealVerified emits a seal verified event
func EmitSealVerified(ctx sdk.Context, sealID string, valid bool, verificationType string) {
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			EventTypeSealVerified,
			sdk.NewAttribute(AttributeKeySealID, sealID),
			sdk.NewAttribute("valid", fmt.Sprintf("%t", valid)),
			sdk.NewAttribute(AttributeKeyVerificationType, verificationType),
			sdk.NewAttribute(AttributeKeyBlockHeight, fmt.Sprintf("%d", ctx.BlockHeight())),
			sdk.NewAttribute(AttributeKeyTimestamp, time.Now().UTC().Format(time.RFC3339)),
		),
	)
}

// EmitSealActivated emits a seal activated event
func EmitSealActivated(ctx sdk.Context, sealID string, actor string) {
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			EventTypeSealActivated,
			sdk.NewAttribute(AttributeKeySealID, sealID),
			sdk.NewAttribute(AttributeKeyActor, actor),
			sdk.NewAttribute(AttributeKeyBlockHeight, fmt.Sprintf("%d", ctx.BlockHeight())),
			sdk.NewAttribute(AttributeKeyTimestamp, time.Now().UTC().Format(time.RFC3339)),
		),
	)
}

// EmitSealRevoked emits a seal revoked event
func EmitSealRevoked(ctx sdk.Context, sealID string, revokedBy string, reason string) {
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			EventTypeSealRevoked,
			sdk.NewAttribute(AttributeKeySealID, sealID),
			sdk.NewAttribute(AttributeKeyActor, revokedBy),
			sdk.NewAttribute(AttributeKeyReason, reason),
			sdk.NewAttribute(AttributeKeyBlockHeight, fmt.Sprintf("%d", ctx.BlockHeight())),
			sdk.NewAttribute(AttributeKeyTimestamp, time.Now().UTC().Format(time.RFC3339)),
		),
	)
}

// EmitSealExpired emits a seal expired event
func EmitSealExpired(ctx sdk.Context, sealID string) {
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			EventTypeSealExpired,
			sdk.NewAttribute(AttributeKeySealID, sealID),
			sdk.NewAttribute(AttributeKeyBlockHeight, fmt.Sprintf("%d", ctx.BlockHeight())),
			sdk.NewAttribute(AttributeKeyTimestamp, time.Now().UTC().Format(time.RFC3339)),
		),
	)
}

// EmitSealAccessed emits a seal accessed event
func EmitSealAccessed(ctx sdk.Context, sealID string, accessor string, purpose string) {
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			EventTypeSealAccessed,
			sdk.NewAttribute(AttributeKeySealID, sealID),
			sdk.NewAttribute(AttributeKeyActor, accessor),
			sdk.NewAttribute(AttributeKeyPurpose, purpose),
			sdk.NewAttribute(AttributeKeyBlockHeight, fmt.Sprintf("%d", ctx.BlockHeight())),
			sdk.NewAttribute(AttributeKeyTimestamp, time.Now().UTC().Format(time.RFC3339)),
		),
	)
}

// EmitSealExported emits a seal exported event
func EmitSealExported(ctx sdk.Context, sealID string, exporter string, format string) {
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			EventTypeSealExported,
			sdk.NewAttribute(AttributeKeySealID, sealID),
			sdk.NewAttribute(AttributeKeyActor, exporter),
			sdk.NewAttribute("format", format),
			sdk.NewAttribute(AttributeKeyBlockHeight, fmt.Sprintf("%d", ctx.BlockHeight())),
			sdk.NewAttribute(AttributeKeyTimestamp, time.Now().UTC().Format(time.RFC3339)),
		),
	)
}

// EmitConsensusReached emits a consensus reached event
func EmitConsensusReached(ctx sdk.Context, jobID string, outputHash []byte, validatorCount int, agreementCount int) {
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			EventTypeConsensusReached,
			sdk.NewAttribute(AttributeKeyJobID, jobID),
			sdk.NewAttribute(AttributeKeyOutputHash, truncateHex(outputHash)),
			sdk.NewAttribute(AttributeKeyValidatorCount, fmt.Sprintf("%d", validatorCount)),
			sdk.NewAttribute("agreement_count", fmt.Sprintf("%d", agreementCount)),
			sdk.NewAttribute(AttributeKeyBlockHeight, fmt.Sprintf("%d", ctx.BlockHeight())),
			sdk.NewAttribute(AttributeKeyTimestamp, time.Now().UTC().Format(time.RFC3339)),
		),
	)
}

// EmitVerificationFailed emits a verification failed event
func EmitVerificationFailed(ctx sdk.Context, jobID string, reason string, validatorAddr string) {
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			EventTypeVerificationFailed,
			sdk.NewAttribute(AttributeKeyJobID, jobID),
			sdk.NewAttribute(AttributeKeyReason, reason),
			sdk.NewAttribute("validator", validatorAddr),
			sdk.NewAttribute(AttributeKeyBlockHeight, fmt.Sprintf("%d", ctx.BlockHeight())),
			sdk.NewAttribute(AttributeKeyTimestamp, time.Now().UTC().Format(time.RFC3339)),
		),
	)
}

// EmitModelRegistered emits a model registered event
func EmitModelRegistered(ctx sdk.Context, modelID string, modelHash []byte, registeredBy string) {
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			EventTypeModelRegistered,
			sdk.NewAttribute("model_id", modelID),
			sdk.NewAttribute(AttributeKeyModelHash, truncateHex(modelHash)),
			sdk.NewAttribute(AttributeKeyActor, registeredBy),
			sdk.NewAttribute(AttributeKeyBlockHeight, fmt.Sprintf("%d", ctx.BlockHeight())),
			sdk.NewAttribute(AttributeKeyTimestamp, time.Now().UTC().Format(time.RFC3339)),
		),
	)
}

// truncateHex creates a truncated hex string for events
func truncateHex(data []byte) string {
	fullHex := hex.EncodeToString(data)
	if len(fullHex) > 16 {
		return fullHex[:16]
	}
	return fullHex
}

// SealIndex provides indexing capabilities for seals
type SealIndex struct {
	// Indexes
	byModelHash     map[string][]string // model hash -> seal IDs
	byPurpose       map[string][]string // purpose -> seal IDs
	byRequester     map[string][]string // requester -> seal IDs
	byStatus        map[string][]string // status -> seal IDs
	byBlockHeight   map[int64][]string  // block height -> seal IDs
	byValidator     map[string][]string // validator -> seal IDs
	byCompliance    map[string][]string // compliance framework -> seal IDs
}

// NewSealIndex creates a new seal index
func NewSealIndex() *SealIndex {
	return &SealIndex{
		byModelHash:   make(map[string][]string),
		byPurpose:     make(map[string][]string),
		byRequester:   make(map[string][]string),
		byStatus:      make(map[string][]string),
		byBlockHeight: make(map[int64][]string),
		byValidator:   make(map[string][]string),
		byCompliance:  make(map[string][]string),
	}
}

// IndexSeal adds a seal to all indexes
func (idx *SealIndex) IndexSeal(seal *types.DigitalSeal) {
	// Index by model hash
	modelKey := hex.EncodeToString(seal.ModelCommitment)
	idx.byModelHash[modelKey] = append(idx.byModelHash[modelKey], seal.Id)

	// Index by purpose
	idx.byPurpose[seal.Purpose] = append(idx.byPurpose[seal.Purpose], seal.Id)

	// Index by requester
	idx.byRequester[seal.RequestedBy] = append(idx.byRequester[seal.RequestedBy], seal.Id)

	// Index by status
	statusKey := seal.Status.String()
	idx.byStatus[statusKey] = append(idx.byStatus[statusKey], seal.Id)

	// Index by block height
	idx.byBlockHeight[seal.BlockHeight] = append(idx.byBlockHeight[seal.BlockHeight], seal.Id)

	// Index by validators
	for _, validator := range seal.ValidatorSet {
		idx.byValidator[validator] = append(idx.byValidator[validator], seal.Id)
	}

	// Index by compliance framework
	if seal.RegulatoryInfo != nil {
		for _, framework := range seal.RegulatoryInfo.ComplianceFrameworks {
			idx.byCompliance[framework] = append(idx.byCompliance[framework], seal.Id)
		}
	}
}

// UpdateSealStatus updates the status index for a seal
func (idx *SealIndex) UpdateSealStatus(sealID string, oldStatus, newStatus types.SealStatus) {
	// Remove from old status index
	oldKey := oldStatus.String()
	if seals, ok := idx.byStatus[oldKey]; ok {
		for i, id := range seals {
			if id == sealID {
				idx.byStatus[oldKey] = append(seals[:i], seals[i+1:]...)
				break
			}
		}
	}

	// Add to new status index
	newKey := newStatus.String()
	idx.byStatus[newKey] = append(idx.byStatus[newKey], sealID)
}

// GetByModelHash returns seal IDs by model hash
func (idx *SealIndex) GetByModelHash(modelHash []byte) []string {
	key := hex.EncodeToString(modelHash)
	return idx.byModelHash[key]
}

// GetByPurpose returns seal IDs by purpose
func (idx *SealIndex) GetByPurpose(purpose string) []string {
	return idx.byPurpose[purpose]
}

// GetByRequester returns seal IDs by requester
func (idx *SealIndex) GetByRequester(requester string) []string {
	return idx.byRequester[requester]
}

// GetByStatus returns seal IDs by status
func (idx *SealIndex) GetByStatus(status types.SealStatus) []string {
	return idx.byStatus[status.String()]
}

// GetByBlockHeight returns seal IDs by block height
func (idx *SealIndex) GetByBlockHeight(height int64) []string {
	return idx.byBlockHeight[height]
}

// GetByBlockHeightRange returns seal IDs in a block height range
func (idx *SealIndex) GetByBlockHeightRange(startHeight, endHeight int64) []string {
	result := make([]string, 0)
	for height := startHeight; height <= endHeight; height++ {
		if seals, ok := idx.byBlockHeight[height]; ok {
			result = append(result, seals...)
		}
	}
	return result
}

// GetByValidator returns seal IDs by validator
func (idx *SealIndex) GetByValidator(validator string) []string {
	return idx.byValidator[validator]
}

// GetByComplianceFramework returns seal IDs by compliance framework
func (idx *SealIndex) GetByComplianceFramework(framework string) []string {
	return idx.byCompliance[framework]
}

// GetStats returns index statistics
func (idx *SealIndex) GetStats() *IndexStats {
	totalSeals := 0
	for _, seals := range idx.byStatus {
		totalSeals += len(seals)
	}

	return &IndexStats{
		TotalSeals:              totalSeals,
		UniqueModels:            len(idx.byModelHash),
		UniquePurposes:          len(idx.byPurpose),
		UniqueRequesters:        len(idx.byRequester),
		UniqueValidators:        len(idx.byValidator),
		ComplianceFrameworks:    len(idx.byCompliance),
		SealsByStatus:           idx.getStatusCounts(),
	}
}

// IndexStats contains index statistics
type IndexStats struct {
	TotalSeals           int            `json:"total_seals"`
	UniqueModels         int            `json:"unique_models"`
	UniquePurposes       int            `json:"unique_purposes"`
	UniqueRequesters     int            `json:"unique_requesters"`
	UniqueValidators     int            `json:"unique_validators"`
	ComplianceFrameworks int            `json:"compliance_frameworks"`
	SealsByStatus        map[string]int `json:"seals_by_status"`
}

// getStatusCounts returns count of seals by status
func (idx *SealIndex) getStatusCounts() map[string]int {
	counts := make(map[string]int)
	for status, seals := range idx.byStatus {
		counts[status] = len(seals)
	}
	return counts
}

// Query represents a seal query
type SealQuery struct {
	ModelHash       []byte
	Purpose         string
	Requester       string
	Status          *types.SealStatus
	MinBlockHeight  int64
	MaxBlockHeight  int64
	Validator       string
	ComplianceFramework string
	Limit           int
	Offset          int
}

// ExecuteQuery executes a query against the index
func (idx *SealIndex) ExecuteQuery(query SealQuery) []string {
	// Start with all results or specific index
	var results []string

	// Use the most selective index first
	if len(query.ModelHash) > 0 {
		results = idx.GetByModelHash(query.ModelHash)
	} else if query.Requester != "" {
		results = idx.GetByRequester(query.Requester)
	} else if query.Purpose != "" {
		results = idx.GetByPurpose(query.Purpose)
	} else if query.Status != nil {
		results = idx.GetByStatus(*query.Status)
	} else if query.Validator != "" {
		results = idx.GetByValidator(query.Validator)
	} else if query.ComplianceFramework != "" {
		results = idx.GetByComplianceFramework(query.ComplianceFramework)
	} else if query.MinBlockHeight > 0 || query.MaxBlockHeight > 0 {
		minH := query.MinBlockHeight
		maxH := query.MaxBlockHeight
		if maxH == 0 {
			maxH = 1000000000 // Large number
		}
		results = idx.GetByBlockHeightRange(minH, maxH)
	}

	// Apply pagination
	if query.Offset > 0 && query.Offset < len(results) {
		results = results[query.Offset:]
	}

	if query.Limit > 0 && query.Limit < len(results) {
		results = results[:query.Limit]
	}

	return results
}
