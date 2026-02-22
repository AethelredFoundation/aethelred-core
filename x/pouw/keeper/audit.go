package keeper

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// ---------------------------------------------------------------------------
// Structured Audit Logging
// ---------------------------------------------------------------------------
//
// This file implements a deterministic, structured audit logging system for
// the pouw module. Every security-relevant action is recorded as an
// AuditRecord, which is:
//
//   1. Hashed (SHA-256) for tamper detection
//   2. Chained to the previous record (hash chain) for continuity
//   3. Emitted as an SDK event for on-chain persistence
//   4. Written to the Cosmos SDK logger for operator visibility
//
// The audit trail is designed for regulatory compliance (e.g. financial AI
// verification audits) and post-incident forensic analysis.
//
// Design principles:
//   - Deterministic: identical inputs always produce identical records
//   - Append-only: records are never modified or deleted
//   - Chainable: each record includes the hash of the previous record
//   - Self-describing: records include type, category, and severity
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Audit record types
// ---------------------------------------------------------------------------

// AuditCategory classifies an audit event by domain.
type AuditCategory string

const (
	AuditCategoryJob          AuditCategory = "job"
	AuditCategoryConsensus    AuditCategory = "consensus"
	AuditCategoryVerification AuditCategory = "verification"
	AuditCategorySlashing     AuditCategory = "slashing"
	AuditCategoryGovernance   AuditCategory = "governance"
	AuditCategoryEconomics    AuditCategory = "economics"
	AuditCategorySecurity     AuditCategory = "security"
	AuditCategoryValidator    AuditCategory = "validator"
)

// AuditSeverity classifies the importance of an audit event.
type AuditSeverity string

const (
	AuditSeverityInfo     AuditSeverity = "info"
	AuditSeverityWarning  AuditSeverity = "warning"
	AuditSeverityCritical AuditSeverity = "critical"
)

// AuditRecord is a single structured audit entry. All fields are exported
// for JSON serialization. The RecordHash is computed deterministically from
// all other fields plus the PreviousHash (hash chain).
type AuditRecord struct {
	// Identity
	Sequence     uint64 `json:"sequence"`
	RecordHash   string `json:"record_hash"`
	PreviousHash string `json:"previous_hash"`

	// Classification
	Category AuditCategory `json:"category"`
	Severity AuditSeverity `json:"severity"`
	Action   string        `json:"action"`

	// Context
	BlockHeight int64  `json:"block_height"`
	Timestamp   string `json:"timestamp"` // RFC3339
	Actor       string `json:"actor"`     // address or "system"

	// Payload
	Details map[string]string `json:"details"`
}

// computeHash produces a deterministic SHA-256 digest of the record. It
// serializes all non-hash fields plus PreviousHash in a canonical order.
func (r *AuditRecord) computeHash() string {
	// Build a canonical representation for hashing.
	// Using a sorted key set to ensure determinism.
	canonical := fmt.Sprintf(
		"seq=%d|prev=%s|cat=%s|sev=%s|act=%s|height=%d|ts=%s|actor=%s",
		r.Sequence, r.PreviousHash, r.Category, r.Severity, r.Action,
		r.BlockHeight, r.Timestamp, r.Actor,
	)
	// Append sorted details.
	if len(r.Details) > 0 {
		// Sort keys for determinism.
		keys := sortedKeys(r.Details)
		for _, k := range keys {
			canonical += fmt.Sprintf("|%s=%s", k, r.Details[k])
		}
	}
	hash := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(hash[:])
}

// sortedKeys returns the keys of a map in sorted order (insertion sort).
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Insertion sort (deterministic, no import needed)
	for i := 1; i < len(keys); i++ {
		k := keys[i]
		j := i - 1
		for j >= 0 && keys[j] > k {
			keys[j+1] = keys[j]
			j--
		}
		keys[j+1] = k
	}
	return keys
}

// ---------------------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------------------

// AuditLogger maintains a hash-chained sequence of audit records and emits
// them to both the SDK event system and the structured logger.
type AuditLogger struct {
	mu           sync.Mutex
	sequence     uint64
	lastHash     string
	records      []AuditRecord // in-memory buffer (bounded)
	bufferCap    int
	totalEmitted uint64
}

// NewAuditLogger creates a new audit logger with a bounded in-memory buffer.
// Records beyond the buffer capacity displace the oldest records (ring buffer
// semantics) in memory, but all records are still emitted to the SDK event
// system for on-chain persistence.
func NewAuditLogger(bufferCapacity int) *AuditLogger {
	if bufferCapacity <= 0 {
		bufferCapacity = 10000
	}
	return &AuditLogger{
		bufferCap: bufferCapacity,
		records:   make([]AuditRecord, 0, bufferCapacity),
		lastHash:  "genesis",
	}
}

// Record creates a new audit record, computes its hash (chained to the
// previous record), appends it to the buffer, emits it as an SDK event,
// and logs it through the Cosmos SDK logger.
func (al *AuditLogger) Record(ctx sdk.Context, category AuditCategory, severity AuditSeverity, action, actor string, details map[string]string) *AuditRecord {
	al.mu.Lock()
	defer al.mu.Unlock()

	al.sequence++
	record := AuditRecord{
		Sequence:     al.sequence,
		PreviousHash: al.lastHash,
		Category:     category,
		Severity:     severity,
		Action:       action,
		BlockHeight:  ctx.BlockHeight(),
		Timestamp:    ctx.BlockTime().UTC().Format(time.RFC3339),
		Actor:        actor,
		Details:      details,
	}

	// Compute and set the record hash.
	record.RecordHash = record.computeHash()
	al.lastHash = record.RecordHash

	// Append to ring buffer.
	if len(al.records) < al.bufferCap {
		al.records = append(al.records, record)
	} else {
		al.records[int(al.totalEmitted)%al.bufferCap] = record
	}
	al.totalEmitted++

	// Emit SDK event for on-chain persistence.
	al.emitAuditEvent(ctx, &record)

	// Log for operator visibility.
	al.logRecord(ctx, &record)

	return &record
}

// emitAuditEvent emits the audit record as a structured SDK event.
func (al *AuditLogger) emitAuditEvent(ctx sdk.Context, r *AuditRecord) {
	attrs := []sdk.Attribute{
		sdk.NewAttribute("sequence", strconv.FormatUint(r.Sequence, 10)),
		sdk.NewAttribute("record_hash", r.RecordHash),
		sdk.NewAttribute("previous_hash", r.PreviousHash),
		sdk.NewAttribute("category", string(r.Category)),
		sdk.NewAttribute("severity", string(r.Severity)),
		sdk.NewAttribute("action", r.Action),
		sdk.NewAttribute("actor", r.Actor),
		sdk.NewAttribute("block_height", strconv.FormatInt(r.BlockHeight, 10)),
		sdk.NewAttribute("timestamp", r.Timestamp),
	}

	// Add detail attributes (prefixed with "detail_" to avoid collisions).
	for _, k := range sortedKeys(r.Details) {
		attrs = append(attrs, sdk.NewAttribute("detail_"+k, r.Details[k]))
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent("audit_record", attrs...),
	)
}

// logRecord writes the audit record to the Cosmos SDK logger with structured
// key-value pairs for operator visibility and log aggregation.
func (al *AuditLogger) logRecord(ctx sdk.Context, r *AuditRecord) {
	kvs := []interface{}{
		"sequence", r.Sequence,
		"hash", r.RecordHash[:16], // truncated for readability
		"category", string(r.Category),
		"action", r.Action,
		"actor", r.Actor,
		"block_height", r.BlockHeight,
	}

	// Add details.
	for _, k := range sortedKeys(r.Details) {
		kvs = append(kvs, k, r.Details[k])
	}

	switch r.Severity {
	case AuditSeverityCritical:
		ctx.Logger().Error("AUDIT", kvs...)
	case AuditSeverityWarning:
		ctx.Logger().Warn("AUDIT", kvs...)
	default:
		ctx.Logger().Info("AUDIT", kvs...)
	}
}

// ---------------------------------------------------------------------------
// Query / export
// ---------------------------------------------------------------------------

// GetRecords returns a copy of the buffered audit records. The returned slice
// is safe to iterate without locks.
func (al *AuditLogger) GetRecords() []AuditRecord {
	al.mu.Lock()
	defer al.mu.Unlock()

	out := make([]AuditRecord, len(al.records))
	copy(out, al.records)
	return out
}

// GetRecordsSince returns all buffered audit records at or after the given
// block height.
func (al *AuditLogger) GetRecordsSince(height int64) []AuditRecord {
	al.mu.Lock()
	defer al.mu.Unlock()

	var out []AuditRecord
	for _, r := range al.records {
		if r.BlockHeight >= height {
			out = append(out, r)
		}
	}
	return out
}

// GetRecordsByCategory returns all buffered records matching the given
// category.
func (al *AuditLogger) GetRecordsByCategory(cat AuditCategory) []AuditRecord {
	al.mu.Lock()
	defer al.mu.Unlock()

	var out []AuditRecord
	for _, r := range al.records {
		if r.Category == cat {
			out = append(out, r)
		}
	}
	return out
}

// GetRecordsBySeverity returns all buffered records matching the given
// severity or higher.
func (al *AuditLogger) GetRecordsBySeverity(minSeverity AuditSeverity) []AuditRecord {
	al.mu.Lock()
	defer al.mu.Unlock()

	minOrd := severityOrdinal(minSeverity)
	var out []AuditRecord
	for _, r := range al.records {
		if severityOrdinal(r.Severity) >= minOrd {
			out = append(out, r)
		}
	}
	return out
}

func severityOrdinal(s AuditSeverity) int {
	switch s {
	case AuditSeverityInfo:
		return 0
	case AuditSeverityWarning:
		return 1
	case AuditSeverityCritical:
		return 2
	default:
		return 0
	}
}

// TotalEmitted returns the total number of audit records ever emitted
// (may exceed the buffer capacity).
func (al *AuditLogger) TotalEmitted() uint64 {
	al.mu.Lock()
	defer al.mu.Unlock()
	return al.totalEmitted
}

// Sequence returns the current sequence number.
func (al *AuditLogger) Sequence() uint64 {
	al.mu.Lock()
	defer al.mu.Unlock()
	return al.sequence
}

// LastHash returns the hash of the most recent record.
func (al *AuditLogger) LastHash() string {
	al.mu.Lock()
	defer al.mu.Unlock()
	return al.lastHash
}

// ExportJSON serializes all buffered records to a JSON byte slice.
func (al *AuditLogger) ExportJSON() ([]byte, error) {
	records := al.GetRecords()
	return json.Marshal(records)
}

// VerifyChain verifies the hash chain integrity of all buffered records.
// Returns nil if the chain is valid, or an error describing the first
// broken link.
func (al *AuditLogger) VerifyChain() error {
	al.mu.Lock()
	defer al.mu.Unlock()

	for i, r := range al.records {
		// Recompute hash.
		expected := r.computeHash()
		if expected != r.RecordHash {
			return fmt.Errorf("audit chain broken at sequence %d: expected hash %s, got %s",
				r.Sequence, expected, r.RecordHash)
		}

		// Check chain linkage.
		if i > 0 {
			if r.PreviousHash != al.records[i-1].RecordHash {
				return fmt.Errorf("audit chain broken at sequence %d: previous hash mismatch", r.Sequence)
			}
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Convenience audit helpers for common operations
// ---------------------------------------------------------------------------

// AuditJobSubmitted records a job submission event.
func (al *AuditLogger) AuditJobSubmitted(ctx sdk.Context, jobID, modelHash, requestedBy, proofType string) {
	al.Record(ctx, AuditCategoryJob, AuditSeverityInfo, "job_submitted", requestedBy, map[string]string{
		"job_id":     jobID,
		"model_hash": modelHash,
		"proof_type": proofType,
	})
}

// AuditJobCompleted records a job completion event.
func (al *AuditLogger) AuditJobCompleted(ctx sdk.Context, jobID, sealID, outputHash string, validatorCount int) {
	al.Record(ctx, AuditCategoryJob, AuditSeverityInfo, "job_completed", "system", map[string]string{
		"job_id":          jobID,
		"seal_id":         sealID,
		"output_hash":     outputHash,
		"validator_count": strconv.Itoa(validatorCount),
	})
}

// AuditJobFailed records a job failure event.
func (al *AuditLogger) AuditJobFailed(ctx sdk.Context, jobID, reason string) {
	al.Record(ctx, AuditCategoryJob, AuditSeverityWarning, "job_failed", "system", map[string]string{
		"job_id": jobID,
		"reason": reason,
	})
}

// AuditConsensusReached records a consensus event.
func (al *AuditLogger) AuditConsensusReached(ctx sdk.Context, jobID string, agreement int, totalVoters int) {
	al.Record(ctx, AuditCategoryConsensus, AuditSeverityInfo, "consensus_reached", "system", map[string]string{
		"job_id":       jobID,
		"agreement":    strconv.Itoa(agreement),
		"total_voters": strconv.Itoa(totalVoters),
	})
}

// AuditConsensusFailed records a consensus failure.
func (al *AuditLogger) AuditConsensusFailed(ctx sdk.Context, jobID string, agreement int, required int) {
	al.Record(ctx, AuditCategoryConsensus, AuditSeverityWarning, "consensus_failed", "system", map[string]string{
		"job_id":    jobID,
		"agreement": strconv.Itoa(agreement),
		"required":  strconv.Itoa(required),
	})
}

// AuditSlashingApplied records a slashing penalty.
func (al *AuditLogger) AuditSlashingApplied(ctx sdk.Context, validatorAddr, condition, severity, amount, jobID string) {
	al.Record(ctx, AuditCategorySlashing, AuditSeverityCritical, "slashing_applied", validatorAddr, map[string]string{
		"condition": condition,
		"severity":  severity,
		"amount":    amount,
		"job_id":    jobID,
	})
}

// AuditEvidenceDetected records evidence of misbehavior.
func (al *AuditLogger) AuditEvidenceDetected(ctx sdk.Context, validatorAddr, condition, detectedBy, jobID string) {
	sev := AuditSeverityWarning
	if condition == "double_sign" || condition == "collusion" {
		sev = AuditSeverityCritical
	}
	al.Record(ctx, AuditCategorySecurity, sev, "evidence_detected", "system", map[string]string{
		"validator":   validatorAddr,
		"condition":   condition,
		"detected_by": detectedBy,
		"job_id":      jobID,
	})
}

// AuditParamChange records a governance parameter change.
func (al *AuditLogger) AuditParamChange(ctx sdk.Context, authority string, changes []ParamFieldChange) {
	details := map[string]string{
		"authority":    authority,
		"change_count": strconv.Itoa(len(changes)),
	}
	for _, c := range changes {
		details["changed_"+c.Field] = c.OldValue + " -> " + c.NewValue
	}
	al.Record(ctx, AuditCategoryGovernance, AuditSeverityWarning, "params_updated", authority, details)
}

// AuditFeeDistributed records a fee distribution event.
func (al *AuditLogger) AuditFeeDistributed(ctx sdk.Context, jobID, totalFee, validatorReward, treasury, burned, insurance string) {
	al.Record(ctx, AuditCategoryEconomics, AuditSeverityInfo, "fee_distributed", "system", map[string]string{
		"job_id":           jobID,
		"total_fee":        totalFee,
		"validator_reward":  validatorReward,
		"treasury":         treasury,
		"burned":           burned,
		"insurance":        insurance,
	})
}

// AuditValidatorRegistered records a new validator registration.
func (al *AuditLogger) AuditValidatorRegistered(ctx sdk.Context, validatorAddr string, maxJobs int64, isOnline bool) {
	al.Record(ctx, AuditCategoryValidator, AuditSeverityInfo, "validator_registered", validatorAddr, map[string]string{
		"max_concurrent_jobs": strconv.FormatInt(maxJobs, 10),
		"is_online":           strconv.FormatBool(isOnline),
	})
}

// AuditSecurityAlert records a high-severity security event.
func (al *AuditLogger) AuditSecurityAlert(ctx sdk.Context, alertType, description string, details map[string]string) {
	if details == nil {
		details = make(map[string]string)
	}
	details["alert_type"] = alertType
	details["description"] = description
	al.Record(ctx, AuditCategorySecurity, AuditSeverityCritical, "security_alert", "system", details)
}
