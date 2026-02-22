package keeper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"cosmossdk.io/log"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/seal/types"
)

// RevocationManager handles seal revocation operations
type RevocationManager struct {
	logger log.Logger
	keeper *Keeper

	// Revocation authority addresses
	authorities map[string]RevocationAuthority

	// Pending disputes
	disputes     map[string]*RevocationDispute
	disputeMutex sync.RWMutex

	// Revocation config
	config RevocationConfig
}

// RevocationConfig contains revocation configuration
type RevocationConfig struct {
	// MinDisputePeriod before revocation is final
	MinDisputePeriod time.Duration

	// RequiredAuthorityThreshold for multi-sig revocation
	RequiredAuthorityThreshold int

	// AllowUserRevocation allows the requester to revoke their own seals
	AllowUserRevocation bool

	// GracePeriodForNotification after revocation
	GracePeriodForNotification time.Duration

	// MaxRevocationReason character limit
	MaxRevocationReason int
}

// DefaultRevocationConfig returns default configuration
func DefaultRevocationConfig() RevocationConfig {
	return RevocationConfig{
		MinDisputePeriod:           24 * time.Hour,
		RequiredAuthorityThreshold: 1,
		AllowUserRevocation:        true,
		GracePeriodForNotification: 7 * 24 * time.Hour,
		MaxRevocationReason:        500,
	}
}

// RevocationAuthority represents an authorized revoker
type RevocationAuthority struct {
	// Address of the authority
	Address string `json:"address"`

	// Name of the authority
	Name string `json:"name"`

	// Level determines revocation power
	Level AuthorityLevel `json:"level"`

	// CanRevokePurposes lists purposes this authority can revoke
	CanRevokePurposes []string `json:"can_revoke_purposes"`

	// Active status
	Active bool `json:"active"`

	// RegisteredAt when authority was registered
	RegisteredAt time.Time `json:"registered_at"`
}

// AuthorityLevel represents authority levels
type AuthorityLevel int

const (
	AuthorityLevelUser       AuthorityLevel = 1 // Can revoke own seals
	AuthorityLevelOperator   AuthorityLevel = 2 // Can revoke seals for their purpose
	AuthorityLevelAdmin      AuthorityLevel = 3 // Can revoke any seal
	AuthorityLevelEmergency  AuthorityLevel = 4 // Can force revoke without dispute
)

// RevocationRequest represents a request to revoke a seal
type RevocationRequest struct {
	// RequestID unique identifier
	RequestID string `json:"request_id"`

	// SealID to revoke
	SealID string `json:"seal_id"`

	// Requester address
	Requester string `json:"requester"`

	// Reason for revocation
	Reason RevocationReason `json:"reason"`

	// ReasonDetails additional details
	ReasonDetails string `json:"reason_details"`

	// Evidence supporting revocation
	Evidence []RevocationEvidence `json:"evidence,omitempty"`

	// Status of the request
	Status RevocationRequestStatus `json:"status"`

	// CreatedAt timestamp
	CreatedAt time.Time `json:"created_at"`

	// ProcessedAt when processed
	ProcessedAt *time.Time `json:"processed_at,omitempty"`

	// ProcessedBy who processed
	ProcessedBy string `json:"processed_by,omitempty"`

	// DisputeDeadline for challenging
	DisputeDeadline time.Time `json:"dispute_deadline"`

	// Approvals for multi-sig
	Approvals []RevocationApproval `json:"approvals,omitempty"`
}

// RevocationReason represents the reason for revocation
type RevocationReason string

const (
	RevocationReasonUserRequest   RevocationReason = "user_request"
	RevocationReasonInvalidOutput RevocationReason = "invalid_output"
	RevocationReasonFraud         RevocationReason = "fraud_detected"
	RevocationReasonModelCompromised RevocationReason = "model_compromised"
	RevocationReasonPrivacyBreach RevocationReason = "privacy_breach"
	RevocationReasonComplianceViolation RevocationReason = "compliance_violation"
	RevocationReasonTEECompromised RevocationReason = "tee_compromised"
	RevocationReasonLegalOrder    RevocationReason = "legal_order"
	RevocationReasonExpired       RevocationReason = "expired"
	RevocationReasonReplaced      RevocationReason = "replaced"
	RevocationReasonOther         RevocationReason = "other"
)

// RevocationRequestStatus represents the status of a revocation request
type RevocationRequestStatus string

const (
	RevocationStatusPending   RevocationRequestStatus = "pending"
	RevocationStatusApproved  RevocationRequestStatus = "approved"
	RevocationStatusRejected  RevocationRequestStatus = "rejected"
	RevocationStatusDisputed  RevocationRequestStatus = "disputed"
	RevocationStatusExecuted  RevocationRequestStatus = "executed"
	RevocationStatusCancelled RevocationRequestStatus = "cancelled"
)

// RevocationEvidence represents evidence supporting revocation
type RevocationEvidence struct {
	// Type of evidence
	Type EvidenceType `json:"type"`

	// Description of evidence
	Description string `json:"description"`

	// Hash of the evidence data
	DataHash []byte `json:"data_hash"`

	// URI where evidence is stored
	URI string `json:"uri,omitempty"`

	// Timestamp when evidence was created
	Timestamp time.Time `json:"timestamp"`

	// Submitter who submitted evidence
	Submitter string `json:"submitter"`
}

// EvidenceType represents types of evidence
type EvidenceType string

const (
	EvidenceTypeDocument   EvidenceType = "document"
	EvidenceTypeProof      EvidenceType = "proof"
	EvidenceTypeAttestation EvidenceType = "attestation"
	EvidenceTypeAuditLog   EvidenceType = "audit_log"
	EvidenceTypeExternalRef EvidenceType = "external_ref"
)

// RevocationApproval represents an approval for revocation
type RevocationApproval struct {
	// Authority who approved
	Authority string `json:"authority"`

	// Approved or rejected
	Approved bool `json:"approved"`

	// Comments
	Comments string `json:"comments,omitempty"`

	// Timestamp of approval
	Timestamp time.Time `json:"timestamp"`

	// Signature over the approval
	Signature []byte `json:"signature,omitempty"`
}

// RevocationDispute represents a dispute against revocation
type RevocationDispute struct {
	// DisputeID unique identifier
	DisputeID string `json:"dispute_id"`

	// RequestID being disputed
	RequestID string `json:"request_id"`

	// SealID being disputed
	SealID string `json:"seal_id"`

	// Disputant who filed the dispute
	Disputant string `json:"disputant"`

	// Reason for dispute
	Reason string `json:"reason"`

	// Evidence supporting dispute
	Evidence []RevocationEvidence `json:"evidence,omitempty"`

	// Status of dispute
	Status DisputeStatus `json:"status"`

	// CreatedAt timestamp
	CreatedAt time.Time `json:"created_at"`

	// ResolvedAt when resolved
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`

	// Resolution details
	Resolution string `json:"resolution,omitempty"`

	// ResolvedBy who resolved
	ResolvedBy string `json:"resolved_by,omitempty"`
}

// DisputeStatus represents dispute status
type DisputeStatus string

const (
	DisputeStatusOpen      DisputeStatus = "open"
	DisputeStatusUnderReview DisputeStatus = "under_review"
	DisputeStatusUpheld    DisputeStatus = "upheld"    // Revocation cancelled
	DisputeStatusRejected  DisputeStatus = "rejected"  // Revocation proceeds
	DisputeStatusClosed    DisputeStatus = "closed"
)

// RevocationResult contains the result of a revocation operation
type RevocationResult struct {
	// Success indicates if revocation was successful
	Success bool `json:"success"`

	// SealID that was revoked
	SealID string `json:"seal_id"`

	// RequestID of the revocation request
	RequestID string `json:"request_id"`

	// Reason for revocation
	Reason RevocationReason `json:"reason"`

	// RevokedBy who revoked
	RevokedBy string `json:"revoked_by"`

	// RevokedAt timestamp
	RevokedAt time.Time `json:"revoked_at"`

	// BlockHeight when revocation was recorded
	BlockHeight int64 `json:"block_height"`

	// TransactionHash of the revocation
	TransactionHash string `json:"transaction_hash,omitempty"`

	// Error if any
	Error string `json:"error,omitempty"`
}

// NewRevocationManager creates a new revocation manager
func NewRevocationManager(logger log.Logger, keeper *Keeper, config RevocationConfig) *RevocationManager {
	return &RevocationManager{
		logger:      logger,
		keeper:      keeper,
		authorities: make(map[string]RevocationAuthority),
		disputes:    make(map[string]*RevocationDispute),
		config:      config,
	}
}

// RegisterAuthority registers a revocation authority
func (rm *RevocationManager) RegisterAuthority(authority RevocationAuthority) error {
	if authority.Address == "" {
		return fmt.Errorf("authority address is required")
	}

	authority.RegisteredAt = time.Now().UTC()
	authority.Active = true
	rm.authorities[authority.Address] = authority

	rm.logger.Info("Revocation authority registered",
		"address", authority.Address,
		"level", authority.Level,
	)

	return nil
}

// RequestRevocation creates a new revocation request
func (rm *RevocationManager) RequestRevocation(ctx context.Context, req *RevocationRequest) (*RevocationRequest, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Validate request
	if err := rm.validateRevocationRequest(ctx, req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Get the seal
	seal, err := rm.keeper.GetSeal(ctx, req.SealID)
	if err != nil {
		return nil, fmt.Errorf("seal not found: %w", err)
	}

	// Check if seal is already revoked
	if seal.Status == types.SealStatusRevoked {
		return nil, fmt.Errorf("seal is already revoked")
	}

	// Generate request ID
	req.RequestID = rm.generateRequestID(req)
	req.Status = RevocationStatusPending
	req.CreatedAt = time.Now().UTC()
	req.DisputeDeadline = req.CreatedAt.Add(rm.config.MinDisputePeriod)

	// Check if requester has authority
	authority, hasAuthority := rm.authorities[req.Requester]
	if !hasAuthority && rm.config.AllowUserRevocation {
		// Check if requester is the seal owner
		if seal.RequestedBy != req.Requester {
			return nil, fmt.Errorf("not authorized to revoke this seal")
		}
	}

	// If user has high enough authority, auto-approve
	if hasAuthority && authority.Level >= AuthorityLevelAdmin {
		req.Status = RevocationStatusApproved
		now := time.Now().UTC()
		req.ProcessedAt = &now
		req.ProcessedBy = req.Requester
	}

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"seal_revocation_requested",
			sdk.NewAttribute("request_id", req.RequestID),
			sdk.NewAttribute("seal_id", req.SealID),
			sdk.NewAttribute("requester", req.Requester),
			sdk.NewAttribute("reason", string(req.Reason)),
		),
	)

	rm.logger.Info("Revocation requested",
		"request_id", req.RequestID,
		"seal_id", req.SealID,
		"requester", req.Requester,
		"reason", req.Reason,
	)

	return req, nil
}

// ApproveRevocation approves a revocation request
func (rm *RevocationManager) ApproveRevocation(ctx context.Context, requestID, approver string, comments string) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Check if approver is an authority
	authority, hasAuthority := rm.authorities[approver]
	if !hasAuthority {
		return fmt.Errorf("not a registered authority")
	}

	if authority.Level < AuthorityLevelOperator {
		return fmt.Errorf("insufficient authority level")
	}

	// In production, get request from store
	// For MVP, just log and emit event
	approval := RevocationApproval{
		Authority: approver,
		Approved:  true,
		Comments:  comments,
		Timestamp: time.Now().UTC(),
	}

	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"seal_revocation_approved",
			sdk.NewAttribute("request_id", requestID),
			sdk.NewAttribute("approver", approver),
		),
	)

	rm.logger.Info("Revocation approved",
		"request_id", requestID,
		"approver", approver,
		"approval", approval,
	)

	return nil
}

// ExecuteRevocation executes a revocation after approval
func (rm *RevocationManager) ExecuteRevocation(ctx context.Context, requestID string) (*RevocationResult, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// In production, get request from store and validate it's approved
	// For MVP, we'll accept the request ID and look up the seal

	result := &RevocationResult{
		RequestID:   requestID,
		RevokedAt:   time.Now().UTC(),
		BlockHeight: sdkCtx.BlockHeight(),
	}

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"seal_revoked",
			sdk.NewAttribute("request_id", requestID),
			sdk.NewAttribute("block_height", fmt.Sprintf("%d", result.BlockHeight)),
		),
	)

	rm.logger.Info("Revocation executed",
		"request_id", requestID,
		"block_height", result.BlockHeight,
	)

	result.Success = true
	return result, nil
}

// RevokeSeal is a convenience method to revoke a seal directly (for authorized users)
func (rm *RevocationManager) RevokeSeal(ctx context.Context, sealID, revoker string, reason RevocationReason, details string) (*RevocationResult, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Get the seal
	seal, err := rm.keeper.GetSeal(ctx, sealID)
	if err != nil {
		return nil, fmt.Errorf("seal not found: %w", err)
	}

	// Check authorization
	authority, hasAuthority := rm.authorities[revoker]
	canRevoke := false

	if hasAuthority && authority.Level >= AuthorityLevelAdmin {
		canRevoke = true
	} else if rm.config.AllowUserRevocation && seal.RequestedBy == revoker {
		canRevoke = true
	}

	if !canRevoke {
		return nil, fmt.Errorf("not authorized to revoke this seal")
	}

	// Check if already revoked
	if seal.Status == types.SealStatusRevoked {
		return nil, fmt.Errorf("seal is already revoked")
	}

	// Revoke the seal
	seal.Status = types.SealStatusRevoked

	// Update seal in store
	if err := rm.keeper.SetSeal(ctx, seal); err != nil {
		return nil, fmt.Errorf("failed to update seal: %w", err)
	}

	// Create result
	result := &RevocationResult{
		Success:     true,
		SealID:      sealID,
		RequestID:   rm.generateRequestID(&RevocationRequest{SealID: sealID, Requester: revoker}),
		Reason:      reason,
		RevokedBy:   revoker,
		RevokedAt:   time.Now().UTC(),
		BlockHeight: sdkCtx.BlockHeight(),
	}

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"seal_revoked",
			sdk.NewAttribute("seal_id", sealID),
			sdk.NewAttribute("revoked_by", revoker),
			sdk.NewAttribute("reason", string(reason)),
			sdk.NewAttribute("block_height", fmt.Sprintf("%d", result.BlockHeight)),
		),
	)

	rm.logger.Info("Seal revoked",
		"seal_id", sealID,
		"revoked_by", revoker,
		"reason", reason,
	)

	return result, nil
}

// FileDispute files a dispute against a revocation
func (rm *RevocationManager) FileDispute(ctx context.Context, requestID, disputant, reason string) (*RevocationDispute, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	rm.disputeMutex.Lock()
	defer rm.disputeMutex.Unlock()

	// Create dispute
	dispute := &RevocationDispute{
		DisputeID: rm.generateDisputeID(requestID, disputant),
		RequestID: requestID,
		Disputant: disputant,
		Reason:    reason,
		Status:    DisputeStatusOpen,
		CreatedAt: time.Now().UTC(),
		Evidence:  make([]RevocationEvidence, 0),
	}

	rm.disputes[dispute.DisputeID] = dispute

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"seal_revocation_disputed",
			sdk.NewAttribute("dispute_id", dispute.DisputeID),
			sdk.NewAttribute("request_id", requestID),
			sdk.NewAttribute("disputant", disputant),
		),
	)

	rm.logger.Info("Revocation disputed",
		"dispute_id", dispute.DisputeID,
		"request_id", requestID,
		"disputant", disputant,
	)

	return dispute, nil
}

// ResolveDispute resolves a revocation dispute
func (rm *RevocationManager) ResolveDispute(ctx context.Context, disputeID, resolver string, upheld bool, resolution string) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	rm.disputeMutex.Lock()
	defer rm.disputeMutex.Unlock()

	dispute, exists := rm.disputes[disputeID]
	if !exists {
		return fmt.Errorf("dispute not found")
	}

	// Check resolver authority
	authority, hasAuthority := rm.authorities[resolver]
	if !hasAuthority || authority.Level < AuthorityLevelAdmin {
		return fmt.Errorf("not authorized to resolve disputes")
	}

	now := time.Now().UTC()
	dispute.ResolvedAt = &now
	dispute.ResolvedBy = resolver
	dispute.Resolution = resolution

	if upheld {
		dispute.Status = DisputeStatusUpheld
	} else {
		dispute.Status = DisputeStatusRejected
	}

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"seal_dispute_resolved",
			sdk.NewAttribute("dispute_id", disputeID),
			sdk.NewAttribute("resolver", resolver),
			sdk.NewAttribute("upheld", fmt.Sprintf("%t", upheld)),
		),
	)

	rm.logger.Info("Dispute resolved",
		"dispute_id", disputeID,
		"resolver", resolver,
		"upheld", upheld,
	)

	return nil
}

// GetDispute returns a dispute by ID
func (rm *RevocationManager) GetDispute(disputeID string) (*RevocationDispute, error) {
	rm.disputeMutex.RLock()
	defer rm.disputeMutex.RUnlock()

	dispute, exists := rm.disputes[disputeID]
	if !exists {
		return nil, fmt.Errorf("dispute not found")
	}

	return dispute, nil
}

// GetDisputesByRequest returns all disputes for a revocation request
func (rm *RevocationManager) GetDisputesByRequest(requestID string) []*RevocationDispute {
	rm.disputeMutex.RLock()
	defer rm.disputeMutex.RUnlock()

	disputes := make([]*RevocationDispute, 0)
	for _, dispute := range rm.disputes {
		if dispute.RequestID == requestID {
			disputes = append(disputes, dispute)
		}
	}

	return disputes
}

// EmergencyRevoke performs immediate revocation without dispute period
func (rm *RevocationManager) EmergencyRevoke(ctx context.Context, sealID, revoker string, reason RevocationReason, justification string) (*RevocationResult, error) {
	// Check emergency authority
	authority, hasAuthority := rm.authorities[revoker]
	if !hasAuthority || authority.Level < AuthorityLevelEmergency {
		return nil, fmt.Errorf("not authorized for emergency revocation")
	}

	// Perform revocation
	result, err := rm.RevokeSeal(ctx, sealID, revoker, reason, justification)
	if err != nil {
		return nil, err
	}

	rm.logger.Warn("Emergency revocation executed",
		"seal_id", sealID,
		"revoker", revoker,
		"reason", reason,
		"justification", justification,
	)

	return result, nil
}

// BatchRevoke revokes multiple seals
func (rm *RevocationManager) BatchRevoke(ctx context.Context, sealIDs []string, revoker string, reason RevocationReason, details string) ([]*RevocationResult, error) {
	results := make([]*RevocationResult, 0, len(sealIDs))

	for _, sealID := range sealIDs {
		result, err := rm.RevokeSeal(ctx, sealID, revoker, reason, details)
		if err != nil {
			rm.logger.Warn("Failed to revoke seal in batch",
				"seal_id", sealID,
				"error", err,
			)
			results = append(results, &RevocationResult{
				Success: false,
				SealID:  sealID,
				Error:   err.Error(),
			})
		} else {
			results = append(results, result)
		}
	}

	return results, nil
}

// validateRevocationRequest validates a revocation request
func (rm *RevocationManager) validateRevocationRequest(ctx context.Context, req *RevocationRequest) error {
	if req.SealID == "" {
		return fmt.Errorf("seal ID is required")
	}

	if req.Requester == "" {
		return fmt.Errorf("requester is required")
	}

	if req.Reason == "" {
		return fmt.Errorf("reason is required")
	}

	if len(req.ReasonDetails) > rm.config.MaxRevocationReason {
		return fmt.Errorf("reason details too long (max %d characters)", rm.config.MaxRevocationReason)
	}

	return nil
}

// generateRequestID generates a unique request ID
func (rm *RevocationManager) generateRequestID(req *RevocationRequest) string {
	h := sha256.New()
	h.Write([]byte(req.SealID))
	h.Write([]byte(req.Requester))
	h.Write([]byte(time.Now().String()))
	return fmt.Sprintf("rev-%s", hex.EncodeToString(h.Sum(nil))[:16])
}

// generateDisputeID generates a unique dispute ID
func (rm *RevocationManager) generateDisputeID(requestID, disputant string) string {
	h := sha256.New()
	h.Write([]byte(requestID))
	h.Write([]byte(disputant))
	h.Write([]byte(time.Now().String()))
	return fmt.Sprintf("disp-%s", hex.EncodeToString(h.Sum(nil))[:16])
}

// GetRevocationReasons returns all valid revocation reasons
func GetRevocationReasons() []RevocationReason {
	return []RevocationReason{
		RevocationReasonUserRequest,
		RevocationReasonInvalidOutput,
		RevocationReasonFraud,
		RevocationReasonModelCompromised,
		RevocationReasonPrivacyBreach,
		RevocationReasonComplianceViolation,
		RevocationReasonTEECompromised,
		RevocationReasonLegalOrder,
		RevocationReasonExpired,
		RevocationReasonReplaced,
		RevocationReasonOther,
	}
}
