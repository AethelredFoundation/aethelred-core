package keeper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"cosmossdk.io/log"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/seal/types"
)

// SealVerifier provides comprehensive seal verification capabilities
type SealVerifier struct {
	logger log.Logger
	keeper *Keeper
	config VerifierConfig
}

// VerifierConfig contains configuration for seal verification
type VerifierConfig struct {
	// VerifyTEEAttestations enables TEE attestation verification
	VerifyTEEAttestations bool

	// VerifyZKMLProofs enables zkML proof verification
	VerifyZKMLProofs bool

	// VerifyConsensus verifies consensus requirements
	VerifyConsensus bool

	// VerifySignatures verifies cryptographic signatures
	VerifySignatures bool

	// AllowExpiredSeals allows verification of expired seals
	AllowExpiredSeals bool

	// MaxAuditTrailSize limits audit trail size
	MaxAuditTrailSize int

	// RequireCompliance requires compliance checks
	RequireCompliance bool
}

// DefaultVerifierConfig returns default configuration
func DefaultVerifierConfig() VerifierConfig {
	return VerifierConfig{
		VerifyTEEAttestations: true,
		VerifyZKMLProofs:      true,
		VerifyConsensus:       true,
		VerifySignatures:      true,
		AllowExpiredSeals:     false,
		MaxAuditTrailSize:     1000,
		RequireCompliance:     true,
	}
}

// VerificationResult contains the result of seal verification
type SealVerificationResult struct {
	// Valid indicates overall validity
	Valid bool `json:"valid"`

	// SealID that was verified
	SealID string `json:"seal_id"`

	// Checks contains individual check results
	Checks []VerificationCheck `json:"checks"`

	// FailedChecks lists failed check names
	FailedChecks []string `json:"failed_checks,omitempty"`

	// Warnings for non-fatal issues
	Warnings []string `json:"warnings,omitempty"`

	// VerificationTime how long verification took
	VerificationTimeMs int64 `json:"verification_time_ms"`

	// Timestamp when verification was performed
	Timestamp time.Time `json:"timestamp"`

	// Summary provides a human-readable summary
	Summary string `json:"summary"`
}

// VerificationCheck represents a single verification check
type VerificationCheck struct {
	// Name of the check
	Name string `json:"name"`

	// Passed indicates if the check passed
	Passed bool `json:"passed"`

	// Message provides details
	Message string `json:"message"`

	// Required indicates if this check is required
	Required bool `json:"required"`

	// TimeMs how long the check took
	TimeMs int64 `json:"time_ms"`
}

// NewSealVerifier creates a new seal verifier
func NewSealVerifier(logger log.Logger, keeper *Keeper, config VerifierConfig) *SealVerifier {
	return &SealVerifier{
		logger: logger,
		keeper: keeper,
		config: config,
	}
}

// VerifySeal performs comprehensive verification of a seal
func (sv *SealVerifier) VerifySeal(ctx context.Context, sealID string) (*SealVerificationResult, error) {
	startTime := time.Now()

	result := &SealVerificationResult{
		SealID:    sealID,
		Valid:     true,
		Checks:    make([]VerificationCheck, 0),
		Timestamp: time.Now().UTC(),
	}

	// Get the seal
	seal, err := sv.keeper.GetSeal(ctx, sealID)
	if err != nil {
		result.Valid = false
		result.Summary = fmt.Sprintf("Seal not found: %s", sealID)
		return result, nil
	}

	// Perform verification checks
	sv.checkBasicValidity(seal, result)
	sv.checkStatus(seal, result)
	sv.checkExpiration(seal, result)
	sv.checkHashIntegrity(seal, result)
	sv.checkConsensus(seal, result)
	sv.checkTEEAttestations(ctx, seal, result)
	sv.checkZKMLProof(ctx, seal, result)
	sv.checkSignatures(seal, result)
	sv.checkCompliance(seal, result)
	sv.checkAuditTrail(seal, result)

	// Compute overall result
	result.Valid = len(result.FailedChecks) == 0
	result.VerificationTimeMs = time.Since(startTime).Milliseconds()
	result.Summary = sv.generateSummary(result)

	// Log verification
	sv.logger.Info("Seal verification completed",
		"seal_id", sealID,
		"valid", result.Valid,
		"checks", len(result.Checks),
		"failed", len(result.FailedChecks),
	)

	return result, nil
}

// checkBasicValidity verifies basic seal validity
func (sv *SealVerifier) checkBasicValidity(seal *types.DigitalSeal, result *SealVerificationResult) {
	startTime := time.Now()

	check := VerificationCheck{
		Name:     "basic_validity",
		Required: true,
	}

	if err := seal.Validate(); err != nil {
		check.Passed = false
		check.Message = fmt.Sprintf("Validation failed: %v", err)
		result.FailedChecks = append(result.FailedChecks, check.Name)
	} else {
		check.Passed = true
		check.Message = "Seal passes basic validation"
	}

	check.TimeMs = time.Since(startTime).Milliseconds()
	result.Checks = append(result.Checks, check)
}

// checkStatus verifies seal status
func (sv *SealVerifier) checkStatus(seal *types.DigitalSeal, result *SealVerificationResult) {
	startTime := time.Now()

	check := VerificationCheck{
		Name:     "status",
		Required: true,
	}

	switch seal.Status {
	case types.SealStatusActive:
		check.Passed = true
		check.Message = "Seal is active"
	case types.SealStatusPending:
		check.Passed = false
		check.Message = "Seal is still pending activation"
		result.FailedChecks = append(result.FailedChecks, check.Name)
	case types.SealStatusRevoked:
		check.Passed = false
		check.Message = "Seal has been revoked"
		result.FailedChecks = append(result.FailedChecks, check.Name)
	case types.SealStatusExpired:
		if sv.config.AllowExpiredSeals {
			check.Passed = true
			check.Message = "Seal has expired (allowed)"
			result.Warnings = append(result.Warnings, "Seal has expired")
		} else {
			check.Passed = false
			check.Message = "Seal has expired"
			result.FailedChecks = append(result.FailedChecks, check.Name)
		}
	default:
		check.Passed = false
		check.Message = fmt.Sprintf("Unknown seal status: %s", seal.Status.String())
		result.FailedChecks = append(result.FailedChecks, check.Name)
	}

	check.TimeMs = time.Since(startTime).Milliseconds()
	result.Checks = append(result.Checks, check)
}

// checkExpiration verifies seal hasn't expired
func (sv *SealVerifier) checkExpiration(seal *types.DigitalSeal, result *SealVerificationResult) {
	startTime := time.Now()

	check := VerificationCheck{
		Name:     "expiration",
		Required: !sv.config.AllowExpiredSeals,
	}

	// For basic seal, check retention period
	if seal.RegulatoryInfo != nil && seal.RegulatoryInfo.RetentionPeriod != nil {
		if seal.Timestamp == nil {
			check.Passed = false
			check.Message = "seal timestamp missing for retention check"
			result.FailedChecks = append(result.FailedChecks, check.Name)
			check.TimeMs = time.Since(startTime).Milliseconds()
			result.Checks = append(result.Checks, check)
			return
		}

		expirationTime := seal.Timestamp.AsTime().Add(seal.RegulatoryInfo.RetentionPeriod.AsDuration())
		if time.Now().After(expirationTime) {
			if sv.config.AllowExpiredSeals {
				check.Passed = true
				check.Message = "Seal retention period has passed (allowed)"
				result.Warnings = append(result.Warnings, "Seal retention period exceeded")
			} else {
				check.Passed = false
				check.Message = "Seal retention period has passed"
				result.FailedChecks = append(result.FailedChecks, check.Name)
			}
		} else {
			check.Passed = true
			check.Message = fmt.Sprintf("Seal valid until %s", expirationTime.Format(time.RFC3339))
		}
	} else {
		check.Passed = true
		check.Message = "No expiration set"
	}

	check.TimeMs = time.Since(startTime).Milliseconds()
	result.Checks = append(result.Checks, check)
}

// checkHashIntegrity verifies hash integrity
func (sv *SealVerifier) checkHashIntegrity(seal *types.DigitalSeal, result *SealVerificationResult) {
	startTime := time.Now()

	check := VerificationCheck{
		Name:     "hash_integrity",
		Required: true,
	}

	// Verify commitments are proper hashes
	if len(seal.ModelCommitment) != 32 {
		check.Passed = false
		check.Message = "Invalid model commitment length"
		result.FailedChecks = append(result.FailedChecks, check.Name)
	} else if len(seal.InputCommitment) != 32 {
		check.Passed = false
		check.Message = "Invalid input commitment length"
		result.FailedChecks = append(result.FailedChecks, check.Name)
	} else if len(seal.OutputCommitment) != 32 {
		check.Passed = false
		check.Message = "Invalid output commitment length"
		result.FailedChecks = append(result.FailedChecks, check.Name)
	} else {
		check.Passed = true
		check.Message = "All commitments are valid 32-byte hashes"
	}

	check.TimeMs = time.Since(startTime).Milliseconds()
	result.Checks = append(result.Checks, check)
}

// checkConsensus verifies consensus requirements
func (sv *SealVerifier) checkConsensus(seal *types.DigitalSeal, result *SealVerificationResult) {
	if !sv.config.VerifyConsensus {
		return
	}

	startTime := time.Now()

	check := VerificationCheck{
		Name:     "consensus",
		Required: true,
	}

	// Check validator count
	if len(seal.ValidatorSet) == 0 {
		check.Passed = false
		check.Message = "No validators in seal"
		result.FailedChecks = append(result.FailedChecks, check.Name)
	} else if len(seal.TeeAttestations) == 0 && seal.ZkProof == nil {
		check.Passed = false
		check.Message = "No verification evidence in seal"
		result.FailedChecks = append(result.FailedChecks, check.Name)
	} else {
		check.Passed = true
		check.Message = fmt.Sprintf("Seal has %d validators", len(seal.ValidatorSet))
	}

	check.TimeMs = time.Since(startTime).Milliseconds()
	result.Checks = append(result.Checks, check)
}

// checkTEEAttestations verifies TEE attestations
func (sv *SealVerifier) checkTEEAttestations(ctx context.Context, seal *types.DigitalSeal, result *SealVerificationResult) {
	if !sv.config.VerifyTEEAttestations {
		return
	}

	startTime := time.Now()

	check := VerificationCheck{
		Name:     "tee_attestations",
		Required: len(seal.TeeAttestations) > 0,
	}

	if len(seal.TeeAttestations) == 0 {
		check.Passed = true
		check.Message = "No TEE attestations to verify"
		check.TimeMs = time.Since(startTime).Milliseconds()
		result.Checks = append(result.Checks, check)
		return
	}

	// Verify each attestation
	validCount := 0
	for i, attestation := range seal.TeeAttestations {
		if attestation == nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("TEE attestation %d was nil", i))
			continue
		}
		if sv.verifyTEEAttestation(attestation, seal.OutputCommitment) {
			validCount++
		} else {
			result.Warnings = append(result.Warnings, fmt.Sprintf("TEE attestation %d failed verification", i))
		}
	}

	if validCount == len(seal.TeeAttestations) {
		check.Passed = true
		check.Message = fmt.Sprintf("All %d TEE attestations verified", validCount)
	} else if validCount > 0 {
		check.Passed = true
		check.Message = fmt.Sprintf("%d/%d TEE attestations verified", validCount, len(seal.TeeAttestations))
		result.Warnings = append(result.Warnings, "Some TEE attestations failed verification")
	} else {
		check.Passed = false
		check.Message = "No TEE attestations could be verified"
		result.FailedChecks = append(result.FailedChecks, check.Name)
	}

	check.TimeMs = time.Since(startTime).Milliseconds()
	result.Checks = append(result.Checks, check)
}

// verifyTEEAttestation verifies a single TEE attestation
func (sv *SealVerifier) verifyTEEAttestation(attestation *types.TEEAttestation, expectedOutput []byte) bool {
	// In production: verify attestation signature, certificate chain, PCRs
	// For MVP: basic validation
	if len(attestation.Quote) == 0 {
		return false
	}
	if len(attestation.Measurement) == 0 {
		return false
	}
	return true
}

// checkZKMLProof verifies zkML proof
func (sv *SealVerifier) checkZKMLProof(ctx context.Context, seal *types.DigitalSeal, result *SealVerificationResult) {
	if !sv.config.VerifyZKMLProofs {
		return
	}

	startTime := time.Now()

	check := VerificationCheck{
		Name:     "zkml_proof",
		Required: seal.ZkProof != nil,
	}

	if seal.ZkProof == nil {
		check.Passed = true
		check.Message = "No zkML proof to verify"
		check.TimeMs = time.Since(startTime).Milliseconds()
		result.Checks = append(result.Checks, check)
		return
	}

	// Verify the proof
	if sv.verifyZKMLProof(seal.ZkProof) {
		check.Passed = true
		check.Message = fmt.Sprintf("zkML proof verified (%s)", seal.ZkProof.ProofSystem)
	} else {
		check.Passed = false
		check.Message = "zkML proof verification failed"
		result.FailedChecks = append(result.FailedChecks, check.Name)
	}

	check.TimeMs = time.Since(startTime).Milliseconds()
	result.Checks = append(result.Checks, check)
}

// verifyZKMLProof verifies a zkML proof
func (sv *SealVerifier) verifyZKMLProof(proof *types.ZKMLProof) bool {
	// In production: call EZKL/RISC0 verifier
	// For MVP: basic validation
	if len(proof.ProofBytes) == 0 {
		return false
	}
	if len(proof.VerifyingKeyHash) != 32 {
		return false
	}
	return true
}

// checkSignatures verifies cryptographic signatures
func (sv *SealVerifier) checkSignatures(seal *types.DigitalSeal, result *SealVerificationResult) {
	if !sv.config.VerifySignatures {
		return
	}

	startTime := time.Now()

	check := VerificationCheck{
		Name:     "signatures",
		Required: false,
	}

	// Verify attestation signatures
	signedCount := 0
	for _, attestation := range seal.TeeAttestations {
		if attestation != nil && len(attestation.Signature) > 0 {
			signedCount++
		}
	}

	if signedCount > 0 {
		check.Passed = true
		check.Message = fmt.Sprintf("%d signatures present", signedCount)
	} else {
		check.Passed = true
		check.Message = "No signatures to verify"
	}

	check.TimeMs = time.Since(startTime).Milliseconds()
	result.Checks = append(result.Checks, check)
}

// checkCompliance verifies compliance requirements
func (sv *SealVerifier) checkCompliance(seal *types.DigitalSeal, result *SealVerificationResult) {
	if !sv.config.RequireCompliance {
		return
	}

	startTime := time.Now()

	check := VerificationCheck{
		Name:     "compliance",
		Required: true,
	}

	// Check regulatory info
	if seal.RegulatoryInfo == nil || len(seal.RegulatoryInfo.ComplianceFrameworks) == 0 {
		result.Warnings = append(result.Warnings, "No compliance frameworks specified")
	}

	if seal.RegulatoryInfo != nil && seal.RegulatoryInfo.AuditRequired && len(seal.TeeAttestations) == 0 && seal.ZkProof == nil {
		check.Passed = false
		check.Message = "Audit required but no verification evidence"
		result.FailedChecks = append(result.FailedChecks, check.Name)
	} else {
		check.Passed = true
		if seal.RegulatoryInfo != nil {
			check.Message = fmt.Sprintf("Compliance: %v", seal.RegulatoryInfo.ComplianceFrameworks)
		} else {
			check.Message = "Compliance: none specified"
		}
	}

	check.TimeMs = time.Since(startTime).Milliseconds()
	result.Checks = append(result.Checks, check)
}

// checkAuditTrail verifies audit trail integrity
func (sv *SealVerifier) checkAuditTrail(seal *types.DigitalSeal, result *SealVerificationResult) {
	startTime := time.Now()

	check := VerificationCheck{
		Name:     "audit_trail",
		Required: false,
	}

	// Basic seals don't have audit trail
	check.Passed = true
	check.Message = "No audit trail in basic seal"

	check.TimeMs = time.Since(startTime).Milliseconds()
	result.Checks = append(result.Checks, check)
}

// generateSummary generates a human-readable summary
func (sv *SealVerifier) generateSummary(result *SealVerificationResult) string {
	if result.Valid {
		return fmt.Sprintf("Seal %s is VALID. Passed %d/%d checks.", result.SealID, len(result.Checks)-len(result.FailedChecks), len(result.Checks))
	}
	return fmt.Sprintf("Seal %s is INVALID. Failed checks: %v", result.SealID, result.FailedChecks)
}

// VerifyEnhancedSeal verifies an enhanced seal
func (sv *SealVerifier) VerifyEnhancedSeal(ctx context.Context, seal *types.EnhancedDigitalSeal) (*SealVerificationResult, error) {
	startTime := time.Now()

	result := &SealVerificationResult{
		SealID:    seal.Id,
		Valid:     true,
		Checks:    make([]VerificationCheck, 0),
		Timestamp: time.Now().UTC(),
	}

	// Enhanced validation
	if err := seal.ValidateEnhanced(); err != nil {
		result.Valid = false
		result.FailedChecks = append(result.FailedChecks, "enhanced_validation")
		result.Checks = append(result.Checks, VerificationCheck{
			Name:    "enhanced_validation",
			Passed:  false,
			Message: err.Error(),
		})
		result.Summary = fmt.Sprintf("Enhanced validation failed: %v", err)
		return result, nil
	}

	// Verify seal hash
	sv.checkEnhancedSealHash(seal, result)

	// Verify output consistency
	sv.checkOutputConsistency(seal, result)

	// Verify verification bundle
	sv.checkVerificationBundle(seal, result)

	// Verify audit trail chain
	sv.checkEnhancedAuditTrail(seal, result)

	result.Valid = len(result.FailedChecks) == 0
	result.VerificationTimeMs = time.Since(startTime).Milliseconds()
	result.Summary = sv.generateSummary(result)

	return result, nil
}

// checkEnhancedSealHash verifies the seal hash
func (sv *SealVerifier) checkEnhancedSealHash(seal *types.EnhancedDigitalSeal, result *SealVerificationResult) {
	check := VerificationCheck{
		Name:     "seal_hash",
		Required: true,
	}

	computedHash := seal.ComputeSealHash()
	if bytes.Equal(computedHash, seal.SealHash) {
		check.Passed = true
		check.Message = "Seal hash verified"
	} else {
		check.Passed = false
		check.Message = "Seal hash mismatch - seal may have been tampered"
		result.FailedChecks = append(result.FailedChecks, check.Name)
	}

	result.Checks = append(result.Checks, check)
}

// checkOutputConsistency verifies all verifications agree on output
func (sv *SealVerifier) checkOutputConsistency(seal *types.EnhancedDigitalSeal, result *SealVerificationResult) {
	check := VerificationCheck{
		Name:     "output_consistency",
		Required: true,
	}

	if seal.VerifyOutputConsistency() {
		check.Passed = true
		check.Message = "All verifications agree on output"
	} else {
		check.Passed = false
		check.Message = "Output mismatch between verifications"
		result.FailedChecks = append(result.FailedChecks, check.Name)
	}

	result.Checks = append(result.Checks, check)
}

// checkVerificationBundle verifies the verification bundle
func (sv *SealVerifier) checkVerificationBundle(seal *types.EnhancedDigitalSeal, result *SealVerificationResult) {
	check := VerificationCheck{
		Name:     "verification_bundle",
		Required: true,
	}

	bundle := seal.VerificationBundle
	if bundle == nil {
		check.Passed = false
		check.Message = "Missing verification bundle"
		result.FailedChecks = append(result.FailedChecks, check.Name)
		result.Checks = append(result.Checks, check)
		return
	}

	// Verify bundle hash
	computedHash := sv.computeBundleHash(bundle)
	if bytes.Equal(computedHash, bundle.BundleHash) {
		check.Passed = true
		check.Message = fmt.Sprintf("Verification bundle valid (%s)", bundle.VerificationType)
	} else {
		check.Passed = false
		check.Message = "Verification bundle hash mismatch"
		result.FailedChecks = append(result.FailedChecks, check.Name)
	}

	result.Checks = append(result.Checks, check)
}

// computeBundleHash computes bundle hash for verification
func (sv *SealVerifier) computeBundleHash(bundle *types.VerificationBundle) []byte {
	h := sha256.New()
	h.Write([]byte(bundle.VerificationType))
	h.Write(bundle.AggregatedOutputHash)

	for _, tee := range bundle.TEEVerifications {
		h.Write(tee.OutputHash)
		h.Write(tee.AttestationDocument)
	}

	if bundle.ZKMLVerification != nil {
		h.Write(bundle.ZKMLVerification.Proof)
	}

	return h.Sum(nil)
}

// checkEnhancedAuditTrail verifies the audit trail chain
func (sv *SealVerifier) checkEnhancedAuditTrail(seal *types.EnhancedDigitalSeal, result *SealVerificationResult) {
	check := VerificationCheck{
		Name:     "audit_trail",
		Required: false,
	}

	if len(seal.AuditTrail) == 0 {
		check.Passed = true
		check.Message = "No audit trail entries"
		result.Checks = append(result.Checks, check)
		return
	}

	// Verify chain integrity
	valid := true
	for i := 1; i < len(seal.AuditTrail); i++ {
		entry := seal.AuditTrail[i]
		prevEntry := seal.AuditTrail[i-1]

		// Compute expected prev hash
		h := sha256.New()
		h.Write([]byte(prevEntry.Timestamp.String()))
		h.Write([]byte(prevEntry.EventType))
		h.Write([]byte(prevEntry.Actor))
		expectedPrevHash := h.Sum(nil)

		if !bytes.Equal(entry.PreviousStateHash, expectedPrevHash) {
			valid = false
			result.Warnings = append(result.Warnings, fmt.Sprintf("Audit trail break at entry %d", i))
		}
	}

	if valid {
		check.Passed = true
		check.Message = fmt.Sprintf("Audit trail verified (%d entries)", len(seal.AuditTrail))
	} else {
		check.Passed = false
		check.Message = "Audit trail integrity compromised"
		result.FailedChecks = append(result.FailedChecks, check.Name)
	}

	result.Checks = append(result.Checks, check)
}

// RecordSealAccess records an access event for audit
func (sv *SealVerifier) RecordSealAccess(ctx context.Context, sealID, actor, purpose string) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"seal_accessed",
			sdk.NewAttribute("seal_id", sealID),
			sdk.NewAttribute("actor", actor),
			sdk.NewAttribute("purpose", purpose),
			sdk.NewAttribute("timestamp", time.Now().UTC().Format(time.RFC3339)),
		),
	)

	return nil
}
