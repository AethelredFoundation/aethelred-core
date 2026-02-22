package types

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	SealStatusUnspecified = SealStatus_SEAL_STATUS_UNSPECIFIED
	SealStatusPending     = SealStatus_SEAL_STATUS_PENDING
	SealStatusActive      = SealStatus_SEAL_STATUS_ACTIVE
	SealStatusRevoked     = SealStatus_SEAL_STATUS_REVOKED
	SealStatusExpired     = SealStatus_SEAL_STATUS_EXPIRED
)

// NewDigitalSeal creates a new Digital Seal
func NewDigitalSeal(
	modelCommitment, inputCommitment, outputCommitment []byte,
	blockHeight int64,
	requestedBy string,
	purpose string,
) *DigitalSeal {
	seal := &DigitalSeal{
		ModelCommitment:  modelCommitment,
		InputCommitment:  inputCommitment,
		OutputCommitment: outputCommitment,
		BlockHeight:      blockHeight,
		Timestamp:        timestamppb.Now(),
		RequestedBy:      requestedBy,
		Purpose:          purpose,
		Status:           SealStatusPending,
		TeeAttestations:  make([]*TEEAttestation, 0),
		ValidatorSet:     make([]string, 0),
	}

	// Generate unique ID from components
	seal.Id = seal.GenerateID()

	return seal
}

// GenerateID creates a unique identifier for the seal based on its contents.
// SECURITY FIX: Uses full 256-bit hash (64 hex chars) to prevent collision attacks.
// The previous 64-bit truncation (16 hex chars) had a collision probability of
// 2^-32 after ~2^32 seals (birthday paradox), which is unacceptable for production.
//
// The ID is composed of:
//   - Model commitment (32 bytes)
//   - Input commitment (32 bytes)
//   - Block height (8 bytes, deterministic encoding)
//   - Requester address
//   - Timestamp (nanosecond precision)
//   - Output commitment (if present, for uniqueness)
//
// This ensures globally unique IDs with cryptographic collision resistance.
func (s *DigitalSeal) GenerateID() string {
	h := sha256.New()

	// Domain separator to prevent cross-domain attacks
	h.Write([]byte("aethelred_seal_id_v2:"))

	// Core commitment data
	h.Write(s.ModelCommitment)
	h.Write(s.InputCommitment)
	if len(s.OutputCommitment) > 0 {
		h.Write(s.OutputCommitment)
	}

	// Block height (fixed-width encoding for determinism)
	heightBytes := make([]byte, 8)
	heightBytes[0] = byte(s.BlockHeight >> 56)
	heightBytes[1] = byte(s.BlockHeight >> 48)
	heightBytes[2] = byte(s.BlockHeight >> 40)
	heightBytes[3] = byte(s.BlockHeight >> 32)
	heightBytes[4] = byte(s.BlockHeight >> 24)
	heightBytes[5] = byte(s.BlockHeight >> 16)
	heightBytes[6] = byte(s.BlockHeight >> 8)
	heightBytes[7] = byte(s.BlockHeight)
	h.Write(heightBytes)

	// Requester address
	h.Write([]byte(s.RequestedBy))

	// Timestamp (nanosecond precision for uniqueness)
	if s.Timestamp != nil {
		ts := s.Timestamp.AsTime().UTC()
		nsBytes := make([]byte, 8)
		nanos := ts.UnixNano()
		nsBytes[0] = byte(nanos >> 56)
		nsBytes[1] = byte(nanos >> 48)
		nsBytes[2] = byte(nanos >> 40)
		nsBytes[3] = byte(nanos >> 32)
		nsBytes[4] = byte(nanos >> 24)
		nsBytes[5] = byte(nanos >> 16)
		nsBytes[6] = byte(nanos >> 8)
		nsBytes[7] = byte(nanos)
		h.Write(nsBytes)
	}

	// Purpose (additional entropy)
	if len(s.Purpose) > 0 {
		h.Write([]byte(s.Purpose))
	}

	// Return full 256-bit hash as 64 hex characters
	return hex.EncodeToString(h.Sum(nil))
}

// AddAttestation adds a TEE attestation to the seal
func (s *DigitalSeal) AddAttestation(attestation *TEEAttestation) {
	if attestation == nil {
		return
	}
	s.TeeAttestations = append(s.TeeAttestations, attestation)
	s.ValidatorSet = append(s.ValidatorSet, attestation.ValidatorAddress)
}

// SetZKProof sets the zero-knowledge proof for this seal
func (s *DigitalSeal) SetZKProof(proof *ZKMLProof) {
	s.ZkProof = proof
}

// Activate marks the seal as active after consensus is reached
func (s *DigitalSeal) Activate() {
	s.Status = SealStatusActive
}

// Revoke marks the seal as revoked
func (s *DigitalSeal) Revoke() {
	s.Status = SealStatusRevoked
}

// Validate checks if the seal is well-formed
func (s *DigitalSeal) Validate() error {
	if len(s.Id) == 0 {
		return fmt.Errorf("seal ID cannot be empty")
	}
	if len(s.ModelCommitment) != 32 {
		return fmt.Errorf("model commitment must be 32 bytes (SHA-256)")
	}
	if len(s.InputCommitment) != 32 {
		return fmt.Errorf("input commitment must be 32 bytes (SHA-256)")
	}
	if len(s.OutputCommitment) != 32 {
		return fmt.Errorf("output commitment must be 32 bytes (SHA-256)")
	}
	if s.BlockHeight <= 0 {
		return fmt.Errorf("block height must be positive")
	}
	if _, err := sdk.AccAddressFromBech32(s.RequestedBy); err != nil {
		return fmt.Errorf("invalid requester address: %w", err)
	}
	return nil
}

// HasConsensus checks if the seal has sufficient validator attestations
func (s *DigitalSeal) HasConsensus(totalValidators int) bool {
	requiredVotes := (totalValidators*2/3) + 1
	return len(s.TeeAttestations) >= requiredVotes
}

// IsVerified checks if the seal is fully verified
func (s *DigitalSeal) IsVerified() bool {
	// A seal is verified if it has TEE attestations OR a ZK proof
	return len(s.TeeAttestations) > 0 || s.ZkProof != nil
}

// GetVerificationType returns the type of verification used
func (s *DigitalSeal) GetVerificationType() string {
	if len(s.TeeAttestations) > 0 && s.ZkProof != nil {
		return "hybrid"
	}
	if len(s.TeeAttestations) > 0 {
		return "tee"
	}
	if s.ZkProof != nil {
		return "zkml"
	}
	return "none"
}
