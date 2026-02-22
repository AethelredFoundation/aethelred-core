// Package app provides application-level vote extension signing for Aethelred.
//
// AS-17: Vote Extension Signing
// This file implements application-level cryptographic signing of vote extensions,
// complementing CometBFT's consensus-level signing with domain-specific signatures
// that bind the vote extension to the validator's compute verification results.
package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"cosmossdk.io/log"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// =============================================================================
// Vote Extension Signature Types
// =============================================================================

// VoteExtensionSignatureVersion is the current signature scheme version
const VoteExtensionSignatureVersion = 1

// VoteExtensionSignatureData contains all data that is signed
type VoteExtensionSignatureData struct {
	// Version for forward compatibility
	Version uint8

	// ChainID to prevent cross-chain replay attacks
	ChainID string

	// Height of the block being voted on
	Height int64

	// Round within the height
	Round int32

	// ValidatorAddress is the consensus address of the signing validator
	ValidatorAddress []byte

	// Timestamp when the extension was created
	Timestamp time.Time

	// ExtensionHash is the SHA-256 hash of the entire vote extension content
	ExtensionHash [32]byte

	// VerificationsMerkleRoot is the Merkle root of all verification results
	// This binds the signature to the specific computation outputs
	VerificationsMerkleRoot [32]byte

	// Nonce for uniqueness
	Nonce []byte
}

// SigningKey wraps the validator's private key with additional metadata
type SigningKey struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	Address    []byte
	KeyID      string // For key rotation tracking
	CreatedAt  time.Time
}

// VoteExtensionSignature contains the cryptographic signature and metadata
type VoteExtensionSignature struct {
	// Signature is the ed25519 signature over SignatureData
	Signature []byte

	// PublicKey is the validator's public key (for verification)
	PublicKey []byte

	// KeyID identifies which key was used (for rotation)
	KeyID string

	// Version of the signature scheme
	Version uint8

	// Timestamp when signed
	Timestamp time.Time
}

// =============================================================================
// Vote Extension Signer
// =============================================================================

// VoteExtensionSigner handles application-level signing of vote extensions
type VoteExtensionSigner struct {
	logger     log.Logger
	chainID    string
	signingKey *SigningKey
	keyHistory map[string]*SigningKey // Historical keys for verification
}

// NewVoteExtensionSigner creates a new vote extension signer
func NewVoteExtensionSigner(logger log.Logger, chainID string) *VoteExtensionSigner {
	return &VoteExtensionSigner{
		logger:     logger,
		chainID:    chainID,
		keyHistory: make(map[string]*SigningKey),
	}
}

// SetSigningKey sets the current signing key
func (s *VoteExtensionSigner) SetSigningKey(privKey ed25519.PrivateKey) error {
	if len(privKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key size: expected %d, got %d", ed25519.PrivateKeySize, len(privKey))
	}

	pubKey := privKey.Public().(ed25519.PublicKey)
	keyID := computeKeyID(pubKey)

	s.signingKey = &SigningKey{
		PrivateKey: privKey,
		PublicKey:  pubKey,
		Address:    computeAddress(pubKey),
		KeyID:      keyID,
		CreatedAt:  time.Now().UTC(),
	}

	// Store in history for verification of old signatures
	s.keyHistory[keyID] = s.signingKey

	s.logger.Info("Vote extension signing key configured",
		"key_id", keyID,
		"address", hex.EncodeToString(s.signingKey.Address),
	)

	return nil
}

// SignVoteExtension signs a vote extension with application-level signature
func (s *VoteExtensionSigner) SignVoteExtension(
	ext *VoteExtension,
	height int64,
	round int32,
) (*VoteExtensionSignature, error) {
	if s.signingKey == nil {
		return nil, errors.New("signing key not configured")
	}

	// Compute extension hash
	extBytes, err := ext.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal extension: %w", err)
	}
	extHash := sha256.Sum256(extBytes)

	// Compute verifications Merkle root
	merkleRoot := computeVerificationsMerkleRoot(ext.Verifications)

	// Build signature data
	sigData := &VoteExtensionSignatureData{
		Version:                 VoteExtensionSignatureVersion,
		ChainID:                 s.chainID,
		Height:                  height,
		Round:                   round,
		ValidatorAddress:        s.signingKey.Address,
		Timestamp:               time.Now().UTC(),
		ExtensionHash:           extHash,
		VerificationsMerkleRoot: merkleRoot,
		Nonce:                   ext.Nonce,
	}

	// Serialize for signing
	signBytes := serializeSignatureData(sigData)

	// Sign with ed25519
	signature := ed25519.Sign(s.signingKey.PrivateKey, signBytes)

	return &VoteExtensionSignature{
		Signature: signature,
		PublicKey: s.signingKey.PublicKey,
		KeyID:     s.signingKey.KeyID,
		Version:   VoteExtensionSignatureVersion,
		Timestamp: sigData.Timestamp,
	}, nil
}

// VerifyVoteExtensionSignature verifies an application-level signature
func (s *VoteExtensionSigner) VerifyVoteExtensionSignature(
	ext *VoteExtension,
	sig *VoteExtensionSignature,
	height int64,
	round int32,
) error {
	if sig == nil {
		return errors.New("signature is nil")
	}

	if len(sig.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size: expected %d, got %d", ed25519.SignatureSize, len(sig.Signature))
	}

	if len(sig.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(sig.PublicKey))
	}

	// Compute extension hash
	extBytes, err := ext.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal extension: %w", err)
	}
	extHash := sha256.Sum256(extBytes)

	// Compute verifications Merkle root
	merkleRoot := computeVerificationsMerkleRoot(ext.Verifications)

	// Derive validator address from public key
	validatorAddr := computeAddress(sig.PublicKey)

	// Rebuild signature data
	sigData := &VoteExtensionSignatureData{
		Version:                 sig.Version,
		ChainID:                 s.chainID,
		Height:                  height,
		Round:                   round,
		ValidatorAddress:        validatorAddr,
		Timestamp:               sig.Timestamp,
		ExtensionHash:           extHash,
		VerificationsMerkleRoot: merkleRoot,
		Nonce:                   ext.Nonce,
	}

	// Serialize for verification
	signBytes := serializeSignatureData(sigData)

	// Verify ed25519 signature
	if !ed25519.Verify(sig.PublicKey, signBytes, sig.Signature) {
		return errors.New("signature verification failed")
	}

	return nil
}

// HasSigningKey returns true if a signing key is configured
func (s *VoteExtensionSigner) HasSigningKey() bool {
	return s.signingKey != nil
}

// GetPublicKey returns the current public key
func (s *VoteExtensionSigner) GetPublicKey() []byte {
	if s.signingKey == nil {
		return nil
	}
	return s.signingKey.PublicKey
}

// GetKeyID returns the current key ID
func (s *VoteExtensionSigner) GetKeyID() string {
	if s.signingKey == nil {
		return ""
	}
	return s.signingKey.KeyID
}

// =============================================================================
// Enhanced Vote Extension with Application Signature
// =============================================================================

// EnhancedVoteExtension wraps VoteExtension with application-level signature
type EnhancedVoteExtension struct {
	// Base vote extension
	*VoteExtension

	// Application-level signature
	AppSignature *VoteExtensionSignature

	// Metadata
	Height int64
	Round  int32
}

// MarshalWithSignature marshals the vote extension including the app signature
func (e *EnhancedVoteExtension) MarshalWithSignature() ([]byte, error) {
	baseBytes, err := e.VoteExtension.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal base extension: %w", err)
	}

	// Append signature data
	// Format: [baseLength(4)][baseBytes][sigLength(4)][sigBytes]
	sigBytes, err := marshalSignature(e.AppSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signature: %w", err)
	}

	result := make([]byte, 4+len(baseBytes)+4+len(sigBytes))
	binary.BigEndian.PutUint32(result[0:4], uint32(len(baseBytes)))
	copy(result[4:4+len(baseBytes)], baseBytes)
	binary.BigEndian.PutUint32(result[4+len(baseBytes):8+len(baseBytes)], uint32(len(sigBytes)))
	copy(result[8+len(baseBytes):], sigBytes)

	return result, nil
}

// UnmarshalEnhancedVoteExtension unmarshals an enhanced vote extension
func UnmarshalEnhancedVoteExtension(data []byte) (*EnhancedVoteExtension, error) {
	if len(data) < 8 {
		return nil, errors.New("data too short")
	}

	baseLen := binary.BigEndian.Uint32(data[0:4])
	if len(data) < int(4+baseLen+4) {
		return nil, errors.New("data too short for base extension")
	}

	baseBytes := data[4 : 4+baseLen]
	sigLenStart := 4 + baseLen
	sigLen := binary.BigEndian.Uint32(data[sigLenStart : sigLenStart+4])

	if len(data) < int(sigLenStart+4+sigLen) {
		return nil, errors.New("data too short for signature")
	}
	sigBytes := data[sigLenStart+4 : sigLenStart+4+sigLen]

	// Unmarshal base extension
	baseExt, err := UnmarshalVoteExtension(baseBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal base extension: %w", err)
	}

	// Unmarshal signature
	sig, err := unmarshalSignature(sigBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signature: %w", err)
	}

	return &EnhancedVoteExtension{
		VoteExtension: baseExt,
		AppSignature:  sig,
	}, nil
}

// =============================================================================
// Vote Extension Verifier for Other Validators
// =============================================================================

// VoteExtensionVerifier verifies vote extensions from other validators
type VoteExtensionVerifier struct {
	logger           log.Logger
	chainID          string
	trustedKeys      map[string]ed25519.PublicKey // Consensus address -> public key
	validatorGetter  ValidatorPublicKeyGetter
}

// ValidatorPublicKeyGetter retrieves validator public keys
type ValidatorPublicKeyGetter interface {
	GetValidatorPubKey(ctx sdk.Context, consAddr sdk.ConsAddress) ([]byte, error)
}

// NewVoteExtensionVerifier creates a new verifier
func NewVoteExtensionVerifier(
	logger log.Logger,
	chainID string,
	validatorGetter ValidatorPublicKeyGetter,
) *VoteExtensionVerifier {
	return &VoteExtensionVerifier{
		logger:          logger,
		chainID:         chainID,
		trustedKeys:     make(map[string]ed25519.PublicKey),
		validatorGetter: validatorGetter,
	}
}

// VerifyExtension verifies a vote extension from another validator
func (v *VoteExtensionVerifier) VerifyExtension(
	ctx sdk.Context,
	ext *VoteExtension,
	height int64,
	round int32,
	expectedValidator sdk.ConsAddress,
) error {
	// Basic validation
	if ext == nil {
		return errors.New("extension is nil")
	}

	// Verify validator address matches
	if !bytes.Equal(ext.ValidatorAddress, expectedValidator) {
		return fmt.Errorf("validator address mismatch: got %x, expected %x",
			ext.ValidatorAddress, expectedValidator)
	}

	// If extension has a signature, verify it
	if len(ext.Signature) > 0 {
		// Get validator's public key
		pubKey, err := v.getValidatorPublicKey(ctx, expectedValidator)
		if err != nil {
			return fmt.Errorf("failed to get validator public key: %w", err)
		}

		// Verify the basic signature first
		if !VerifyVoteExtensionSignature(ext, pubKey) {
			return errors.New("basic signature verification failed")
		}
	}

	// Verify extension hash
	if len(ext.ExtensionHash) > 0 {
		computedHash := ext.ComputeHash()
		if !bytes.Equal(ext.ExtensionHash, computedHash) {
			return fmt.Errorf("extension hash mismatch: got %x, computed %x",
				ext.ExtensionHash, computedHash)
		}
	}

	// Verify timestamp is reasonable
	if !ext.Timestamp.IsZero() {
		now := ctx.BlockTime()
		maxPast := now.Add(-5 * time.Minute)
		maxFuture := now.Add(30 * time.Second)

		if ext.Timestamp.Before(maxPast) || ext.Timestamp.After(maxFuture) {
			return fmt.Errorf("timestamp out of range: %s (expected between %s and %s)",
				ext.Timestamp, maxPast, maxFuture)
		}
	}

	// Verify each verification result
	for _, ver := range ext.Verifications {
		if err := v.verifyComputeVerification(&ver); err != nil {
			return fmt.Errorf("verification %s invalid: %w", ver.JobID, err)
		}
	}

	return nil
}

// verifyComputeVerification validates a single compute verification
func (v *VoteExtensionVerifier) verifyComputeVerification(ver *ComputeVerification) error {
	// Job ID required
	if ver.JobID == "" {
		return errors.New("missing job ID")
	}

	// Model hash required
	if len(ver.ModelHash) == 0 {
		return errors.New("missing model hash")
	}

	// Input hash required
	if len(ver.InputHash) == 0 {
		return errors.New("missing input hash")
	}

	// If successful, output hash required
	if ver.Success && len(ver.OutputHash) == 0 {
		return errors.New("successful verification missing output hash")
	}

	// Verify TEE attestation if present
	if ver.TEEAttestation != nil {
		if err := v.verifyTEEAttestation(ver.TEEAttestation); err != nil {
			return fmt.Errorf("TEE attestation invalid: %w", err)
		}
	}

	// Verify ZK proof if present
	if ver.ZKProof != nil {
		if err := v.verifyZKProof(ver.ZKProof); err != nil {
			return fmt.Errorf("ZK proof invalid: %w", err)
		}
	}

	return nil
}

// verifyTEEAttestation validates a TEE attestation
func (v *VoteExtensionVerifier) verifyTEEAttestation(att *TEEAttestationData) error {
	if att == nil {
		return nil
	}

	// Platform must be specified
	if att.Platform == "" || att.Platform == "unknown" {
		return errors.New("unknown TEE platform")
	}

	// Quote data required for real attestations
	if att.Platform != "simulated" && len(att.Quote) == 0 {
		return errors.New("missing attestation quote")
	}

	// Measurement should be present
	if len(att.Measurement) == 0 {
		return errors.New("missing measurement")
	}

	return nil
}

// verifyZKProof validates a ZK proof
func (v *VoteExtensionVerifier) verifyZKProof(proof *ZKProofData) error {
	if proof == nil {
		return nil
	}

	// Proof bytes required
	if len(proof.Proof) == 0 {
		return errors.New("missing proof bytes")
	}

	// Public inputs required
	if len(proof.PublicInputs) == 0 {
		return errors.New("missing public inputs")
	}

	// Circuit hash required
	if len(proof.CircuitHash) == 0 {
		return errors.New("missing circuit hash")
	}

	return nil
}

// getValidatorPublicKey retrieves the validator's public key
func (v *VoteExtensionVerifier) getValidatorPublicKey(ctx sdk.Context, consAddr sdk.ConsAddress) ([]byte, error) {
	// Check cache first
	addrStr := consAddr.String()
	if pubKey, ok := v.trustedKeys[addrStr]; ok {
		return pubKey, nil
	}

	// Query from validator getter
	if v.validatorGetter != nil {
		pubKey, err := v.validatorGetter.GetValidatorPubKey(ctx, consAddr)
		if err != nil {
			return nil, err
		}
		// Cache the result
		v.trustedKeys[addrStr] = pubKey
		return pubKey, nil
	}

	return nil, fmt.Errorf("validator public key not found: %s", consAddr.String())
}

// =============================================================================
// Helper Functions
// =============================================================================

// computeKeyID computes a unique identifier for a public key
func computeKeyID(pubKey ed25519.PublicKey) string {
	hash := sha256.Sum256(pubKey)
	return hex.EncodeToString(hash[:8])
}

// computeAddress derives the consensus address from a public key
func computeAddress(pubKey []byte) []byte {
	hash := sha256.Sum256(pubKey)
	return hash[:20] // Use first 20 bytes as address
}

// serializeSignatureData serializes the signature data for signing
func serializeSignatureData(data *VoteExtensionSignatureData) []byte {
	// Domain separator
	domainSep := []byte("aethelred_vote_extension_v1:")

	var buf bytes.Buffer
	buf.Write(domainSep)

	// Version
	buf.WriteByte(data.Version)

	// ChainID (length-prefixed)
	chainBytes := []byte(data.ChainID)
	binary.Write(&buf, binary.BigEndian, uint16(len(chainBytes)))
	buf.Write(chainBytes)

	// Height
	binary.Write(&buf, binary.BigEndian, data.Height)

	// Round
	binary.Write(&buf, binary.BigEndian, data.Round)

	// ValidatorAddress (length-prefixed)
	binary.Write(&buf, binary.BigEndian, uint16(len(data.ValidatorAddress)))
	buf.Write(data.ValidatorAddress)

	// Timestamp (Unix nano)
	binary.Write(&buf, binary.BigEndian, data.Timestamp.UnixNano())

	// ExtensionHash
	buf.Write(data.ExtensionHash[:])

	// VerificationsMerkleRoot
	buf.Write(data.VerificationsMerkleRoot[:])

	// Nonce (length-prefixed)
	binary.Write(&buf, binary.BigEndian, uint16(len(data.Nonce)))
	buf.Write(data.Nonce)

	return buf.Bytes()
}

// computeVerificationsMerkleRoot computes the Merkle root of verifications
func computeVerificationsMerkleRoot(verifications []ComputeVerification) [32]byte {
	if len(verifications) == 0 {
		return sha256.Sum256([]byte("empty_verifications"))
	}

	// Compute leaf hashes
	leafHashes := make([][32]byte, len(verifications))
	for i, v := range verifications {
		leafHashes[i] = computeVerificationHash(&v)
	}

	// Build Merkle tree
	for len(leafHashes) > 1 {
		var nextLevel [][32]byte
		for i := 0; i < len(leafHashes); i += 2 {
			if i+1 < len(leafHashes) {
				// Hash pair
				combined := append(leafHashes[i][:], leafHashes[i+1][:]...)
				nextLevel = append(nextLevel, sha256.Sum256(combined))
			} else {
				// Odd number of leaves, promote
				nextLevel = append(nextLevel, leafHashes[i])
			}
		}
		leafHashes = nextLevel
	}

	return leafHashes[0]
}

// computeVerificationHash computes the hash of a single verification
func computeVerificationHash(v *ComputeVerification) [32]byte {
	h := sha256.New()
	h.Write([]byte("verification:"))
	h.Write([]byte(v.JobID))
	h.Write(v.ModelHash)
	h.Write(v.InputHash)
	h.Write(v.OutputHash)
	if v.Success {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}

	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return hash
}

// marshalSignature marshals a vote extension signature
func marshalSignature(sig *VoteExtensionSignature) ([]byte, error) {
	if sig == nil {
		return []byte{0}, nil
	}

	var buf bytes.Buffer

	// Version
	buf.WriteByte(sig.Version)

	// Signature
	binary.Write(&buf, binary.BigEndian, uint16(len(sig.Signature)))
	buf.Write(sig.Signature)

	// PublicKey
	binary.Write(&buf, binary.BigEndian, uint16(len(sig.PublicKey)))
	buf.Write(sig.PublicKey)

	// KeyID
	keyIDBytes := []byte(sig.KeyID)
	binary.Write(&buf, binary.BigEndian, uint16(len(keyIDBytes)))
	buf.Write(keyIDBytes)

	// Timestamp
	binary.Write(&buf, binary.BigEndian, sig.Timestamp.UnixNano())

	return buf.Bytes(), nil
}

// unmarshalSignature unmarshals a vote extension signature
func unmarshalSignature(data []byte) (*VoteExtensionSignature, error) {
	if len(data) == 0 || (len(data) == 1 && data[0] == 0) {
		return nil, nil
	}

	buf := bytes.NewReader(data)

	var sig VoteExtensionSignature

	// Version
	version, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	sig.Version = version

	// Signature
	var sigLen uint16
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return nil, err
	}
	sig.Signature = make([]byte, sigLen)
	if _, err := buf.Read(sig.Signature); err != nil {
		return nil, err
	}

	// PublicKey
	var pubKeyLen uint16
	if err := binary.Read(buf, binary.BigEndian, &pubKeyLen); err != nil {
		return nil, err
	}
	sig.PublicKey = make([]byte, pubKeyLen)
	if _, err := buf.Read(sig.PublicKey); err != nil {
		return nil, err
	}

	// KeyID
	var keyIDLen uint16
	if err := binary.Read(buf, binary.BigEndian, &keyIDLen); err != nil {
		return nil, err
	}
	keyIDBytes := make([]byte, keyIDLen)
	if _, err := buf.Read(keyIDBytes); err != nil {
		return nil, err
	}
	sig.KeyID = string(keyIDBytes)

	// Timestamp
	var tsNano int64
	if err := binary.Read(buf, binary.BigEndian, &tsNano); err != nil {
		return nil, err
	}
	sig.Timestamp = time.Unix(0, tsNano)

	return &sig, nil
}
