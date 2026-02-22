package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"cosmossdk.io/log"
)

func TestVoteExtensionSigner_SetSigningKey(t *testing.T) {
	logger := log.NewNopLogger()
	signer := NewVoteExtensionSigner(logger, "test-chain-1")

	// Generate a test key
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Set the signing key
	if err := signer.SetSigningKey(privKey); err != nil {
		t.Fatalf("SetSigningKey failed: %v", err)
	}

	// Verify key is set
	if !signer.HasSigningKey() {
		t.Error("Expected HasSigningKey to return true")
	}

	// Verify public key is available
	if len(signer.GetPublicKey()) != ed25519.PublicKeySize {
		t.Errorf("Expected public key size %d, got %d", ed25519.PublicKeySize, len(signer.GetPublicKey()))
	}

	// Verify key ID is set
	if signer.GetKeyID() == "" {
		t.Error("Expected non-empty key ID")
	}
}

func TestVoteExtensionSigner_InvalidKeySize(t *testing.T) {
	logger := log.NewNopLogger()
	signer := NewVoteExtensionSigner(logger, "test-chain-1")

	// Try to set an invalid key
	invalidKey := make([]byte, 32) // Wrong size
	err := signer.SetSigningKey(invalidKey)
	if err == nil {
		t.Error("Expected error for invalid key size")
	}
}

func TestVoteExtensionSigner_SignAndVerify(t *testing.T) {
	logger := log.NewNopLogger()
	signer := NewVoteExtensionSigner(logger, "test-chain-1")

	// Generate a test key
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if err := signer.SetSigningKey(privKey); err != nil {
		t.Fatalf("SetSigningKey failed: %v", err)
	}

	// Create a test vote extension
	ext := &VoteExtension{
		Height:           100,
		ValidatorAddress: signer.signingKey.Address,
		Timestamp:        time.Now().UTC(),
		Nonce:            make([]byte, 32),
		Verifications: []ComputeVerification{
			{
				JobID:      "job-1",
				ModelHash:  []byte("model-hash"),
				InputHash:  []byte("input-hash"),
				OutputHash: []byte("output-hash"),
				Success:    true,
			},
		},
	}
	rand.Read(ext.Nonce)

	// Sign the extension
	sig, err := signer.SignVoteExtension(ext, 100, 0)
	if err != nil {
		t.Fatalf("SignVoteExtension failed: %v", err)
	}

	// Verify the signature
	if len(sig.Signature) != ed25519.SignatureSize {
		t.Errorf("Expected signature size %d, got %d", ed25519.SignatureSize, len(sig.Signature))
	}

	// Verify using the signer
	err = signer.VerifyVoteExtensionSignature(ext, sig, 100, 0)
	if err != nil {
		t.Errorf("VerifyVoteExtensionSignature failed: %v", err)
	}
}

func TestVoteExtensionSigner_VerifyTamperedExtension(t *testing.T) {
	logger := log.NewNopLogger()
	signer := NewVoteExtensionSigner(logger, "test-chain-1")

	// Generate a test key
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if err := signer.SetSigningKey(privKey); err != nil {
		t.Fatalf("SetSigningKey failed: %v", err)
	}

	// Create and sign a vote extension
	ext := &VoteExtension{
		Height:           100,
		ValidatorAddress: signer.signingKey.Address,
		Timestamp:        time.Now().UTC(),
		Nonce:            make([]byte, 32),
		Verifications: []ComputeVerification{
			{
				JobID:      "job-1",
				ModelHash:  []byte("model-hash"),
				InputHash:  []byte("input-hash"),
				OutputHash: []byte("output-hash"),
				Success:    true,
			},
		},
	}
	rand.Read(ext.Nonce)

	sig, err := signer.SignVoteExtension(ext, 100, 0)
	if err != nil {
		t.Fatalf("SignVoteExtension failed: %v", err)
	}

	// Tamper with the extension
	ext.Verifications[0].OutputHash = []byte("tampered-output")

	// Verification should fail
	err = signer.VerifyVoteExtensionSignature(ext, sig, 100, 0)
	if err == nil {
		t.Error("Expected verification to fail for tampered extension")
	}
}

func TestVoteExtensionSigner_WrongHeight(t *testing.T) {
	logger := log.NewNopLogger()
	signer := NewVoteExtensionSigner(logger, "test-chain-1")

	// Generate a test key
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if err := signer.SetSigningKey(privKey); err != nil {
		t.Fatalf("SetSigningKey failed: %v", err)
	}

	ext := &VoteExtension{
		Height:           100,
		ValidatorAddress: signer.signingKey.Address,
		Timestamp:        time.Now().UTC(),
		Nonce:            make([]byte, 32),
	}
	rand.Read(ext.Nonce)

	// Sign at height 100
	sig, err := signer.SignVoteExtension(ext, 100, 0)
	if err != nil {
		t.Fatalf("SignVoteExtension failed: %v", err)
	}

	// Verify at height 101 (wrong height)
	err = signer.VerifyVoteExtensionSignature(ext, sig, 101, 0)
	if err == nil {
		t.Error("Expected verification to fail for wrong height")
	}
}

func TestComputeVerificationsMerkleRoot_EmptyVerifications(t *testing.T) {
	root := computeVerificationsMerkleRoot(nil)
	if root == [32]byte{} {
		t.Error("Expected non-zero root for empty verifications")
	}
}

func TestComputeVerificationsMerkleRoot_SingleVerification(t *testing.T) {
	verifications := []ComputeVerification{
		{
			JobID:      "job-1",
			ModelHash:  []byte("model"),
			InputHash:  []byte("input"),
			OutputHash: []byte("output"),
			Success:    true,
		},
	}

	root := computeVerificationsMerkleRoot(verifications)
	if root == [32]byte{} {
		t.Error("Expected non-zero root")
	}
}

func TestComputeVerificationsMerkleRoot_MultipleVerifications(t *testing.T) {
	verifications := []ComputeVerification{
		{JobID: "job-1", ModelHash: []byte("m1"), InputHash: []byte("i1"), OutputHash: []byte("o1"), Success: true},
		{JobID: "job-2", ModelHash: []byte("m2"), InputHash: []byte("i2"), OutputHash: []byte("o2"), Success: true},
		{JobID: "job-3", ModelHash: []byte("m3"), InputHash: []byte("i3"), OutputHash: []byte("o3"), Success: false},
	}

	root := computeVerificationsMerkleRoot(verifications)
	if root == [32]byte{} {
		t.Error("Expected non-zero root")
	}

	// Order matters - different order should give different root
	verifications2 := []ComputeVerification{
		{JobID: "job-2", ModelHash: []byte("m2"), InputHash: []byte("i2"), OutputHash: []byte("o2"), Success: true},
		{JobID: "job-1", ModelHash: []byte("m1"), InputHash: []byte("i1"), OutputHash: []byte("o1"), Success: true},
		{JobID: "job-3", ModelHash: []byte("m3"), InputHash: []byte("i3"), OutputHash: []byte("o3"), Success: false},
	}

	root2 := computeVerificationsMerkleRoot(verifications2)
	if root == root2 {
		t.Error("Expected different roots for different ordering")
	}
}

func TestSerializeSignatureData_Deterministic(t *testing.T) {
	data := &VoteExtensionSignatureData{
		Version:          1,
		ChainID:          "test-chain",
		Height:           100,
		Round:            0,
		ValidatorAddress: []byte("validator-addr"),
		Timestamp:        time.Unix(1000000, 0),
		ExtensionHash:    [32]byte{1, 2, 3},
		Nonce:            []byte("test-nonce"),
	}

	bytes1 := serializeSignatureData(data)
	bytes2 := serializeSignatureData(data)

	if !bytes.Equal(bytes1, bytes2) {
		t.Error("Expected serialization to be deterministic")
	}
}

func TestMarshalUnmarshalSignature(t *testing.T) {
	sig := &VoteExtensionSignature{
		Signature: make([]byte, ed25519.SignatureSize),
		PublicKey: make([]byte, ed25519.PublicKeySize),
		KeyID:     "test-key-id",
		Version:   1,
		Timestamp: time.Now().UTC().Truncate(time.Nanosecond),
	}
	rand.Read(sig.Signature)
	rand.Read(sig.PublicKey)

	// Marshal
	data, err := marshalSignature(sig)
	if err != nil {
		t.Fatalf("marshalSignature failed: %v", err)
	}

	// Unmarshal
	sig2, err := unmarshalSignature(data)
	if err != nil {
		t.Fatalf("unmarshalSignature failed: %v", err)
	}

	// Compare
	if !bytes.Equal(sig.Signature, sig2.Signature) {
		t.Error("Signature mismatch")
	}
	if !bytes.Equal(sig.PublicKey, sig2.PublicKey) {
		t.Error("PublicKey mismatch")
	}
	if sig.KeyID != sig2.KeyID {
		t.Errorf("KeyID mismatch: %s vs %s", sig.KeyID, sig2.KeyID)
	}
	if sig.Version != sig2.Version {
		t.Errorf("Version mismatch: %d vs %d", sig.Version, sig2.Version)
	}
	if !sig.Timestamp.Equal(sig2.Timestamp) {
		t.Errorf("Timestamp mismatch: %v vs %v", sig.Timestamp, sig2.Timestamp)
	}
}

func TestMarshalUnmarshalNilSignature(t *testing.T) {
	data, err := marshalSignature(nil)
	if err != nil {
		t.Fatalf("marshalSignature failed for nil: %v", err)
	}

	sig, err := unmarshalSignature(data)
	if err != nil {
		t.Fatalf("unmarshalSignature failed: %v", err)
	}

	if sig != nil {
		t.Error("Expected nil signature")
	}
}

func TestComputeKeyID(t *testing.T) {
	pubKey1 := make([]byte, ed25519.PublicKeySize)
	pubKey2 := make([]byte, ed25519.PublicKeySize)
	rand.Read(pubKey1)
	rand.Read(pubKey2)

	id1 := computeKeyID(pubKey1)
	id2 := computeKeyID(pubKey2)

	if id1 == id2 {
		t.Error("Expected different key IDs for different keys")
	}

	// Same key should give same ID
	id1Again := computeKeyID(pubKey1)
	if id1 != id1Again {
		t.Error("Expected same key ID for same key")
	}
}

func TestComputeAddress(t *testing.T) {
	pubKey := make([]byte, ed25519.PublicKeySize)
	rand.Read(pubKey)

	addr := computeAddress(pubKey)
	if len(addr) != 20 {
		t.Errorf("Expected address length 20, got %d", len(addr))
	}

	// Same key should give same address
	addr2 := computeAddress(pubKey)
	if !bytes.Equal(addr, addr2) {
		t.Error("Expected same address for same key")
	}
}

func TestVoteExtensionSigner_NoKeyConfigured(t *testing.T) {
	logger := log.NewNopLogger()
	signer := NewVoteExtensionSigner(logger, "test-chain-1")

	ext := &VoteExtension{
		Height: 100,
	}

	// Should fail without key
	_, err := signer.SignVoteExtension(ext, 100, 0)
	if err == nil {
		t.Error("Expected error when signing without key")
	}

	// HasSigningKey should return false
	if signer.HasSigningKey() {
		t.Error("Expected HasSigningKey to return false")
	}
}
