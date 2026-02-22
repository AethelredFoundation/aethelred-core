package app_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aethelred/aethelred/app"
)

// ────────────────────────────────────────────────────────────────────────────
// Test Helpers
// ────────────────────────────────────────────────────────────────────────────

func makeNonce(t *testing.T) []byte {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return nonce
}

func make32Bytes() []byte {
	h := sha256.Sum256([]byte("test-data"))
	return h[:]
}

func wrapWithPower(extensions []*app.VoteExtension, power int64) []app.VoteExtensionWithPower {
	out := make([]app.VoteExtensionWithPower, 0, len(extensions))
	for _, ext := range extensions {
		out = append(out, app.VoteExtensionWithPower{
			Extension: ext,
			Power:     power,
		})
	}
	return out
}

func makeValidTEEAttestation() *app.TEEAttestationData {
	return makeValidTEEAttestationWithUserData(make32Bytes())
}

func makeValidTEEAttestationWithUserData(userData []byte) *app.TEEAttestationData {
	nonce := bytes.Repeat([]byte{0x11}, 32)
	quote := makeValidNitroQuote(userData, nonce)
	return &app.TEEAttestationData{
		Platform:    "aws-nitro",
		EnclaveID:   "enclave-123",
		Measurement: make([]byte, 48),
		Quote:       quote,
		UserData:    userData,
		Nonce:       nonce,
		Timestamp:   time.Now().UTC(),
	}
}

type nitroQuoteTest struct {
	ModuleID    string          `json:"module_id"`
	Timestamp   int64           `json:"timestamp_unix"`
	Digest      string          `json:"digest"`
	PCRs        []nitroQuotePCR `json:"pcrs"`
	Certificate []byte          `json:"certificate,omitempty"`
	CABundle    []byte          `json:"cabundle,omitempty"`
	PublicKey   []byte          `json:"public_key,omitempty"`
	UserData    []byte          `json:"user_data,omitempty"`
	Nonce       []byte          `json:"nonce,omitempty"`
}

type nitroQuotePCR struct {
	Index int    `json:"index"`
	Value []byte `json:"value"`
}

func makeValidNitroQuote(userData, nonce []byte) []byte {
	q := nitroQuoteTest{
		ModuleID:  "enclave-123",
		Timestamp: time.Now().Unix(),
		Digest:    "SHA384",
		PCRs: []nitroQuotePCR{
			{Index: 0, Value: make32Bytes()},
		},
		UserData: userData,
		Nonce:    nonce,
	}
	b, _ := json.Marshal(q)
	return b
}

func makeValidZKProof() *app.ZKProofData {
	publicInputs := append(make([]byte, 0, 64), make32Bytes()...)
	publicInputs = append(publicInputs, make32Bytes()...)
	return &app.ZKProofData{
		ProofSystem:      "ezkl",
		Proof:            make([]byte, 256), // >= 128 bytes
		PublicInputs:     publicInputs,
		VerifyingKeyHash: make32Bytes(),
		CircuitHash:      make32Bytes(),
		ProofSize:        256,
	}
}

func makeSuccessfulVerification(t *testing.T) app.ComputeVerification {
	t.Helper()
	outputHash := make32Bytes()
	tee := makeValidTEEAttestationWithUserData(outputHash)
	return app.ComputeVerification{
		JobID:           "job-001",
		ModelHash:       make32Bytes(),
		InputHash:       make32Bytes(),
		OutputHash:      outputHash,
		AttestationType: app.AttestationTypeTEE,
		TEEAttestation:  tee,
		ExecutionTimeMs: 150,
		Success:         true,
		Nonce:           makeNonce(t),
	}
}

func makeValidVoteExtension(t *testing.T) *app.VoteExtension {
	t.Helper()
	ve := app.NewVoteExtension(100, []byte("validator-address-001"))
	ve.AddVerification(makeSuccessfulVerification(t))
	ve.ExtensionHash = ve.ComputeHash()
	return ve
}

// ────────────────────────────────────────────────────────────────────────────
// VoteExtension.Validate() — Permissive Mode
// ────────────────────────────────────────────────────────────────────────────

func TestVoteExtension_Validate_ValidExtension(t *testing.T) {
	ve := makeValidVoteExtension(t)
	if err := ve.Validate(); err != nil {
		t.Fatalf("expected valid extension, got error: %v", err)
	}
}

func TestVoteExtension_Validate_WrongVersion(t *testing.T) {
	ve := makeValidVoteExtension(t)
	ve.Version = 99
	err := ve.Validate()
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
	if !strings.Contains(err.Error(), "unsupported vote extension version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVoteExtension_Validate_ZeroHeight(t *testing.T) {
	ve := makeValidVoteExtension(t)
	ve.Height = 0
	err := ve.Validate()
	if err == nil {
		t.Fatal("expected error for zero height")
	}
	if !strings.Contains(err.Error(), "invalid height") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVoteExtension_Validate_NegativeHeight(t *testing.T) {
	ve := makeValidVoteExtension(t)
	ve.Height = -5
	err := ve.Validate()
	if err == nil {
		t.Fatal("expected error for negative height")
	}
}

func TestVoteExtension_Validate_EmptyValidatorAddress(t *testing.T) {
	ve := makeValidVoteExtension(t)
	ve.ValidatorAddress = nil
	err := ve.Validate()
	if err == nil {
		t.Fatal("expected error for empty validator address")
	}
	if !strings.Contains(err.Error(), "missing validator address") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVoteExtension_Validate_FutureTimestamp(t *testing.T) {
	ve := makeValidVoteExtension(t)
	now := time.Now().UTC()
	ve.Timestamp = now.Add(5 * time.Minute) // > 1 min tolerance
	err := ve.ValidateAtBlockTime(now)
	if err == nil {
		t.Fatal("expected error for future timestamp")
	}
	if !strings.Contains(err.Error(), "in the future") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVoteExtension_Validate_StaleTimestamp(t *testing.T) {
	ve := makeValidVoteExtension(t)
	now := time.Now().UTC()
	ve.Timestamp = now.Add(-15 * time.Minute) // > 10 min stale limit
	err := ve.ValidateAtBlockTime(now)
	if err == nil {
		t.Fatal("expected error for stale timestamp")
	}
	if !strings.Contains(err.Error(), "too old") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVoteExtension_Validate_HashTampering(t *testing.T) {
	ve := makeValidVoteExtension(t)
	ve.ExtensionHash = ve.ComputeHash()
	// Tamper with a field after hash computation
	ve.Height = 999
	err := ve.Validate()
	if err == nil {
		t.Fatal("expected error for tampered hash")
	}
	if !strings.Contains(err.Error(), "tampered") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVoteExtension_Validate_EmptyHashPermissive(t *testing.T) {
	ve := makeValidVoteExtension(t)
	ve.ExtensionHash = nil // permissive mode allows missing hash
	if err := ve.Validate(); err != nil {
		t.Fatalf("permissive mode should accept missing hash, got: %v", err)
	}
}

func TestVoteExtension_Validate_NoVerifications(t *testing.T) {
	ve := app.NewVoteExtension(100, []byte("val-addr"))
	// Extension with zero verifications should still be valid
	if err := ve.Validate(); err != nil {
		t.Fatalf("empty verification list should be valid, got: %v", err)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// VoteExtension.ValidateStrict() — Production Mode
// ────────────────────────────────────────────────────────────────────────────

func TestVoteExtension_ValidateStrict_RejectsUnsigned(t *testing.T) {
	ve := makeValidVoteExtension(t)
	ve.Signature = nil
	err := ve.ValidateStrict()
	if err == nil {
		t.Fatal("strict mode must reject unsigned extensions")
	}
	if !strings.Contains(err.Error(), "unsigned vote extensions are rejected") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVoteExtension_ValidateStrict_RejectsMissingHash(t *testing.T) {
	ve := makeValidVoteExtension(t)
	ve.ExtensionHash = nil
	ve.Signature = make([]byte, 64)
	err := ve.ValidateStrict()
	if err == nil {
		t.Fatal("strict mode must reject missing extension hash")
	}
	if !strings.Contains(err.Error(), "extension hash is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVoteExtension_ValidateStrict_RejectsInvalidSigLength(t *testing.T) {
	ve := makeValidVoteExtension(t)
	ve.Signature = make([]byte, 32) // wrong length — ed25519 needs 64
	err := ve.ValidateStrict()
	if err == nil {
		t.Fatal("strict mode must reject wrong signature length")
	}
	if !strings.Contains(err.Error(), "invalid signature length") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVoteExtension_ValidateStrict_AcceptsSignedExtension(t *testing.T) {
	ve := makeValidVoteExtension(t)
	// Generate a real ed25519 key pair and sign
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.SignVoteExtension(ve, privKey); err != nil {
		t.Fatal(err)
	}
	if err := ve.ValidateStrict(); err != nil {
		t.Fatalf("strict mode should accept properly signed extension: %v", err)
	}
}

func TestVoteExtension_ValidateStrict_RejectsSimulatedTEE(t *testing.T) {
	ve := makeValidVoteExtension(t)
	// Set TEE attestation to simulated
	ve.Verifications[0].TEEAttestation.Platform = "simulated"
	// Sign properly
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.SignVoteExtension(ve, privKey); err != nil {
		t.Fatal(err)
	}
	err = ve.ValidateStrict()
	if err == nil {
		t.Fatal("strict mode must reject simulated TEE platform")
	}
	if !strings.Contains(err.Error(), "simulated TEE platform is rejected") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// ComputeVerification.Validate()
// ────────────────────────────────────────────────────────────────────────────

func TestComputeVerification_Validate_MissingJobID(t *testing.T) {
	v := makeSuccessfulVerification(t)
	v.JobID = ""
	err := v.Validate()
	if err == nil {
		t.Fatal("expected error for missing job ID")
	}
	if !strings.Contains(err.Error(), "missing job ID") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestComputeVerification_Validate_JobIDTooLong(t *testing.T) {
	v := makeSuccessfulVerification(t)
	v.JobID = strings.Repeat("x", 300)
	err := v.Validate()
	if err == nil {
		t.Fatal("expected error for oversized job ID")
	}
	if !strings.Contains(err.Error(), "job ID too long") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestComputeVerification_Validate_MissingNonce(t *testing.T) {
	v := makeSuccessfulVerification(t)
	v.Nonce = nil
	err := v.Validate()
	if err == nil {
		t.Fatal("expected error for missing nonce")
	}
	if !strings.Contains(err.Error(), "missing nonce") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestComputeVerification_Validate_WrongNonceLength(t *testing.T) {
	v := makeSuccessfulVerification(t)
	v.Nonce = make([]byte, 16) // must be 32
	err := v.Validate()
	if err == nil {
		t.Fatal("expected error for wrong nonce length")
	}
	if !strings.Contains(err.Error(), "nonce must be exactly 32 bytes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestComputeVerification_Validate_MissingModelHash(t *testing.T) {
	v := makeSuccessfulVerification(t)
	v.ModelHash = nil
	err := v.Validate()
	if err == nil {
		t.Fatal("expected error for missing model hash")
	}
}

func TestComputeVerification_Validate_WrongModelHashLength(t *testing.T) {
	v := makeSuccessfulVerification(t)
	v.ModelHash = make([]byte, 20) // must be 32
	err := v.Validate()
	if err == nil {
		t.Fatal("expected error for wrong model hash length")
	}
	if !strings.Contains(err.Error(), "model hash must be 32 bytes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestComputeVerification_Validate_SuccessfulWithoutOutputHash(t *testing.T) {
	v := makeSuccessfulVerification(t)
	v.OutputHash = nil
	err := v.Validate()
	if err == nil {
		t.Fatal("expected error for successful verification without output hash")
	}
	if !strings.Contains(err.Error(), "32-byte output hash") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestComputeVerification_Validate_SuccessfulWithZeroExecTime(t *testing.T) {
	v := makeSuccessfulVerification(t)
	v.ExecutionTimeMs = 0
	err := v.Validate()
	if err == nil {
		t.Fatal("expected error for zero execution time on success")
	}
	if !strings.Contains(err.Error(), "positive execution time") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestComputeVerification_Validate_SuccessfulWithNegativeExecTime(t *testing.T) {
	v := makeSuccessfulVerification(t)
	v.ExecutionTimeMs = -100
	err := v.Validate()
	if err == nil {
		t.Fatal("expected error for negative execution time")
	}
}

func TestComputeVerification_Validate_UnknownAttestationType(t *testing.T) {
	v := makeSuccessfulVerification(t)
	v.AttestationType = "quantum"
	err := v.Validate()
	if err == nil {
		t.Fatal("expected error for unknown attestation type")
	}
	if !strings.Contains(err.Error(), "unknown attestation type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestComputeVerification_Validate_TEE_MissingAttestationData(t *testing.T) {
	v := makeSuccessfulVerification(t)
	v.AttestationType = app.AttestationTypeTEE
	v.TEEAttestation = nil
	err := v.Validate()
	if err == nil {
		t.Fatal("expected error for TEE type with no attestation data")
	}
	if !strings.Contains(err.Error(), "requires TEE attestation data") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestComputeVerification_Validate_ZKML_MissingProofData(t *testing.T) {
	v := makeSuccessfulVerification(t)
	v.AttestationType = app.AttestationTypeZKML
	v.TEEAttestation = nil
	v.ZKProof = nil
	err := v.Validate()
	if err == nil {
		t.Fatal("expected error for zkML type with no proof data")
	}
	if !strings.Contains(err.Error(), "requires ZK proof data") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestComputeVerification_Validate_Hybrid_MissingBoth(t *testing.T) {
	v := makeSuccessfulVerification(t)
	v.AttestationType = app.AttestationTypeHybrid
	v.TEEAttestation = nil
	v.ZKProof = nil
	err := v.Validate()
	if err == nil {
		t.Fatal("expected error for hybrid type with missing data")
	}
	if !strings.Contains(err.Error(), "requires both TEE and zkML") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestComputeVerification_Validate_Hybrid_MissingZKProof(t *testing.T) {
	v := makeSuccessfulVerification(t)
	v.AttestationType = app.AttestationTypeHybrid
	v.ZKProof = nil
	err := v.Validate()
	if err == nil {
		t.Fatal("expected error for hybrid type with missing ZK proof")
	}
}

func TestComputeVerification_Validate_None_SuccessRejected(t *testing.T) {
	v := makeSuccessfulVerification(t)
	v.AttestationType = app.AttestationTypeNone
	err := v.Validate()
	if err == nil {
		t.Fatal("expected error: successful verification cannot have no attestation")
	}
	if !strings.Contains(err.Error(), "cannot have no attestation") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestComputeVerification_Validate_None_FailureAccepted(t *testing.T) {
	v := app.ComputeVerification{
		JobID:           "job-fail",
		ModelHash:       make32Bytes(),
		Nonce:           make([]byte, 32),
		AttestationType: app.AttestationTypeNone,
		Success:         false,
		ErrorCode:       app.ErrorCodeTEEFailure,
		ErrorMessage:    "enclave unavailable",
	}
	if err := v.Validate(); err != nil {
		t.Fatalf("failed verification with none attestation should be valid: %v", err)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// TEEAttestationData.Validate()
// ────────────────────────────────────────────────────────────────────────────

func TestTEEAttestation_Validate_Valid(t *testing.T) {
	ta := makeValidTEEAttestation()
	if err := ta.Validate(); err != nil {
		t.Fatalf("expected valid attestation, got: %v", err)
	}
}

func TestTEEAttestation_Validate_EmptyPlatform(t *testing.T) {
	ta := makeValidTEEAttestation()
	ta.Platform = ""
	err := ta.Validate()
	if err == nil {
		t.Fatal("expected error for empty platform")
	}
}

func TestTEEAttestation_Validate_UnknownPlatform(t *testing.T) {
	ta := makeValidTEEAttestation()
	ta.Platform = "google-cc"
	err := ta.Validate()
	if err == nil {
		t.Fatal("expected error for unknown platform")
	}
	if !strings.Contains(err.Error(), "unknown TEE platform") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTEEAttestation_Validate_SimulatedPermissive(t *testing.T) {
	ta := makeValidTEEAttestation()
	ta.Platform = "simulated"
	// Permissive mode should accept simulated
	if err := ta.Validate(); err != nil {
		t.Fatalf("permissive mode should accept simulated, got: %v", err)
	}
}

func TestTEEAttestation_Validate_MissingMeasurement(t *testing.T) {
	ta := makeValidTEEAttestation()
	ta.Measurement = nil
	err := ta.Validate()
	if err == nil {
		t.Fatal("expected error for missing measurement")
	}
}

func TestTEEAttestation_Validate_EmptyQuote(t *testing.T) {
	ta := makeValidTEEAttestation()
	ta.Quote = nil
	err := ta.Validate()
	if err == nil {
		t.Fatal("expected error for empty quote")
	}
}

func TestTEEAttestation_Validate_QuoteTooShort(t *testing.T) {
	ta := makeValidTEEAttestation()
	ta.Quote = make([]byte, 32) // minimum 64
	err := ta.Validate()
	if err == nil {
		t.Fatal("expected error for short quote")
	}
	if !strings.Contains(err.Error(), "quote too short") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTEEAttestation_Validate_MissingNonce(t *testing.T) {
	ta := makeValidTEEAttestation()
	ta.Nonce = nil
	err := ta.Validate()
	if err == nil {
		t.Fatal("expected error for missing nonce")
	}
}

func TestTEEAttestation_Validate_MissingUserData(t *testing.T) {
	ta := makeValidTEEAttestation()
	ta.UserData = nil
	err := ta.Validate()
	if err == nil {
		t.Fatal("expected error for missing user data")
	}
}

func TestTEEAttestation_Validate_ZeroTimestamp(t *testing.T) {
	ta := makeValidTEEAttestation()
	ta.Timestamp = time.Time{}
	err := ta.Validate()
	if err == nil {
		t.Fatal("expected error for zero timestamp")
	}
}

func TestTEEAttestation_AllPlatforms(t *testing.T) {
	platforms := []string{"aws-nitro", "intel-sgx", "intel-tdx", "amd-sev", "arm-trustzone", "simulated"}
	for _, p := range platforms {
		t.Run(p, func(t *testing.T) {
			ta := makeValidTEEAttestation()
			ta.Platform = p
			if err := ta.Validate(); err != nil {
				t.Fatalf("platform %s should be valid in permissive mode: %v", p, err)
			}
		})
	}
}

// ────────────────────────────────────────────────────────────────────────────
// ZKProofData.Validate()
// ────────────────────────────────────────────────────────────────────────────

func TestZKProof_Validate_Valid(t *testing.T) {
	zp := makeValidZKProof()
	if err := zp.Validate(); err != nil {
		t.Fatalf("expected valid proof, got: %v", err)
	}
}

func TestZKProof_Validate_EmptyProofSystem(t *testing.T) {
	zp := makeValidZKProof()
	zp.ProofSystem = ""
	if err := zp.Validate(); err == nil {
		t.Fatal("expected error for empty proof system")
	}
}

func TestZKProof_Validate_UnknownProofSystem(t *testing.T) {
	zp := makeValidZKProof()
	zp.ProofSystem = "groth16"
	err := zp.Validate()
	if err == nil {
		t.Fatal("expected error for unknown proof system")
	}
	if !strings.Contains(err.Error(), "unknown proof system") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestZKProof_Validate_AllProofSystems(t *testing.T) {
	systems := []string{"ezkl", "risc0", "plonky2", "halo2"}
	for _, s := range systems {
		t.Run(s, func(t *testing.T) {
			zp := makeValidZKProof()
			zp.ProofSystem = s
			if err := zp.Validate(); err != nil {
				t.Fatalf("system %s should be valid: %v", s, err)
			}
		})
	}
}

func TestZKProof_Validate_EmptyProof(t *testing.T) {
	zp := makeValidZKProof()
	zp.Proof = nil
	if err := zp.Validate(); err == nil {
		t.Fatal("expected error for empty proof")
	}
}

func TestZKProof_Validate_ProofTooShort(t *testing.T) {
	zp := makeValidZKProof()
	zp.Proof = make([]byte, 64) // minimum 128
	err := zp.Validate()
	if err == nil {
		t.Fatal("expected error for short proof")
	}
	if !strings.Contains(err.Error(), "proof data too short") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestZKProof_Validate_WrongVKHashLength(t *testing.T) {
	zp := makeValidZKProof()
	zp.VerifyingKeyHash = make([]byte, 20) // must be 32
	err := zp.Validate()
	if err == nil {
		t.Fatal("expected error for wrong VK hash length")
	}
	if !strings.Contains(err.Error(), "verifying key hash must be 32 bytes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestZKProof_Validate_WrongCircuitHashLength(t *testing.T) {
	zp := makeValidZKProof()
	zp.CircuitHash = make([]byte, 16) // if provided, must be 32
	err := zp.Validate()
	if err == nil {
		t.Fatal("expected error for wrong circuit hash length")
	}
	if !strings.Contains(err.Error(), "circuit hash must be 32 bytes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestZKProof_Validate_EmptyCircuitHash(t *testing.T) {
	zp := makeValidZKProof()
	zp.CircuitHash = nil // nil is acceptable
	if err := zp.Validate(); err != nil {
		t.Fatalf("nil circuit hash should be valid: %v", err)
	}
}

func TestZKProof_Validate_MissingPublicInputs(t *testing.T) {
	zp := makeValidZKProof()
	zp.PublicInputs = nil
	err := zp.Validate()
	if err == nil {
		t.Fatal("expected error for missing public inputs")
	}
	if !strings.Contains(err.Error(), "missing public inputs") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Signing and Signature Verification
// ────────────────────────────────────────────────────────────────────────────

func TestSignAndVerify_RoundTrip(t *testing.T) {
	ve := makeValidVoteExtension(t)
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if err := app.SignVoteExtension(ve, privKey); err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	if len(ve.Signature) != ed25519.SignatureSize {
		t.Fatalf("expected %d byte signature, got %d", ed25519.SignatureSize, len(ve.Signature))
	}

	if !app.VerifyVoteExtensionSignature(ve, pubKey) {
		t.Fatal("signature verification failed")
	}
}

func TestVerify_EmptySignature(t *testing.T) {
	ve := makeValidVoteExtension(t)
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	ve.Signature = nil
	if app.VerifyVoteExtensionSignature(ve, pubKey) {
		t.Fatal("should reject empty signature")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	ve := makeValidVoteExtension(t)
	_, privKey1, _ := ed25519.GenerateKey(rand.Reader)
	pubKey2, _, _ := ed25519.GenerateKey(rand.Reader)

	if err := app.SignVoteExtension(ve, privKey1); err != nil {
		t.Fatal(err)
	}
	if app.VerifyVoteExtensionSignature(ve, pubKey2) {
		t.Fatal("should reject wrong public key")
	}
}

func TestVerify_TamperedData(t *testing.T) {
	ve := makeValidVoteExtension(t)
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)

	if err := app.SignVoteExtension(ve, privKey); err != nil {
		t.Fatal(err)
	}

	// Tamper with data after signing
	ve.Height = 999
	if app.VerifyVoteExtensionSignature(ve, pubKey) {
		t.Fatal("should reject tampered data")
	}
}

func TestVerify_WrongSignatureLength(t *testing.T) {
	ve := makeValidVoteExtension(t)
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	ve.Signature = make([]byte, 32) // wrong length
	if app.VerifyVoteExtensionSignature(ve, pubKey) {
		t.Fatal("should reject wrong signature length")
	}
}

func TestVerify_WrongPubKeyLength(t *testing.T) {
	ve := makeValidVoteExtension(t)
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	if err := app.SignVoteExtension(ve, privKey); err != nil {
		t.Fatal(err)
	}
	shortPubKey := make([]byte, 16) // too short
	if app.VerifyVoteExtensionSignature(ve, shortPubKey) {
		t.Fatal("should reject wrong public key length")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Marshal / Unmarshal
// ────────────────────────────────────────────────────────────────────────────

func TestMarshalUnmarshal_RoundTrip(t *testing.T) {
	ve := makeValidVoteExtension(t)
	data, err := ve.Marshal()
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	ve2, err := app.UnmarshalVoteExtension(data)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if ve2.Version != ve.Version {
		t.Fatal("version mismatch")
	}
	if ve2.Height != ve.Height {
		t.Fatal("height mismatch")
	}
	if len(ve2.Verifications) != len(ve.Verifications) {
		t.Fatal("verification count mismatch")
	}
}

func TestUnmarshal_EmptyData(t *testing.T) {
	_, err := app.UnmarshalVoteExtension(nil)
	if err == nil {
		t.Fatal("expected error for nil data")
	}
	if !strings.Contains(err.Error(), "empty vote extension data") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUnmarshal_InvalidJSON(t *testing.T) {
	_, err := app.UnmarshalVoteExtension([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestUnmarshal_EmptyObject(t *testing.T) {
	_, err := app.UnmarshalVoteExtension([]byte("{}"))
	if err != nil {
		t.Fatalf("empty object should unmarshal (validation is separate): %v", err)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// ComputeHash determinism
// ────────────────────────────────────────────────────────────────────────────

func TestComputeHash_Deterministic(t *testing.T) {
	ve := makeValidVoteExtension(t)
	h1 := ve.ComputeHash()
	h2 := ve.ComputeHash()
	if len(h1) != 32 {
		t.Fatalf("expected 32-byte hash, got %d", len(h1))
	}
	for i := range h1 {
		if h1[i] != h2[i] {
			t.Fatal("hash is not deterministic")
		}
	}
}

func TestComputeHash_DifferentForDifferentData(t *testing.T) {
	ve1 := makeValidVoteExtension(t)
	ve2 := makeValidVoteExtension(t)
	ve2.Height = 200

	h1 := ve1.ComputeHash()
	h2 := ve2.ComputeHash()
	if string(h1) == string(h2) {
		t.Fatal("different extensions should produce different hashes")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// AggregateVoteExtensions
// ────────────────────────────────────────────────────────────────────────────

func TestAggregate_NoExtensions(t *testing.T) {
	ctx := testCtx(t)
	result := app.AggregateVoteExtensions(ctx, nil, 67, true)
	if len(result) != 0 {
		t.Fatal("expected empty result")
	}
}

func TestAggregate_ConsensusReached(t *testing.T) {
	ctx := testCtx(t)
	outputHash := make32Bytes()

	var extensions []*app.VoteExtension
	for i := 0; i < 3; i++ {
		ve := app.NewVoteExtension(100, []byte("validator"))
		tee := makeValidTEEAttestationWithUserData(outputHash)
		v := app.ComputeVerification{
			JobID:           "job-consensus",
			ModelHash:       make32Bytes(),
			InputHash:       make32Bytes(),
			OutputHash:      outputHash,
			AttestationType: app.AttestationTypeTEE,
			TEEAttestation:  tee,
			ExecutionTimeMs: 100,
			Success:         true,
			Nonce:           make([]byte, 32),
		}
		ve.AddVerification(v)
		extensions = append(extensions, ve)
	}

	result := app.AggregateVoteExtensions(ctx, wrapWithPower(extensions, 1), 67, true)
	agg, ok := result["job-consensus"]
	if !ok {
		t.Fatal("expected result for job-consensus")
	}
	if !agg.HasConsensus {
		t.Fatal("expected consensus to be reached with 3/3 validators")
	}
	if agg.ValidatorCount != 3 {
		t.Fatalf("expected 3 validators, got %d", agg.ValidatorCount)
	}
}

func TestAggregate_ConsensusTimestampUsesBlockTime(t *testing.T) {
	blockTime := time.Unix(1_700_000_000, 0).UTC()
	ctx := testCtx(t).WithBlockTime(blockTime)
	outputHash := make32Bytes()

	ve := app.NewVoteExtension(100, []byte("validator"))
	tee := makeValidTEEAttestationWithUserData(outputHash)
	ve.AddVerification(app.ComputeVerification{
		JobID:           "job-time",
		ModelHash:       make32Bytes(),
		InputHash:       make32Bytes(),
		OutputHash:      outputHash,
		AttestationType: app.AttestationTypeTEE,
		TEEAttestation:  tee,
		ExecutionTimeMs: 10,
		Success:         true,
		Nonce:           make([]byte, 32),
	})

	result := app.AggregateVoteExtensions(ctx, wrapWithPower([]*app.VoteExtension{ve}, 10), 67, true)
	agg, ok := result["job-time"]
	if !ok {
		t.Fatal("expected result for job-time")
	}
	if !agg.ConsensusReached.Equal(blockTime) {
		t.Fatalf("expected deterministic block time %s, got %s", blockTime, agg.ConsensusReached)
	}
}

func TestAggregate_NoConsensus_Disagreement(t *testing.T) {
	ctx := testCtx(t)

	var extensions []*app.VoteExtension
	// 3 validators, each with different output
	for i := 0; i < 3; i++ {
		ve := app.NewVoteExtension(100, []byte("validator"))
		outputHash := sha256.Sum256([]byte{byte(i)}) // different outputs
		tee := makeValidTEEAttestationWithUserData(outputHash[:])
		v := app.ComputeVerification{
			JobID:           "job-disagree",
			ModelHash:       make32Bytes(),
			InputHash:       make32Bytes(),
			OutputHash:      outputHash[:],
			AttestationType: app.AttestationTypeTEE,
			TEEAttestation:  tee,
			ExecutionTimeMs: 100,
			Success:         true,
			Nonce:           make([]byte, 32),
		}
		ve.AddVerification(v)
		extensions = append(extensions, ve)
	}

	result := app.AggregateVoteExtensions(ctx, wrapWithPower(extensions, 1), 67, true)
	agg, ok := result["job-disagree"]
	if !ok {
		t.Fatal("expected result for job-disagree")
	}
	if agg.HasConsensus {
		t.Fatal("should NOT reach consensus with all different outputs")
	}
}

func TestAggregate_SkipsFailedVerifications(t *testing.T) {
	ctx := testCtx(t)

	var extensions []*app.VoteExtension
	for i := 0; i < 3; i++ {
		ve := app.NewVoteExtension(100, []byte("validator"))
		v := app.ComputeVerification{
			JobID:           "job-fail",
			ModelHash:       make32Bytes(),
			AttestationType: app.AttestationTypeNone,
			Success:         false,
			ErrorMessage:    "enclave failure",
			Nonce:           make([]byte, 32),
		}
		ve.AddVerification(v)
		extensions = append(extensions, ve)
	}

	result := app.AggregateVoteExtensions(ctx, wrapWithPower(extensions, 1), 67, true)
	// Failed verifications should not create aggregated results
	if _, ok := result["job-fail"]; ok {
		t.Fatal("failed verifications should not produce aggregated results")
	}
}

func TestAggregate_SkipsNilExtensions(t *testing.T) {
	ctx := testCtx(t)
	extensions := []*app.VoteExtension{nil, nil, nil}
	result := app.AggregateVoteExtensions(ctx, wrapWithPower(extensions, 1), 67, true)
	if len(result) != 0 {
		t.Fatal("nil extensions should be skipped")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// InjectedVoteExtensionTx
// ────────────────────────────────────────────────────────────────────────────

func TestInjectedTx_MarshalUnmarshal(t *testing.T) {
	agg := &app.AggregatedVerification{
		JobID:          "job-seal",
		OutputHash:     make32Bytes(),
		ValidatorCount: 3,
		TotalVotes:     4,
		AgreementPower: 3,
		TotalPower:     4,
		HasConsensus:   true,
	}
	tx := app.NewInjectedVoteExtensionTx(agg, 100)
	data, err := tx.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	tx2, err := app.UnmarshalInjectedVoteExtensionTx(data)
	if err != nil {
		t.Fatal(err)
	}
	if tx2.JobID != "job-seal" {
		t.Fatalf("expected job-seal, got %s", tx2.JobID)
	}
	if tx2.Type != "create_seal_from_consensus" {
		t.Fatalf("expected create_seal_from_consensus type, got %s", tx2.Type)
	}
}

func TestIsInjectedVoteExtensionTx_Valid(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{
		"type":   "create_seal_from_consensus",
		"job_id": "test",
	})
	if !app.IsInjectedVoteExtensionTx(data) {
		t.Fatal("should detect valid injected tx")
	}
}

func TestIsInjectedVoteExtensionTx_WrongType(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{
		"type":   "something_else",
		"job_id": "test",
	})
	if app.IsInjectedVoteExtensionTx(data) {
		t.Fatal("should reject wrong type")
	}
}

func TestIsInjectedVoteExtensionTx_InvalidJSON(t *testing.T) {
	if app.IsInjectedVoteExtensionTx([]byte("not json")) {
		t.Fatal("should reject invalid JSON")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Edge cases and security scenarios
// ────────────────────────────────────────────────────────────────────────────

func TestVoteExtension_MaxVerifications(t *testing.T) {
	ve := app.NewVoteExtension(100, []byte("val"))
	// Add many verifications — should not panic
	for i := 0; i < app.MaxVerificationsPerExtension; i++ {
		v := app.ComputeVerification{
			JobID:           "job-bulk",
			ModelHash:       make32Bytes(),
			Nonce:           make([]byte, 32),
			AttestationType: app.AttestationTypeNone,
			Success:         false,
		}
		ve.AddVerification(v)
	}
	if len(ve.Verifications) != app.MaxVerificationsPerExtension {
		t.Fatalf("expected %d verifications, got %d", app.MaxVerificationsPerExtension, len(ve.Verifications))
	}
}

func TestVoteExtension_SortVerificationsByJobID(t *testing.T) {
	verifications := []app.ComputeVerification{
		{JobID: "charlie"},
		{JobID: "alpha"},
		{JobID: "bravo"},
	}
	app.SortVerificationsByJobID(verifications)
	if verifications[0].JobID != "alpha" {
		t.Fatal("expected alpha first")
	}
	if verifications[1].JobID != "bravo" {
		t.Fatal("expected bravo second")
	}
	if verifications[2].JobID != "charlie" {
		t.Fatal("expected charlie third")
	}
}

func TestVoteExtension_ValidateStrict_HybridWithSimulatedTEE(t *testing.T) {
	ve := makeValidVoteExtension(t)
	ve.Verifications[0].AttestationType = app.AttestationTypeHybrid
	ve.Verifications[0].ZKProof = makeValidZKProof()
	ve.Verifications[0].TEEAttestation.Platform = "simulated"
	// Sign properly
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	if err := app.SignVoteExtension(ve, privKey); err != nil {
		t.Fatal(err)
	}
	err := ve.ValidateStrict()
	if err == nil {
		t.Fatal("strict mode must reject simulated TEE even in hybrid mode")
	}
	if !strings.Contains(err.Error(), "simulated TEE platform is rejected") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVoteExtension_ZKML_ValidInStrict(t *testing.T) {
	ve := app.NewVoteExtension(100, []byte("validator-addr"))
	outputHash := make32Bytes()
	v := app.ComputeVerification{
		JobID:           "job-zkml",
		ModelHash:       make32Bytes(),
		InputHash:       make32Bytes(),
		OutputHash:      outputHash,
		AttestationType: app.AttestationTypeZKML,
		ZKProof:         makeValidZKProof(),
		ExecutionTimeMs: 200,
		Success:         true,
		Nonce:           make([]byte, 32),
	}
	ve.AddVerification(v)
	ve.ExtensionHash = ve.ComputeHash()

	// Sign
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	if err := app.SignVoteExtension(ve, privKey); err != nil {
		t.Fatal(err)
	}
	// zkML should be accepted in strict mode (no simulated TEE issue)
	if err := ve.ValidateStrict(); err != nil {
		t.Fatalf("zkML should be valid in strict mode: %v", err)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Policy tests
// ────────────────────────────────────────────────────────────────────────────

// Policy: VoteExtensionVersion must be exactly 1 for the MVP.
func TestPolicy_VoteExtensionVersion(t *testing.T) {
	if app.VoteExtensionVersion != 1 {
		t.Fatalf("POLICY: VoteExtensionVersion must be 1 for MVP, got %d", app.VoteExtensionVersion)
	}
}

// Policy: Nonce must be exactly 32 bytes for replay protection.
func TestPolicy_NonceMustBe32Bytes(t *testing.T) {
	for _, size := range []int{0, 1, 16, 31, 33, 64} {
		v := makeSuccessfulVerification(t)
		v.Nonce = make([]byte, size)
		err := v.Validate()
		if err == nil {
			t.Fatalf("nonce of size %d should be rejected", size)
		}
	}
	// Exactly 32 should pass
	v := makeSuccessfulVerification(t)
	v.Nonce = make([]byte, 32)
	if err := v.Validate(); err != nil {
		t.Fatalf("nonce of size 32 should be accepted: %v", err)
	}
}

// Policy: In strict mode, ALL of these must cause rejection.
func TestPolicy_StrictMode_RequiredRejections(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*app.VoteExtension)
	}{
		{"unsigned", func(ve *app.VoteExtension) { ve.Signature = nil }},
		{"short_sig", func(ve *app.VoteExtension) { ve.Signature = make([]byte, 32) }},
		{"no_hash", func(ve *app.VoteExtension) {
			ve.ExtensionHash = nil
			ve.Signature = make([]byte, 64)
		}},
		{"simulated_tee", func(ve *app.VoteExtension) {
			ve.Verifications[0].TEEAttestation.Platform = "simulated"
			_, privKey, _ := ed25519.GenerateKey(rand.Reader)
			app.SignVoteExtension(ve, privKey)
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ve := makeValidVoteExtension(t)
			tc.modify(ve)
			if err := ve.ValidateStrict(); err == nil {
				t.Fatalf("POLICY VIOLATION: strict mode must reject %s", tc.name)
			}
		})
	}
}
