package keeper_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"cosmossdk.io/log"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// =============================================================================
// NEGATIVE-CASE TESTS: Vote Extension Validation
//
// These tests verify that malformed, incomplete, or malicious vote extensions
// are correctly rejected by the consensus handler validation pipeline.
// Each test targets a specific field or invariant from VERIFICATION_POLICY.md.
// =============================================================================

// ---------------------------------------------------------------------------
// Section 1: VoteExtensionWire structural validation
// ---------------------------------------------------------------------------

func TestNegative_VoteExtension_EmptyJobID(t *testing.T) {
	v := validSuccessfulVerification()
	v.JobID = ""

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "missing job ID")
}

func TestNegative_VoteExtension_OutputHashWrongSize(t *testing.T) {
	v := validSuccessfulVerification()
	v.OutputHash = randomBytes(16) // should be 32

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "32-byte output hash")
}

func TestNegative_VoteExtension_ModelHashWrongSize(t *testing.T) {
	v := validSuccessfulVerification()
	v.ModelHash = randomBytes(20) // should be 32

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "32-byte model hash")
}

func TestNegative_VoteExtension_MissingNonce(t *testing.T) {
	v := validSuccessfulVerification()
	v.Nonce = nil

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "nonce")
}

func TestNegative_VoteExtension_NonceWrongSize(t *testing.T) {
	v := validSuccessfulVerification()
	v.Nonce = randomBytes(16) // should be 32

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "nonce must be 32 bytes")
}

func TestNegative_VoteExtension_ZeroExecutionTime(t *testing.T) {
	v := validSuccessfulVerification()
	v.ExecutionTimeMs = 0

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "execution time must be positive")
}

func TestNegative_VoteExtension_NegativeExecutionTime(t *testing.T) {
	v := validSuccessfulVerification()
	v.ExecutionTimeMs = -50

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "execution time must be positive")
}

func TestNegative_VoteExtension_UnknownAttestationType(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "quantum"

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "unknown attestation type")
}

// ---------------------------------------------------------------------------
// Section 2: TEE Attestation Wire structural validation
// ---------------------------------------------------------------------------

func TestNegative_TEE_MissingAttestationData(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "tee"
	v.TEEAttestation = nil

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "missing TEE attestation data")
}

func TestNegative_TEE_MalformedJSON(t *testing.T) {
	// We can't use json.Marshal with invalid JSON inside RawMessage, so
	// construct the raw extension bytes directly with malformed attestation.
	v := validSuccessfulVerification()
	v.AttestationType = "tee"
	// Use a valid JSON string that is NOT a valid TEE attestation object
	v.TEEAttestation = json.RawMessage([]byte(`"not-an-object"`))

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "failed to parse TEE attestation")
}

func TestNegative_TEE_UnknownPlatform(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "tee"
	v.TEEAttestation = makeTEEAttestation(func(a *teeAttestationBuilder) {
		a.Platform = "google-enclave"
	}, v.OutputHash)

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "unknown TEE platform")
}

func TestNegative_TEE_EmptyPlatform(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "tee"
	v.TEEAttestation = makeTEEAttestation(func(a *teeAttestationBuilder) {
		a.Platform = ""
	}, v.OutputHash)

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "unknown TEE platform")
}

func TestNegative_TEE_MissingMeasurement(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "tee"
	v.TEEAttestation = makeTEEAttestation(func(a *teeAttestationBuilder) {
		a.Measurement = nil
	}, v.OutputHash)

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "missing enclave measurement")
}

func TestNegative_TEE_QuoteTooShort(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "tee"
	v.TEEAttestation = makeTEEAttestation(func(a *teeAttestationBuilder) {
		a.Quote = randomBytes(32) // minimum is 64
	}, v.OutputHash)

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "attestation quote too short")
}

func TestNegative_TEE_EmptyQuote(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "tee"
	v.TEEAttestation = makeTEEAttestation(func(a *teeAttestationBuilder) {
		a.Quote = nil
	}, v.OutputHash)

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "attestation quote too short")
}

func TestNegative_TEE_MissingUserDataBinding(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "tee"
	v.TEEAttestation = makeTEEAttestation(func(a *teeAttestationBuilder) {
		a.UserData = nil
	}, v.OutputHash)

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "missing user data binding")
}

func TestNegative_TEE_UserDataMismatchOutputHash(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "tee"
	v.TEEAttestation = makeTEEAttestation(func(a *teeAttestationBuilder) {
		a.UserData = randomBytes(32) // doesn't match v.OutputHash
	}, v.OutputHash)

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "user data does not match output hash")
}

func TestNegative_TEE_MissingNonce(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "tee"
	v.TEEAttestation = makeTEEAttestation(func(a *teeAttestationBuilder) {
		a.Nonce = nil
	}, v.OutputHash)

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "missing nonce")
}

func TestNegative_TEE_ZeroTimestamp(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "tee"
	v.TEEAttestation = makeTEEAttestation(func(a *teeAttestationBuilder) {
		a.Timestamp = time.Time{}
	}, v.OutputHash)

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "missing timestamp")
}

func TestNegative_TEE_StaleTimestamp(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "tee"
	v.TEEAttestation = makeTEEAttestation(func(a *teeAttestationBuilder) {
		a.Timestamp = time.Now().Add(-15 * time.Minute) // >10 minute threshold
	}, v.OutputHash)

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "stale")
}

// ---------------------------------------------------------------------------
// Section 3: ZK Proof Wire structural validation
// ---------------------------------------------------------------------------

func TestNegative_ZK_MissingProofData(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "zkml"
	v.TEEAttestation = nil
	v.ZKProof = nil

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "missing zkML proof data")
}

func TestNegative_ZK_MalformedJSON(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "zkml"
	v.TEEAttestation = nil
	// Use a valid JSON string that is NOT a valid ZK proof object
	v.ZKProof = json.RawMessage([]byte(`"not-an-object"`))

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "failed to parse zkML proof")
}

func TestNegative_ZK_UnknownProofSystem(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "zkml"
	v.TEEAttestation = nil
	v.ZKProof = makeZKProof(func(p *zkProofBuilder) {
		p.ProofSystem = "nova"
	})

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "unknown proof system")
}

func TestNegative_ZK_EmptyProofSystem(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "zkml"
	v.TEEAttestation = nil
	v.ZKProof = makeZKProof(func(p *zkProofBuilder) {
		p.ProofSystem = ""
	})

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "unknown proof system")
}

func TestNegative_ZK_ProofTooShort(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "zkml"
	v.TEEAttestation = nil
	v.ZKProof = makeZKProof(func(p *zkProofBuilder) {
		p.Proof = randomBytes(64) // minimum is 128
	})

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "proof data too short")
}

func TestNegative_ZK_EmptyProof(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "zkml"
	v.TEEAttestation = nil
	v.ZKProof = makeZKProof(func(p *zkProofBuilder) {
		p.Proof = nil
	})

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "proof data too short")
}

func TestNegative_ZK_VKHashWrongSize(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "zkml"
	v.TEEAttestation = nil
	v.ZKProof = makeZKProof(func(p *zkProofBuilder) {
		p.VerifyingKeyHash = randomBytes(16) // should be 32
	})

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "verifying key hash must be 32 bytes")
}

func TestNegative_ZK_MissingPublicInputs(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "zkml"
	v.TEEAttestation = nil
	v.ZKProof = makeZKProof(func(p *zkProofBuilder) {
		p.PublicInputs = nil
	})

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "missing public inputs")
}

// ---------------------------------------------------------------------------
// Section 4: Hybrid verification (TEE + ZK both required)
// ---------------------------------------------------------------------------

func TestNegative_Hybrid_MissingTEEPart(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "hybrid"
	v.TEEAttestation = nil
	v.ZKProof = makeZKProof(nil)

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "hybrid TEE part invalid")
}

func TestNegative_Hybrid_MissingZKPart(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "hybrid"
	// TEEAttestation is valid from validSuccessfulVerification()
	v.ZKProof = nil

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "hybrid zkML part invalid")
}

func TestNegative_Hybrid_InvalidTEEPlatform(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "hybrid"
	v.TEEAttestation = makeTEEAttestation(func(a *teeAttestationBuilder) {
		a.Platform = "fictional-tee"
	}, v.OutputHash)
	v.ZKProof = makeZKProof(nil)

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "hybrid TEE part invalid")
}

func TestNegative_Hybrid_InvalidZKSystem(t *testing.T) {
	v := validSuccessfulVerification()
	v.AttestationType = "hybrid"
	// TEEAttestation is valid from validSuccessfulVerification()
	v.ZKProof = makeZKProof(func(p *zkProofBuilder) {
		p.ProofSystem = "starks-v999"
	})

	err := validateVerificationWireViaExtension(t, v)
	assertErrorContains(t, err, "hybrid zkML part invalid")
}

// ---------------------------------------------------------------------------
// Section 5: Extension-level validation
// ---------------------------------------------------------------------------

func TestNegative_Extension_WrongVersion(t *testing.T) {
	ext := validExtension()
	ext.Version = 2

	data, _ := json.Marshal(ext)
	err := unmarshalAndValidateExtension(data)
	assertErrorContains(t, err, "unsupported vote extension version")
}

func TestNegative_Extension_FutureTimestamp(t *testing.T) {
	ext := validExtension()
	ext.Timestamp = time.Now().Add(5 * time.Minute) // >1min in the future

	data, _ := json.Marshal(ext)
	err := unmarshalAndValidateExtension(data)
	assertErrorContains(t, err, "timestamp is in the future")
}

func TestNegative_Extension_MalformedJSON(t *testing.T) {
	err := unmarshalAndValidateExtension([]byte(`{broken`))
	assertErrorContains(t, err, "failed to unmarshal")
}

func TestNegative_Extension_EmptyBytes(t *testing.T) {
	err := unmarshalAndValidateExtension([]byte{})
	assertErrorContains(t, err, "failed to unmarshal")
}

// ---------------------------------------------------------------------------
// Section 6: Failed verifications pass through (success=false accepted)
// ---------------------------------------------------------------------------

func TestPositive_FailedVerification_Accepted(t *testing.T) {
	// A verification with success=false should not be structurally validated
	// for attestation contents — it's a legitimate failure report.
	v := keeper.VerificationWire{
		JobID:           "test-job-1",
		Success:         false,
		ErrorCode:       "E001",
		ErrorMessage:    "enclave timed out",
		AttestationType: "",
	}

	ext := &keeper.VoteExtensionWire{
		Version:          1,
		Height:           100,
		ValidatorAddress: json.RawMessage(`"cosmosvaloper1test"`),
		Verifications:    []keeper.VerificationWire{v},
		Timestamp:        time.Now().UTC(),
	}

	data, err := json.Marshal(ext)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// This should NOT error — failed verifications are informational
	resultErr := unmarshalAndValidateExtension(data)
	if resultErr != nil {
		t.Errorf("expected failed verification to be accepted, got error: %v", resultErr)
	}
}

// =============================================================================
// Test Infrastructure — builders and helpers
// =============================================================================

// teeAttestationBuilder provides defaults that pass all structural validation.
type teeAttestationBuilder struct {
	Platform    string    `json:"platform"`
	EnclaveID   string    `json:"enclave_id"`
	Measurement []byte    `json:"measurement"`
	Quote       []byte    `json:"quote"`
	UserData    []byte    `json:"user_data"`
	Timestamp   time.Time `json:"timestamp"`
	Nonce       []byte    `json:"nonce"`
}

func defaultTEEAttestation(outputHash []byte) *teeAttestationBuilder {
	return &teeAttestationBuilder{
		Platform:    "aws-nitro",
		EnclaveID:   "enclave-001",
		Measurement: randomBytes(48),
		Quote:       randomBytes(128),
		UserData:    outputHash, // must match verification output hash
		Timestamp:   time.Now().UTC(),
		Nonce:       randomBytes(32),
	}
}

func makeTEEAttestation(mutate func(*teeAttestationBuilder), outputHash []byte) json.RawMessage {
	a := defaultTEEAttestation(outputHash)
	if mutate != nil {
		mutate(a)
	}
	data, _ := json.Marshal(a)
	return data
}

// zkProofBuilder provides defaults that pass all structural validation.
type zkProofBuilder struct {
	ProofSystem      string `json:"proof_system"`
	Proof            []byte `json:"proof"`
	PublicInputs     []byte `json:"public_inputs"`
	VerifyingKeyHash []byte `json:"verifying_key_hash"`
	CircuitHash      []byte `json:"circuit_hash"`
	ProofSize        int64  `json:"proof_size"`
}

func defaultZKProof() *zkProofBuilder {
	return &zkProofBuilder{
		ProofSystem:      "ezkl",
		Proof:            randomBytes(256),
		PublicInputs:     randomBytes(64),
		VerifyingKeyHash: randomBytes(32),
		CircuitHash:      randomBytes(32),
		ProofSize:        256,
	}
}

func makeZKProof(mutate func(*zkProofBuilder)) json.RawMessage {
	p := defaultZKProof()
	if mutate != nil {
		mutate(p)
	}
	data, _ := json.Marshal(p)
	return data
}

// validSuccessfulVerification returns a VerificationWire that passes
// all structural validation for TEE attestation type.
func validSuccessfulVerification() keeper.VerificationWire {
	outputHash := randomHash()
	return keeper.VerificationWire{
		JobID:           "test-job-neg",
		ModelHash:       randomHash(),
		InputHash:       randomHash(),
		OutputHash:      outputHash,
		AttestationType: "tee",
		TEEAttestation:  makeTEEAttestation(nil, outputHash),
		ExecutionTimeMs: 150,
		Success:         true,
		Nonce:           randomBytes(32),
	}
}

// validExtension creates a structurally valid VoteExtensionWire
// (but without a real keeper context for job existence checks).
func validExtension() *keeper.VoteExtensionWire {
	return &keeper.VoteExtensionWire{
		Version:          1,
		Height:           100,
		ValidatorAddress: json.RawMessage(`"cosmosvaloper1test"`),
		Verifications:    []keeper.VerificationWire{}, // empty is fine
		Timestamp:        time.Now().UTC(),
	}
}

// validateVerificationWireViaExtension wraps a single verification in a
// vote extension, marshals it, and runs validation, returning the error.
// This bypasses the job-existence check (no keeper) by using success=true
// verifications which will be validated structurally first.
func validateVerificationWireViaExtension(t *testing.T, v keeper.VerificationWire) error {
	t.Helper()

	ext := &keeper.VoteExtensionWire{
		Version:          1,
		Height:           100,
		ValidatorAddress: json.RawMessage(`"cosmosvaloper1test"`),
		Verifications:    []keeper.VerificationWire{v},
		Timestamp:        time.Now().UTC(),
	}

	data, err := json.Marshal(ext)
	if err != nil {
		t.Fatalf("failed to marshal extension: %v", err)
	}

	return unmarshalAndValidateExtension(data)
}

// unmarshalAndValidateExtension simulates the VerifyVoteExtension path
// without requiring a live keeper. It performs all structural validation
// that happens before job-existence checks.
func unmarshalAndValidateExtension(data []byte) error {
	var ext keeper.VoteExtensionWire
	if err := json.Unmarshal(data, &ext); err != nil {
		return fmt.Errorf("failed to unmarshal vote extension: %w", err)
	}

	if ext.Version != 1 {
		return fmt.Errorf("unsupported vote extension version: %d", ext.Version)
	}

	if ext.Timestamp.After(time.Now().Add(time.Minute)) {
		return fmt.Errorf("vote extension timestamp is in the future")
	}

	// Construct a minimal ConsensusHandler for validation only
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), nil, nil)
	ctx := sdk.Context{}.WithBlockTime(ext.Timestamp)
	for i, v := range ext.Verifications {
		if err := ch.ValidateVerificationWireWithCtxForTest(ctx, &v); err != nil {
			return fmt.Errorf("invalid verification at index %d: %w", i, err)
		}
	}

	return nil
}

func assertErrorContains(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", substr)
	}
	if !containsSubstring(err.Error(), substr) {
		t.Fatalf("expected error containing %q, got: %s", substr, err.Error())
	}
	t.Logf("OK: correctly rejected with: %s", err.Error())
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// NOTE: randomHash() and randomBytes() are defined in consensus_test.go
// (same package), so they are available here without re-declaration.
