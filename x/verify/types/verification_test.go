package types

import "testing"

func TestZKMLProofValidate(t *testing.T) {
	proof := &ZKMLProof{}
	if err := proof.Validate(); err == nil {
		t.Fatalf("expected error for empty proof")
	}

	proof.ProofSystem = "ezkl"
	proof.ProofBytes = []byte{0x01}
	proof.VerifyingKeyHash = make([]byte, 31)
	if err := proof.Validate(); err == nil {
		t.Fatalf("expected error for invalid verifying key hash length")
	}

	proof.VerifyingKeyHash = make([]byte, 32)
	if err := proof.Validate(); err != nil {
		t.Fatalf("expected valid proof, got %v", err)
	}
}

func TestTEEAttestationValidate(t *testing.T) {
	att := &TEEAttestation{}
	if err := att.Validate(); err == nil {
		t.Fatalf("expected error for unspecified platform")
	}

	att.Platform = TEEPlatformAWSNitro
	if err := att.Validate(); err == nil {
		t.Fatalf("expected error for empty measurement")
	}

	att.Measurement = []byte{0x01}
	if err := att.Validate(); err == nil {
		t.Fatalf("expected error for empty quote")
	}

	att.Quote = []byte{0x02}
	if err := att.Validate(); err != nil {
		t.Fatalf("expected valid attestation, got %v", err)
	}
}

func TestSupportedChecks(t *testing.T) {
	if !IsPlatformSupported(TEEPlatformAWSNitro) {
		t.Fatalf("expected AWS Nitro to be supported")
	}
	if IsPlatformSupported(TEEPlatformUnspecified) {
		t.Fatalf("expected unspecified platform to be unsupported")
	}

	if !IsProofSystemSupported("ezkl") {
		t.Fatalf("expected ezkl to be supported")
	}
	if IsProofSystemSupported("unknown") {
		t.Fatalf("expected unknown system to be unsupported")
	}
}
