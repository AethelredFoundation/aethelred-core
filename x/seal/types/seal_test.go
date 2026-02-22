package types

import (
	"bytes"
	"sync"
	"testing"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var bech32Once sync.Once

func ensureBech32() {
	bech32Once.Do(func() {
		defer func() { _ = recover() }()
		cfg := sdk.GetConfig()
		cfg.SetBech32PrefixForAccount("aeth", "aethpub")
		cfg.SetBech32PrefixForValidator("aethvaloper", "aethvaloperpub")
		cfg.SetBech32PrefixForConsensusNode("aethvalcons", "aethvalconspub")
		cfg.Seal()
	})
}

func testAccAddress(seed byte) string {
	ensureBech32()
	addr := bytes.Repeat([]byte{seed}, 20)
	return sdk.AccAddress(addr).String()
}

func TestDigitalSealValidateAndID(t *testing.T) {
	seal := NewDigitalSeal(
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		100,
		testAccAddress(1),
		"credit_scoring",
	)
	if len(seal.Id) != 64 {
		t.Fatalf("expected 64-char id, got %d", len(seal.Id))
	}
	if err := seal.Validate(); err != nil {
		t.Fatalf("expected valid seal, got %v", err)
	}

	seal.ModelCommitment = []byte{0x01}
	if err := seal.Validate(); err == nil {
		t.Fatalf("expected error for invalid model commitment length")
	}
}

func TestDigitalSealValidate_InvalidAddress(t *testing.T) {
	seal := NewDigitalSeal(
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		100,
		"not-a-bech32-address",
		"credit_scoring",
	)
	if err := seal.Validate(); err == nil {
		t.Fatalf("expected error for invalid requester address")
	}
}

func TestDigitalSealVerificationFlags(t *testing.T) {
	seal := &DigitalSeal{}
	if seal.IsVerified() {
		t.Fatalf("expected unverified")
	}
	if seal.GetVerificationType() != "none" {
		t.Fatalf("expected none verification type")
	}

	seal.TeeAttestations = []*TEEAttestation{{}}
	if !seal.IsVerified() {
		t.Fatalf("expected verified with TEE")
	}
	if seal.GetVerificationType() != "tee" {
		t.Fatalf("expected tee verification type")
	}

	seal.ZkProof = &ZKMLProof{}
	if seal.GetVerificationType() != "hybrid" {
		t.Fatalf("expected hybrid verification type")
	}
}

func TestDigitalSealConsensus(t *testing.T) {
	seal := &DigitalSeal{}
	seal.TeeAttestations = []*TEEAttestation{{}, {}, {}, {}, {}, {}} // 6
	if seal.HasConsensus(10) {
		t.Fatalf("expected no consensus with 6/10")
	}
	seal.TeeAttestations = append(seal.TeeAttestations, &TEEAttestation{}) // 7
	if !seal.HasConsensus(10) {
		t.Fatalf("expected consensus with 7/10")
	}
}

func TestDigitalSealAddAttestation(t *testing.T) {
	seal := NewDigitalSeal(
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		100,
		testAccAddress(14),
		"credit_scoring",
	)
	att := &TEEAttestation{ValidatorAddress: testAccAddress(15)}
	seal.AddAttestation(att)
	if len(seal.TeeAttestations) != 1 {
		t.Fatalf("expected attestation added")
	}
	if len(seal.ValidatorSet) != 1 {
		t.Fatalf("expected validator set updated")
	}
}

func TestDigitalSealGenerateIDDeterministic(t *testing.T) {
	ensureBech32()
	ts := timestamppb.New(time.Unix(1700000000, 0))
	seal := &DigitalSeal{
		ModelCommitment:  bytes.Repeat([]byte{0x01}, 32),
		InputCommitment:  bytes.Repeat([]byte{0x02}, 32),
		OutputCommitment: bytes.Repeat([]byte{0x03}, 32),
		BlockHeight:      123,
		RequestedBy:      testAccAddress(2),
		Purpose:          "credit_scoring",
		Timestamp:        ts,
	}
	id1 := seal.GenerateID()
	id2 := seal.GenerateID()
	if id1 != id2 {
		t.Fatalf("expected deterministic id")
	}
}
