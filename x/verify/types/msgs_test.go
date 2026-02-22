package types

import (
	"bytes"
	"sync"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
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

func TestMsgRegisterVerifyingKeyValidateBasic(t *testing.T) {
	msg := NewMsgRegisterVerifyingKey(
		testAccAddress(1),
		[]byte{0x01},
		"ezkl",
		[]byte{0x02},
		[]byte{0x03},
	)
	if err := msg.ValidateBasic(); err != nil {
		t.Fatalf("expected valid msg, got %v", err)
	}

	msg.Creator = "bad-address"
	if err := msg.ValidateBasic(); err == nil {
		t.Fatalf("expected error for invalid creator")
	}

	msg.Creator = testAccAddress(1)
	msg.ProofSystem = "unknown"
	if err := msg.ValidateBasic(); err == nil {
		t.Fatalf("expected error for unsupported proof system")
	}
}

func TestMsgRegisterCircuitValidateBasic(t *testing.T) {
	msg := &MsgRegisterCircuit{
		Creator:      testAccAddress(2),
		CircuitBytes: []byte{0x01},
		ProofSystem:  "ezkl",
	}
	if err := msg.ValidateBasic(); err != nil {
		t.Fatalf("expected valid msg, got %v", err)
	}

	msg.Creator = "bad"
	if err := msg.ValidateBasic(); err == nil {
		t.Fatalf("expected error for invalid creator")
	}
}

func TestMsgVerifyZKProofValidateBasic(t *testing.T) {
	proof := &ZKMLProof{ProofSystem: "ezkl", ProofBytes: []byte{0x01}, VerifyingKeyHash: make([]byte, 32)}
	msg := &MsgVerifyZKProof{Verifier: testAccAddress(3), Proof: proof}
	if err := msg.ValidateBasic(); err != nil {
		t.Fatalf("expected valid msg, got %v", err)
	}

	msg.Verifier = "bad"
	if err := msg.ValidateBasic(); err == nil {
		t.Fatalf("expected error for invalid verifier")
	}

	msg.Verifier = testAccAddress(3)
	msg.Proof = nil
	if err := msg.ValidateBasic(); err == nil {
		t.Fatalf("expected error for nil proof")
	}
}
