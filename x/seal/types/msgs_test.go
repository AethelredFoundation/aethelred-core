package types

import (
	"bytes"
	"testing"
)

func TestMsgCreateSealValidateBasic(t *testing.T) {
	msg := NewMsgCreateSeal(
		testAccAddress(10),
		"job-1",
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		"credit_scoring",
	)
	if err := msg.ValidateBasic(); err != nil {
		t.Fatalf("expected valid msg, got %v", err)
	}

	msg.JobId = ""
	if err := msg.ValidateBasic(); err == nil {
		t.Fatalf("expected error for empty job id")
	}

	msg.JobId = "job-1"
	msg.ModelCommitment = []byte{0x01}
	if err := msg.ValidateBasic(); err == nil {
		t.Fatalf("expected error for invalid model commitment length")
	}
}

func TestMsgRevokeSealValidateBasic(t *testing.T) {
	msg := NewMsgRevokeSeal(testAccAddress(11), "seal-1", "reason")
	if err := msg.ValidateBasic(); err != nil {
		t.Fatalf("expected valid msg, got %v", err)
	}

	msg.Authority = "bad"
	if err := msg.ValidateBasic(); err == nil {
		t.Fatalf("expected error for invalid authority")
	}

	msg.Authority = testAccAddress(11)
	msg.Reason = ""
	if err := msg.ValidateBasic(); err == nil {
		t.Fatalf("expected error for empty reason")
	}
}
