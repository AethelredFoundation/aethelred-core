package types

import "testing"

func TestDefaultGenesis(t *testing.T) {
	gs := DefaultGenesis()
	if gs == nil {
		t.Fatalf("expected non-nil genesis")
	}
	if gs.Params == nil {
		t.Fatalf("expected non-nil params")
	}
	if len(gs.TeeConfigs) == 0 {
		t.Fatalf("expected tee configs")
	}
}

func TestGenesisValidateParams(t *testing.T) {
	gs := DefaultGenesis()
	gs.Params = nil
	if err := gs.Validate(); err == nil {
		t.Fatalf("expected error for nil params")
	}

	gs = DefaultGenesis()
	gs.Params.MaxProofSize = 0
	if err := gs.Validate(); err == nil {
		t.Fatalf("expected error for invalid max proof size")
	}
}

func TestGenesisValidateVerifyingKey(t *testing.T) {
	gs := DefaultGenesis()
	gs.VerifyingKeys = []*VerifyingKey{{Hash: []byte{0x01}, KeyBytes: []byte{0x02}}}
	if err := gs.Validate(); err == nil {
		t.Fatalf("expected error for invalid verifying key hash length")
	}
}
