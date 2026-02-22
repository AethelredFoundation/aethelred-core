package types

import "testing"

func TestSealDefaultGenesis(t *testing.T) {
	gs := DefaultGenesis()
	if gs == nil {
		t.Fatalf("expected non-nil genesis")
	}
	if gs.Params == nil {
		t.Fatalf("expected params")
	}
}

func TestSealGenesisValidate(t *testing.T) {
	gs := DefaultGenesis()
	gs.Params = nil
	if err := gs.Validate(); err == nil {
		t.Fatalf("expected error for nil params")
	}

	gs = DefaultGenesis()
	gs.Params.MinValidatorAttestations = 0
	if err := gs.Validate(); err == nil {
		t.Fatalf("expected error for invalid min validator attestations")
	}
}
