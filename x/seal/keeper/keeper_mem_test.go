package keeper

import (
	"bytes"
	"context"
	"sync"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/seal/types"
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

func newSealForTest(seed byte) *types.DigitalSeal {
	seal := types.NewDigitalSeal(
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		100,
		testAccAddress(seed),
		"credit_scoring",
	)
	seal.Status = types.SealStatusActive
	seal.TeeAttestations = []*types.TEEAttestation{{ValidatorAddress: testAccAddress(seed + 1)}}
	return seal
}

func TestKeeperMemSetGetSeal(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := context.Background()

	seal := newSealForTest(1)
	if err := k.SetSeal(ctx, seal); err != nil {
		t.Fatalf("expected set seal success, got %v", err)
	}

	got, err := k.GetSeal(ctx, seal.Id)
	if err != nil {
		t.Fatalf("expected get seal success, got %v", err)
	}
	if got.Id != seal.Id {
		t.Fatalf("expected seal ID match")
	}

	if _, err := k.GetSeal(ctx, "missing"); err == nil {
		t.Fatalf("expected error for missing seal")
	}
}

func TestKeeperMemListSealsByModelRequester(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := context.Background()

	seal1 := newSealForTest(2)
	seal2 := newSealForTest(3)
	seal2.ModelCommitment = bytes.Repeat([]byte{0x09}, 32)
	seal2.Id = seal2.GenerateID()

	_ = k.SetSeal(ctx, seal1)
	_ = k.SetSeal(ctx, seal2)

	byModel, err := k.ListSealsByModel(ctx, seal1.ModelCommitment)
	if err != nil {
		t.Fatalf("expected list by model success, got %v", err)
	}
	if len(byModel) != 1 {
		t.Fatalf("expected 1 seal for model, got %d", len(byModel))
	}

	byRequester, err := k.ListSealsByRequester(ctx, seal1.RequestedBy)
	if err != nil {
		t.Fatalf("expected list by requester success, got %v", err)
	}
	if len(byRequester) != 1 {
		t.Fatalf("expected 1 seal for requester, got %d", len(byRequester))
	}
}

func TestKeeperVerifySeal(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := context.Background()

	seal := newSealForTest(4)
	_ = k.SetSeal(ctx, seal)

	valid, err := k.VerifySeal(ctx, seal.Id)
	if err != nil || !valid {
		t.Fatalf("expected seal valid, got valid=%v err=%v", valid, err)
	}

	seal.Status = types.SealStatusPending
	_ = k.SetSeal(ctx, seal)
	valid, err = k.VerifySeal(ctx, seal.Id)
	if err != nil || valid {
		t.Fatalf("expected seal invalid when pending")
	}
}

func TestKeeperGetAllSeals(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := context.Background()

	_ = k.SetSeal(ctx, newSealForTest(5))
	_ = k.SetSeal(ctx, newSealForTest(6))

	all := k.GetAllSeals(ctx)
	if len(all) != 2 {
		t.Fatalf("expected 2 seals, got %d", len(all))
	}
}
