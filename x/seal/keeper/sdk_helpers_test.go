package keeper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"cosmossdk.io/log"

	"github.com/aethelred/aethelred/x/seal/types"
)

func TestTruncateHash(t *testing.T) {
	short := []byte{0x01, 0x02}
	if got := truncateHash(short); got != hex.EncodeToString(short) {
		t.Fatalf("expected full hash for short input")
	}

	long := make([]byte, 32)
	got := truncateHash(long)
	if !strings.Contains(got, "...") {
		t.Fatalf("expected truncated hash")
	}
}

func TestComputeHashes(t *testing.T) {
	helper := &SDKHelper{}
	input := []byte("data")

	expected := sha256.Sum256(input)
	if got := helper.ComputeInputHash(input); got != hex.EncodeToString(expected[:]) {
		t.Fatalf("expected input hash to match")
	}
	if got := helper.ComputeModelHash(input); got != hex.EncodeToString(expected[:]) {
		t.Fatalf("expected model hash to match")
	}
}

func TestVerifyFromBase64Errors(t *testing.T) {
	helper := &SDKHelper{}

	if _, err := helper.VerifyFromBase64(nil, "***"); err == nil {
		t.Fatalf("expected error for invalid base64")
	}

	invalidJSON := base64.StdEncoding.EncodeToString([]byte("not-json"))
	if _, err := helper.VerifyFromBase64(nil, invalidJSON); err == nil {
		t.Fatalf("expected error for invalid json")
	}

	exported := ExportedSeal{Seal: map[string]interface{}{"foo": "bar"}}
	payload, _ := json.Marshal(exported)
	encoded := base64.StdEncoding.EncodeToString(payload)
	if _, err := helper.VerifyFromBase64(nil, encoded); err == nil {
		t.Fatalf("expected error for missing seal id")
	}
}

func TestSDKHelperModelAndOutputVerification(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := context.Background()
	helper := NewSDKHelper(log.NewNopLogger(), &k, nil, nil)

	seal := types.NewDigitalSeal(
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		100,
		testAccAddress(1),
		"credit_scoring",
	)
	seal.Status = types.SealStatusActive
	seal.TeeAttestations = []*types.TEEAttestation{{ValidatorAddress: testAccAddress(2)}}
	_ = k.SetSeal(ctx, seal)

	ok, err := helper.VerifyOutputHash(ctx, seal.Id, seal.OutputCommitment)
	if err != nil || !ok {
		t.Fatalf("expected output hash to verify")
	}

	result, err := helper.VerifyModelAndOutput(ctx, seal.Id, seal.ModelCommitment, seal.OutputCommitment)
	if err != nil || !result.Valid {
		t.Fatalf("expected model/output verification to succeed")
	}
}

func TestSDKHelperListSeals(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := context.Background()
	helper := NewSDKHelper(log.NewNopLogger(), &k, nil, nil)

	seal1 := types.NewDigitalSeal(
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		100,
		testAccAddress(3),
		"credit_scoring",
	)
	seal2 := types.NewDigitalSeal(
		bytes.Repeat([]byte{0x09}, 32),
		bytes.Repeat([]byte{0x0A}, 32),
		bytes.Repeat([]byte{0x0B}, 32),
		200,
		testAccAddress(4),
		"fraud_detection",
	)
	_ = k.SetSeal(ctx, seal1)
	_ = k.SetSeal(ctx, seal2)

	byModel, err := helper.ListSealsByModel(ctx, seal1.ModelCommitment, 10)
	if err != nil || len(byModel) != 1 {
		t.Fatalf("expected one seal by model")
	}

	byPurpose, err := helper.ListSealsByPurpose(ctx, "fraud_detection", 10)
	if err != nil || len(byPurpose) != 1 {
		t.Fatalf("expected one seal by purpose")
	}
}

func TestSDKHelperSummariesAndCompliance(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := context.Background()
	helper := NewSDKHelper(log.NewNopLogger(), &k, nil, nil)

	seal := types.NewDigitalSeal(
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		100,
		testAccAddress(7),
		"credit_scoring",
	)
	seal.RegulatoryInfo = &types.RegulatoryInfo{
		ComplianceFrameworks:     []string{"HIPAA"},
		DataClassification:       "confidential",
		JurisdictionRestrictions: []string{"US"},
	}
	_ = k.SetSeal(ctx, seal)

	summary, err := helper.GetSealSummary(ctx, seal.Id)
	if err != nil {
		t.Fatalf("expected summary, got %v", err)
	}
	if len(summary.ComplianceFrameworks) != 1 {
		t.Fatalf("expected compliance frameworks in summary")
	}

	compliance, err := helper.GetComplianceInfo(ctx, seal.Id)
	if err != nil {
		t.Fatalf("expected compliance info, got %v", err)
	}
	if compliance.DataClassification != "confidential" {
		t.Fatalf("expected data classification")
	}
}
