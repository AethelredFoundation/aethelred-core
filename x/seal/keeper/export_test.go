package keeper

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"cosmossdk.io/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/seal/types"
)

func newSDKContext() context.Context {
	header := tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  100,
		Time:    time.Now().UTC(),
	}
	sdkCtx := sdk.NewContext(nil, header, false, log.NewNopLogger())
	return sdk.WrapSDKContext(sdkCtx)
}

func TestSealExporterExportJSON(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := newSDKContext()
	seal := newSealForTest(1)
	_ = k.SetSeal(context.Background(), seal)

	exporter := NewSealExporter(log.NewNopLogger(), &k, nil)
	options := DefaultExportOptions()
	options.VerifyBeforeExport = false
	options.Format = ExportFormatJSON
	options.ExporterAddress = testAccAddress(2)

	export, err := exporter.Export(ctx, seal.Id, options)
	if err != nil {
		t.Fatalf("expected export success, got %v", err)
	}
	if export.Metadata.ContentHash == "" {
		t.Fatalf("expected content hash")
	}
}

func TestSealExporterExportFormats(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := newSDKContext()
	seal := newSealForTest(3)
	_ = k.SetSeal(context.Background(), seal)

	exporter := NewSealExporter(log.NewNopLogger(), &k, nil)
	options := DefaultExportOptions()
	options.VerifyBeforeExport = false

	options.Format = ExportFormatCompact
	export, err := exporter.Export(ctx, seal.Id, options)
	if err != nil {
		t.Fatalf("expected compact export success, got %v", err)
	}
	if _, ok := export.Seal.(*CompactSeal); !ok {
		t.Fatalf("expected compact seal type")
	}

	options.Format = ExportFormatPortable
	export, err = exporter.Export(ctx, seal.Id, options)
	if err != nil {
		t.Fatalf("expected portable export success, got %v", err)
	}
	if _, ok := export.Seal.(*PortableSeal); !ok {
		t.Fatalf("expected portable seal type")
	}

	options.Format = ExportFormatAudit
	export, err = exporter.Export(ctx, seal.Id, options)
	if err != nil {
		t.Fatalf("expected audit export success, got %v", err)
	}
	if _, ok := export.Seal.(*AuditExport); !ok {
		t.Fatalf("expected audit export type")
	}
}

func TestSealExporterExportVerifyFailure(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := newSDKContext()
	seal := newSealForTest(4)
	seal.Status = types.SealStatusPending
	_ = k.SetSeal(context.Background(), seal)

	verifier := NewSealVerifier(log.NewNopLogger(), &k, DefaultVerifierConfig())
	exporter := NewSealExporter(log.NewNopLogger(), &k, verifier)
	options := DefaultExportOptions()
	options.VerifyBeforeExport = true

	_, err := exporter.Export(ctx, seal.Id, options)
	if err == nil || !strings.Contains(err.Error(), "seal verification failed") {
		t.Fatalf("expected verification failure error")
	}
}

func TestSealExporterBatchAndBase64(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := newSDKContext()
	seal := newSealForTest(5)
	_ = k.SetSeal(context.Background(), seal)

	exporter := NewSealExporter(log.NewNopLogger(), &k, nil)
	options := DefaultExportOptions()
	options.VerifyBeforeExport = false

	exports, err := exporter.ExportBatch(ctx, []string{seal.Id, "missing"}, options)
	if err != nil {
		t.Fatalf("unexpected batch export error: %v", err)
	}
	if len(exports) != 1 {
		t.Fatalf("expected 1 export, got %d", len(exports))
	}

	b64, err := exporter.ExportToBase64(ctx, seal.Id, options)
	if err != nil {
		t.Fatalf("expected base64 export success, got %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(b64); err != nil {
		t.Fatalf("expected valid base64")
	}

	imported, err := exporter.ImportFromBase64(b64)
	if err != nil {
		t.Fatalf("expected import success, got %v", err)
	}
	if imported.Format != ExportFormatJSON {
		t.Fatalf("expected json format in import")
	}
}
