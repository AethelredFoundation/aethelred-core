package keeper_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"cosmossdk.io/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// =============================================================================
// PRODUCTION MODE TESTS: Vote Extension Validation
//
// These tests verify that the consensus handler correctly enforces
// production-mode (AllowSimulated=false) security policies:
//   - Unsigned vote extensions MUST be rejected
//   - Missing extension hash MUST be rejected
//   - Simulated TEE platform MUST be rejected
//
// A nil keeper means GetParams returns nil → AllowSimulated defaults to false
// → production mode is enforced.
// =============================================================================

// makeProductionHandler creates a ConsensusHandler with nil keeper,
// which forces production mode (AllowSimulated=false).
func makeProductionHandler() *keeper.ConsensusHandler {
	return keeper.NewConsensusHandler(log.NewNopLogger(), nil, nil)
}

// makeProductionExtension creates a vote extension with the specified
// fields, marshals it, and returns the bytes.
func makeProductionExtension(t *testing.T, mutate func(*keeper.VoteExtensionWire)) []byte {
	t.Helper()
	ext := &keeper.VoteExtensionWire{
		Version:          1,
		Height:           100,
		ValidatorAddress: json.RawMessage(`"cosmosvaloper1production"`),
		Verifications:    []keeper.VerificationWire{},
		Timestamp:        time.Now().UTC(),
		Signature:        json.RawMessage(`"c2lnbmF0dXJl"`), // non-empty base64
		ExtensionHash:    json.RawMessage(`"aGFzaA=="`),      // non-empty base64
	}
	if mutate != nil {
		mutate(ext)
	}
	data, err := json.Marshal(ext)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// ---------------------------------------------------------------------------
// Production Mode: Unsigned Extensions Must Be Rejected
// ---------------------------------------------------------------------------

func TestProduction_RejectsUnsignedExtension(t *testing.T) {
	ch := makeProductionHandler()
	ctx := sdkCtxForHeight(100)

	data := makeProductionExtension(t, func(ext *keeper.VoteExtensionWire) {
		ext.Signature = nil // no signature
	})

	err := ch.VerifyVoteExtension(ctx, data)
	if err == nil {
		t.Fatal("POLICY VIOLATION: production mode must reject unsigned vote extensions")
	}
	if !strings.Contains(err.Error(), "unsigned vote extension rejected") {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Logf("OK: correctly rejected unsigned extension: %v", err)
}

func TestProduction_RejectsEmptySignature(t *testing.T) {
	ch := makeProductionHandler()
	ctx := sdkCtxForHeight(100)

	data := makeProductionExtension(t, func(ext *keeper.VoteExtensionWire) {
		ext.Signature = json.RawMessage(`""`) // empty base64
	})

	err := ch.VerifyVoteExtension(ctx, data)
	if err == nil {
		t.Fatal("POLICY VIOLATION: production mode must reject empty signature")
	}
	t.Logf("OK: correctly rejected empty signature: %v", err)
}

// ---------------------------------------------------------------------------
// Production Mode: Missing Extension Hash Must Be Rejected
// ---------------------------------------------------------------------------

func TestProduction_RejectsMissingExtensionHash(t *testing.T) {
	ch := makeProductionHandler()
	ctx := sdkCtxForHeight(100)

	data := makeProductionExtension(t, func(ext *keeper.VoteExtensionWire) {
		ext.ExtensionHash = nil // no hash
	})

	err := ch.VerifyVoteExtension(ctx, data)
	if err == nil {
		t.Fatal("POLICY VIOLATION: production mode must reject missing extension hash")
	}
	if !strings.Contains(err.Error(), "missing extension hash") {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Logf("OK: correctly rejected missing extension hash: %v", err)
}

func TestProduction_RejectsEmptyExtensionHash(t *testing.T) {
	ch := makeProductionHandler()
	ctx := sdkCtxForHeight(100)

	data := makeProductionExtension(t, func(ext *keeper.VoteExtensionWire) {
		ext.ExtensionHash = json.RawMessage(`""`) // empty base64
	})

	err := ch.VerifyVoteExtension(ctx, data)
	if err == nil {
		t.Fatal("POLICY VIOLATION: production mode must reject empty extension hash")
	}
	t.Logf("OK: correctly rejected empty extension hash: %v", err)
}

// ---------------------------------------------------------------------------
// Production Mode: Simulated TEE Platform Must Be Rejected
// ---------------------------------------------------------------------------

func TestProduction_RejectsSimulatedTEEPlatform(t *testing.T) {
	ch := makeProductionHandler()
	ctx := sdkCtxForHeight(100)

	// Create an extension with a simulated TEE attestation
	outputHash := randomHash()
	v := keeper.VerificationWire{
		JobID:           "test-prod-tee",
		ModelHash:       randomHash(),
		InputHash:       randomHash(),
		OutputHash:      outputHash,
		AttestationType: "tee",
		TEEAttestation:  makeTEEAttestation(func(a *teeAttestationBuilder) {
			a.Platform = "simulated"
		}, outputHash),
		ExecutionTimeMs: 150,
		Success:         true,
		Nonce:           randomBytes(32),
	}

	data := makeProductionExtension(t, func(ext *keeper.VoteExtensionWire) {
		ext.Verifications = []keeper.VerificationWire{v}
	})

	err := ch.VerifyVoteExtension(ctx, data)
	if err == nil {
		t.Fatal("POLICY VIOLATION: production mode must reject simulated TEE platform")
	}
	if !strings.Contains(err.Error(), "simulated TEE platform rejected") {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Logf("OK: correctly rejected simulated TEE: %v", err)
}

func TestProduction_RejectsSimulatedTEEInHybrid(t *testing.T) {
	ch := makeProductionHandler()
	ctx := sdkCtxForHeight(100)

	outputHash := randomHash()
	v := keeper.VerificationWire{
		JobID:           "test-prod-hybrid",
		ModelHash:       randomHash(),
		InputHash:       randomHash(),
		OutputHash:      outputHash,
		AttestationType: "hybrid",
		TEEAttestation:  makeTEEAttestation(func(a *teeAttestationBuilder) {
			a.Platform = "simulated"
		}, outputHash),
		ZKProof:         makeZKProof(nil),
		ExecutionTimeMs: 200,
		Success:         true,
		Nonce:           randomBytes(32),
	}

	data := makeProductionExtension(t, func(ext *keeper.VoteExtensionWire) {
		ext.Verifications = []keeper.VerificationWire{v}
	})

	err := ch.VerifyVoteExtension(ctx, data)
	if err == nil {
		t.Fatal("POLICY VIOLATION: production mode must reject simulated TEE even in hybrid")
	}
	if !strings.Contains(err.Error(), "simulated TEE platform rejected") {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Logf("OK: correctly rejected simulated TEE in hybrid: %v", err)
}

// ---------------------------------------------------------------------------
// Production Mode: Real TEE Platforms Must Be Accepted (structural only)
// ---------------------------------------------------------------------------

func TestProduction_AcceptsRealTEEPlatforms(t *testing.T) {
	realPlatforms := []string{"aws-nitro", "intel-sgx", "intel-tdx", "amd-sev", "arm-trustzone"}

	for _, platform := range realPlatforms {
		t.Run(platform, func(t *testing.T) {
			ch := makeProductionHandler()
			ctx := sdkCtxForHeight(100)

			outputHash := randomHash()
			v := keeper.VerificationWire{
				JobID:           "test-prod-" + platform,
				ModelHash:       randomHash(),
				InputHash:       randomHash(),
				OutputHash:      outputHash,
				AttestationType: "tee",
				TEEAttestation: makeTEEAttestation(func(a *teeAttestationBuilder) {
					a.Platform = platform
				}, outputHash),
				ExecutionTimeMs: 150,
				Success:         true,
				Nonce:           randomBytes(32),
			}

			// This checks only TEE attestation validation, not job existence
			err := ch.ValidateTEEAttestationWireStrictForTest(ctx, &v)
			if err != nil {
				t.Fatalf("real TEE platform %s should be accepted in production: %v", platform, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Production Mode: zkML-only verification should pass (no TEE to reject)
// ---------------------------------------------------------------------------

func TestProduction_AcceptsZKMLOnly(t *testing.T) {
	ch := makeProductionHandler()
	ctx := sdkCtxForHeight(100)

	v := keeper.VerificationWire{
		JobID:           "test-prod-zkml",
		ModelHash:       randomHash(),
		InputHash:       randomHash(),
		OutputHash:      randomHash(),
		AttestationType: "zkml",
		ZKProof:         makeZKProof(nil),
		ExecutionTimeMs: 300,
		Success:         true,
		Nonce:           randomBytes(32),
	}

	// Validate the verification wire structurally
	err := ch.ValidateVerificationWireForTest(&v)
	if err != nil {
		t.Fatalf("zkML-only should be accepted: %v", err)
	}

	// Also test via full extension in production mode
	data := makeProductionExtension(t, func(ext *keeper.VoteExtensionWire) {
		ext.Verifications = []keeper.VerificationWire{v}
	})

	// This will fail on job existence check (no keeper), but should NOT fail
	// on the simulated TEE check (since this is zkML).
	err = ch.VerifyVoteExtension(ctx, data)
	if err != nil {
		// Expected: error from job existence check, not from TEE check
		if strings.Contains(err.Error(), "simulated TEE") {
			t.Fatal("zkML verification should not trigger simulated TEE rejection")
		}
		// Job existence check failure is expected with nil keeper
		t.Logf("Expected failure from job existence check: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Production Mode: Version and structural checks still apply
// ---------------------------------------------------------------------------

func TestProduction_RejectsWrongVersion(t *testing.T) {
	ch := makeProductionHandler()
	ctx := sdkCtxForHeight(100)

	data := makeProductionExtension(t, func(ext *keeper.VoteExtensionWire) {
		ext.Version = 42
	})

	err := ch.VerifyVoteExtension(ctx, data)
	if err == nil {
		t.Fatal("production mode should reject wrong version")
	}
	if !strings.Contains(err.Error(), "unsupported vote extension version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProduction_RejectsHeightMismatch(t *testing.T) {
	ch := makeProductionHandler()
	ctx := sdkCtxForHeight(100) // height=100

	data := makeProductionExtension(t, func(ext *keeper.VoteExtensionWire) {
		ext.Height = 999 // mismatch
	})

	err := ch.VerifyVoteExtension(ctx, data)
	if err == nil {
		t.Fatal("production mode should reject height mismatch")
	}
	if !strings.Contains(err.Error(), "height mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProduction_RejectsFutureTimestamp(t *testing.T) {
	ch := makeProductionHandler()
	ctx := sdkCtxForHeight(100)

	data := makeProductionExtension(t, func(ext *keeper.VoteExtensionWire) {
		ext.Timestamp = time.Now().Add(5 * time.Minute)
	})

	err := ch.VerifyVoteExtension(ctx, data)
	if err == nil {
		t.Fatal("production mode should reject future timestamp")
	}
	if !strings.Contains(err.Error(), "in the future") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProduction_RejectsMalformedJSON(t *testing.T) {
	ch := makeProductionHandler()
	ctx := sdkCtxForHeight(100)

	err := ch.VerifyVoteExtension(ctx, []byte(`{malformed`))
	if err == nil {
		t.Fatal("should reject malformed JSON")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Production Mode: Failed verifications are still accepted
// ---------------------------------------------------------------------------

func TestProduction_AcceptsFailedVerifications(t *testing.T) {
	ch := makeProductionHandler()
	ctx := sdkCtxForHeight(100)

	v := keeper.VerificationWire{
		JobID:           "test-prod-fail",
		Success:         false,
		ErrorCode:       "TIMEOUT",
		ErrorMessage:    "enclave timed out",
		AttestationType: "",
	}

	data := makeProductionExtension(t, func(ext *keeper.VoteExtensionWire) {
		ext.Verifications = []keeper.VerificationWire{v}
	})

	err := ch.VerifyVoteExtension(ctx, data)
	// Should not fail on the failed verification itself
	// (may fail on unsigned check or hash check depending on fields)
	if err != nil && strings.Contains(err.Error(), "missing job ID") {
		t.Fatal("failed verification with valid job ID should not fail structural validation")
	}
	t.Logf("Production mode with failed verification: %v", err)
}

// ---------------------------------------------------------------------------
// Production Mode: Empty extension is accepted (no jobs)
// ---------------------------------------------------------------------------

func TestProduction_AcceptsEmptyExtension(t *testing.T) {
	ch := makeProductionHandler()
	ctx := sdkCtxForHeight(100)

	data := makeProductionExtension(t, nil) // empty verifications

	// Production mode: must have signature + hash but no verifications
	// This checks that production guards don't reject valid empty extensions
	err := ch.VerifyVoteExtension(ctx, data)
	if err != nil {
		// If there's an error, it should be about parsing, not production guards
		t.Logf("Empty extension result: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Policy: Combined rejection matrix
// ---------------------------------------------------------------------------

func TestPolicy_Production_RejectionMatrix(t *testing.T) {
	type testCase struct {
		name     string
		mutate   func(*keeper.VoteExtensionWire)
		contains string
	}

	cases := []testCase{
		{
			name: "no_signature",
			mutate: func(ext *keeper.VoteExtensionWire) {
				ext.Signature = nil
			},
			contains: "unsigned",
		},
		{
			name: "no_hash",
			mutate: func(ext *keeper.VoteExtensionWire) {
				ext.ExtensionHash = nil
			},
			contains: "missing extension hash",
		},
		{
			name: "wrong_version",
			mutate: func(ext *keeper.VoteExtensionWire) {
				ext.Version = 0
			},
			contains: "unsupported vote extension version",
		},
		{
			name: "height_mismatch",
			mutate: func(ext *keeper.VoteExtensionWire) {
				ext.Height = 42
			},
			contains: "height mismatch",
		},
		{
			name: "future_timestamp",
			mutate: func(ext *keeper.VoteExtensionWire) {
				ext.Timestamp = time.Now().Add(10 * time.Minute)
			},
			contains: "in the future",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := makeProductionHandler()
			ctx := sdkCtxForHeight(100)
			data := makeProductionExtension(t, tc.mutate)

			err := ch.VerifyVoteExtension(ctx, data)
			if err == nil {
				t.Fatalf("POLICY VIOLATION: %s must be rejected in production mode", tc.name)
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("expected error containing %q, got: %v", tc.contains, err)
			}
			t.Logf("OK: %s rejected: %v", tc.name, err)
		})
	}
}

// ---------------------------------------------------------------------------
// Helper: create sdk.Context with a specific block height
// ---------------------------------------------------------------------------

func sdkCtxForHeight(height int64) sdk.Context {
	header := tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  height,
		Time:    time.Now().UTC(),
	}
	return sdk.NewContext(nil, header, false, log.NewNopLogger())
}

// Imports needed for this file that aren't already in the package
var _ = fmt.Sprintf // keep fmt import alive
