package keeper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeDrandProvider struct {
	pulse DrandPulse
	err   error
}

func (f fakeDrandProvider) LatestPulse(ctx context.Context) (DrandPulse, error) {
	if f.err != nil {
		return DrandPulse{}, f.err
	}
	return f.pulse, nil
}

func TestHTTPDrandPulseProvider_LatestPulse(t *testing.T) {
	signature := bytesFromString("drand-signature-v1-with-production-like-length-abcdefghijklmnopqrstuvwxyz")
	randomness := sha256.Sum256(signature)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(
			w,
			`{"round":12345,"randomness":"%s","signature":"%s"}`,
			hex.EncodeToString(randomness[:]),
			hex.EncodeToString(signature),
		)
	}))
	t.Cleanup(server.Close)

	provider := NewHTTPDrandPulseProvider(server.URL, time.Second)
	pulse, err := provider.LatestPulse(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pulse.Round != 12345 {
		t.Fatalf("expected round 12345, got %d", pulse.Round)
	}
	if !equalBytes(pulse.Randomness, randomness[:]) {
		t.Fatal("randomness mismatch")
	}
	if !equalBytes(pulse.Signature, signature) {
		t.Fatal("signature mismatch")
	}
}

func TestHTTPDrandPulseProvider_RejectsInconsistentPayload(t *testing.T) {
	signature := bytesFromString("drand-signature-v1-with-production-like-length-abcdefghijklmnopqrstuvwxyz")
	wrongRandomness := sha256.Sum256(bytesFromString("wrong-randomness"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(
			w,
			`{"round":12345,"randomness":"%s","signature":"%s"}`,
			hex.EncodeToString(wrongRandomness[:]),
			hex.EncodeToString(signature),
		)
	}))
	t.Cleanup(server.Close)

	provider := NewHTTPDrandPulseProvider(server.URL, time.Second)
	if _, err := provider.LatestPulse(context.Background()); err == nil {
		t.Fatal("expected consistency-check error")
	}
}

func TestAssignmentEntropyFromContext_UsesRequiredDrandProvider(t *testing.T) {
	signature := bytesFromString("signature-with-adequate-length-for-test-vector-abcdefghijklmnopqrstuvwxyz")
	randomness := sha256.Sum256(signature)
	cfg := DefaultSchedulerConfig()
	cfg.RequirePublicDrandPulse = true
	cfg.AllowDKGBeaconFallback = false
	cfg.AllowLegacyEntropyFallback = false
	cfg.DrandPulseProvider = fakeDrandProvider{
		pulse: DrandPulse{
			Round:      88,
			Randomness: randomness[:],
			Signature:  signature,
			Scheme:     drandBeaconSchemeV1,
			Source:     "drand-public",
		},
	}

	entropy, meta, err := assignmentEntropyFromContext(context.Background(), 1, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entropy) == 0 {
		t.Fatal("expected entropy bytes")
	}
	if meta.Source != "drand-public" {
		t.Fatalf("unexpected source: %s", meta.Source)
	}
	if meta.BeaconRound != 88 {
		t.Fatalf("unexpected round: %d", meta.BeaconRound)
	}
}

func TestAssignmentEntropyFromContext_RejectsMissingDrandInStrictMode(t *testing.T) {
	cfg := DefaultSchedulerConfig()
	cfg.RequirePublicDrandPulse = true
	cfg.AllowDKGBeaconFallback = false
	cfg.AllowLegacyEntropyFallback = false
	cfg.DrandPulseProvider = fakeDrandProvider{
		err: fmt.Errorf("relay unavailable"),
	}

	if _, _, err := assignmentEntropyFromContext(context.Background(), 1, cfg); err == nil {
		t.Fatal("expected error in strict drand mode")
	}
}

func bytesFromString(value string) []byte {
	out := make([]byte, len(value))
	copy(out, []byte(value))
	return out
}
