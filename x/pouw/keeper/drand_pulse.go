package keeper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	nethttp "net/http"
	"net/url"
	"strings"
	"time"

	drandclient "github.com/drand/drand/client"
	drandhttp "github.com/drand/drand/client/http"
)

const (
	// DefaultDrandEndpoint is the League of Entropy public relay.
	DefaultDrandEndpoint = "https://api.drand.sh"
	// DefaultDrandChainHashHex is the public League of Entropy quicknet chain hash.
	// This acts as the root of trust for the drand client verifier.
	DefaultDrandChainHashHex = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
)

// DrandPulse captures the minimum data needed to drive deterministic assignment.
type DrandPulse struct {
	Round      uint64
	Randomness []byte
	Signature  []byte
	Scheme     string
	Source     string
}

// DrandPulseProvider abstracts drand pulse retrieval.
type DrandPulseProvider interface {
	LatestPulse(ctx context.Context) (DrandPulse, error)
}

// HTTPDrandPulseProvider queries a drand HTTP relay for the latest pulse.
//
// Verification model:
//   - Production/public endpoints use the official drand Go client with chain-hash
//     root of trust + full chain verification.
//   - Localhost test endpoints fall back to a dependency-light JSON parser and
//     self-consistency check (randomness == sha256(signature)) so unit tests can use
//     httptest without implementing the full drand relay API surface.
type HTTPDrandPulseProvider struct {
	endpoint             string
	client               *nethttp.Client
	scheme               string
	source               string
	chainHash            []byte
	useLocalTestFallback bool
}

type drandHTTPPulse struct {
	Round      uint64 `json:"round"`
	Randomness string `json:"randomness"`
	Signature  string `json:"signature"`
}

// NewHTTPDrandPulseProvider builds a drand provider backed by the public HTTP relay.
func NewHTTPDrandPulseProvider(endpoint string, timeout time.Duration) *HTTPDrandPulseProvider {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		trimmed = DefaultDrandEndpoint
	}

	if timeout <= 0 {
		timeout = 4 * time.Second
	}

	chainHash, err := hex.DecodeString(DefaultDrandChainHashHex)
	if err != nil {
		// Static constant; preserve constructor API and fail later on fetch if this ever regresses.
		chainHash = nil
	}

	return &HTTPDrandPulseProvider{
		endpoint: strings.TrimRight(trimmed, "/"),
		client: &nethttp.Client{
			Timeout: timeout,
		},
		scheme:               drandBeaconSchemeV1,
		source:               "drand-public",
		chainHash:            chainHash,
		useLocalTestFallback: isLocalDrandEndpoint(trimmed),
	}
}

// LatestPulse fetches and validates the latest drand pulse.
func (p *HTTPDrandPulseProvider) LatestPulse(ctx context.Context) (DrandPulse, error) {
	if p == nil {
		return DrandPulse{}, fmt.Errorf("drand provider is nil")
	}
	if p.useLocalTestFallback {
		return p.latestPulseLocalHTTP(ctx)
	}
	return p.latestPulseVerified(ctx)
}

func (p *HTTPDrandPulseProvider) latestPulseVerified(ctx context.Context) (DrandPulse, error) {
	if len(p.chainHash) == 0 {
		return DrandPulse{}, fmt.Errorf("drand chain hash root-of-trust is not configured")
	}

	httpClient, err := drandhttp.New(p.endpoint, p.chainHash, nil)
	if err != nil {
		return DrandPulse{}, fmt.Errorf("build drand http client: %w", err)
	}
	verifiedClient, err := drandclient.New(
		drandclient.From(httpClient),
		drandclient.WithChainHash(p.chainHash),
		drandclient.WithFullChainVerification(),
	)
	if err != nil {
		_ = httpClient.Close()
		return DrandPulse{}, fmt.Errorf("build verifying drand client: %w", err)
	}
	defer verifiedClient.Close()

	result, err := verifiedClient.Get(ctx, 0)
	if err != nil {
		return DrandPulse{}, fmt.Errorf("verified drand fetch failed: %w", err)
	}
	if result == nil {
		return DrandPulse{}, fmt.Errorf("verified drand fetch returned nil result")
	}
	if result.Round() == 0 {
		return DrandPulse{}, fmt.Errorf("invalid drand round: 0")
	}
	randomness := result.Randomness()
	if len(randomness) != 32 {
		return DrandPulse{}, fmt.Errorf("invalid drand randomness length: got %d want 32", len(randomness))
	}
	signature := result.Signature()
	if len(signature) < 48 {
		return DrandPulse{}, fmt.Errorf("invalid drand signature length: got %d", len(signature))
	}

	return DrandPulse{
		Round:      result.Round(),
		Randomness: randomness,
		Signature:  signature,
		Scheme:     p.scheme,
		Source:     p.source,
	}, nil
}

func (p *HTTPDrandPulseProvider) latestPulseLocalHTTP(ctx context.Context) (DrandPulse, error) {
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, p.endpoint+"/public/latest", nil)
	if err != nil {
		return DrandPulse{}, fmt.Errorf("build drand request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return DrandPulse{}, fmt.Errorf("drand request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return DrandPulse{}, fmt.Errorf("drand relay status %d", resp.StatusCode)
	}

	var payload drandHTTPPulse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return DrandPulse{}, fmt.Errorf("decode drand payload: %w", err)
	}
	if payload.Round == 0 {
		return DrandPulse{}, fmt.Errorf("invalid drand round: 0")
	}

	randomness, err := hex.DecodeString(strings.TrimSpace(payload.Randomness))
	if err != nil {
		return DrandPulse{}, fmt.Errorf("invalid drand randomness hex: %w", err)
	}
	if len(randomness) != 32 {
		return DrandPulse{}, fmt.Errorf("invalid drand randomness length: got %d want 32", len(randomness))
	}

	signature, err := hex.DecodeString(strings.TrimSpace(payload.Signature))
	if err != nil {
		return DrandPulse{}, fmt.Errorf("invalid drand signature hex: %w", err)
	}
	if len(signature) < 48 {
		return DrandPulse{}, fmt.Errorf("invalid drand signature length: got %d", len(signature))
	}

	expectedRandomness := sha256.Sum256(signature)
	if !equalBytes(expectedRandomness[:], randomness) {
		return DrandPulse{}, fmt.Errorf("drand pulse failed randomness/signature consistency check")
	}

	return DrandPulse{
		Round:      payload.Round,
		Randomness: randomness,
		Signature:  signature,
		Scheme:     p.scheme,
		Source:     p.source,
	}, nil
}

func isLocalDrandEndpoint(endpoint string) bool {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true
	default:
		return false
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
