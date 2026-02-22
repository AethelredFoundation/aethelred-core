package keeper

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aethelred/aethelred/internal/circuitbreaker"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func withHTTPClientStub(t *testing.T, fn roundTripFunc) {
	t.Helper()
	old := secureHTTPClientProvider
	secureHTTPClientProvider = func() *http.Client {
		return &http.Client{Transport: fn}
	}
	t.Cleanup(func() { secureHTTPClientProvider = old })
}

func TestRemoteVerifierOffline_ZKPaths(t *testing.T) {
	withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
		require.Equal(t, "POST", req.Method)
		require.True(t, strings.HasSuffix(req.URL.Path, "/verify"))

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"verified":true}`)),
			Header:     make(http.Header),
		}, nil
	})

	k := Keeper{}
	ok, err := k.callRemoteZKVerifier(context.Background(), "https://verifier.example", sampleZKProof(), sampleVerifyingKey())
	require.NoError(t, err)
	require.True(t, ok)
}

func TestRemoteVerifierOffline_ZKErrorsAndBreaker(t *testing.T) {
	t.Run("invalid endpoint rejected before HTTP", func(t *testing.T) {
		k := Keeper{}
		ok, err := k.callRemoteZKVerifier(context.Background(), "ftp://example.com", sampleZKProof(), sampleVerifyingKey())
		require.Error(t, err)
		require.False(t, ok)
		require.Contains(t, err.Error(), "invalid verifier endpoint")
	})

	t.Run("circuit open blocks request", func(t *testing.T) {
		k := Keeper{
			zkVerifierBreaker: circuitbreaker.New("zk", 1, time.Hour),
		}
		k.zkVerifierBreaker.RecordFailure()
		ok, err := k.callRemoteZKVerifier(context.Background(), "https://verifier.example", sampleZKProof(), sampleVerifyingKey())
		require.ErrorContains(t, err, "circuit open")
		require.False(t, ok)
	})

	t.Run("non-200 status returns error", func(t *testing.T) {
		withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(strings.NewReader(`bad request`)),
				Header:     make(http.Header),
			}, nil
		})

		k := Keeper{}
		ok, err := k.callRemoteZKVerifier(context.Background(), "https://verifier.example", sampleZKProof(), sampleVerifyingKey())
		require.ErrorContains(t, err, "status 400")
		require.False(t, ok)
	})

	t.Run("decode failure", func(t *testing.T) {
		withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{bad-json`)),
				Header:     make(http.Header),
			}, nil
		})

		k := Keeper{}
		ok, err := k.callRemoteZKVerifier(context.Background(), "https://verifier.example", sampleZKProof(), sampleVerifyingKey())
		require.ErrorContains(t, err, "decode")
		require.False(t, ok)
	})

	t.Run("explicit verifier error", func(t *testing.T) {
		withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"verified":false,"error":"invalid proof"}`)),
				Header:     make(http.Header),
			}, nil
		})

		k := Keeper{}
		ok, err := k.callRemoteZKVerifier(context.Background(), "https://verifier.example", sampleZKProof(), sampleVerifyingKey())
		require.ErrorContains(t, err, "verification failed")
		require.False(t, ok)
	})

	t.Run("transport error", func(t *testing.T) {
		withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("network down")
		})

		k := Keeper{}
		ok, err := k.callRemoteZKVerifier(context.Background(), "https://verifier.example", sampleZKProof(), sampleVerifyingKey())
		require.ErrorContains(t, err, "request failed")
		require.False(t, ok)
	})
}

func TestRemoteVerifierOffline_AttestationPaths(t *testing.T) {
	withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
		require.Equal(t, "POST", req.Method)
		require.True(t, strings.HasSuffix(req.URL.Path, "/verify"))

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"verified":true}`)),
			Header:     make(http.Header),
		}, nil
	})

	k := Keeper{}
	ok, err := k.callRemoteAttestationVerifier(context.Background(), "https://attestation.example", sampleTEEAttestation())
	require.NoError(t, err)
	require.True(t, ok)
}

func TestRemoteVerifierOffline_AttestationErrorsAndBreaker(t *testing.T) {
	t.Run("invalid endpoint rejected before HTTP", func(t *testing.T) {
		k := Keeper{}
		ok, err := k.callRemoteAttestationVerifier(context.Background(), "ftp://example.com", sampleTEEAttestation())
		require.Error(t, err)
		require.False(t, ok)
		require.Contains(t, err.Error(), "invalid attestation endpoint")
	})

	t.Run("circuit open blocks request", func(t *testing.T) {
		k := Keeper{
			attestationVerifierBreaker: circuitbreaker.New("attestation", 1, time.Hour),
		}
		k.attestationVerifierBreaker.RecordFailure()
		ok, err := k.callRemoteAttestationVerifier(context.Background(), "https://attestation.example", sampleTEEAttestation())
		require.ErrorContains(t, err, "circuit open")
		require.False(t, ok)
	})

	t.Run("non-200 status returns error", func(t *testing.T) {
		withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(strings.NewReader(`unauthorized`)),
				Header:     make(http.Header),
			}, nil
		})

		k := Keeper{}
		ok, err := k.callRemoteAttestationVerifier(context.Background(), "https://attestation.example", sampleTEEAttestation())
		require.ErrorContains(t, err, "status 401")
		require.False(t, ok)
	})

	t.Run("decode failure", func(t *testing.T) {
		withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{bad-json`)),
				Header:     make(http.Header),
			}, nil
		})

		k := Keeper{}
		ok, err := k.callRemoteAttestationVerifier(context.Background(), "https://attestation.example", sampleTEEAttestation())
		require.ErrorContains(t, err, "decode")
		require.False(t, ok)
	})

	t.Run("explicit verifier error", func(t *testing.T) {
		withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"verified":false,"error":"invalid quote"}`)),
				Header:     make(http.Header),
			}, nil
		})

		k := Keeper{}
		ok, err := k.callRemoteAttestationVerifier(context.Background(), "https://attestation.example", sampleTEEAttestation())
		require.ErrorContains(t, err, "verification failed")
		require.False(t, ok)
	})

	t.Run("transport error", func(t *testing.T) {
		withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("network down")
		})

		k := Keeper{}
		ok, err := k.callRemoteAttestationVerifier(context.Background(), "https://attestation.example", sampleTEEAttestation())
		require.ErrorContains(t, err, "request failed")
		require.False(t, ok)
	})
}

