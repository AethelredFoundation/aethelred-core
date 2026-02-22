package keeper

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aethelred/aethelred/x/verify/types"
)

// verifierResponse is the standard response format returned by both
// the ZK verifier and the attestation verifier services.
type verifierResponse struct {
	Verified bool   `json:"verified"`
	Error    string `json:"error,omitempty"`
}

// zkVerifierRequest is the expected request payload sent to the ZK verifier.
type zkVerifierRequest struct {
	Proof        *types.ZKMLProof    `json:"proof"`
	VerifyingKey *types.VerifyingKey `json:"verifying_key"`
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newZeroKeeper returns a zero-value Keeper suitable for calling the remote
// HTTP verifier methods, which do not access store state.
func newZeroKeeper() Keeper {
	return Keeper{}
}

// newLocalTestServer starts an httptest server bound to 127.0.0.1.
// If the environment blocks opening local sockets (e.g., sandbox restrictions),
// it skips the test instead of failing.
func newLocalTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping: cannot listen on localhost (sandbox restriction): %v", err)
	}

	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	return server
}

// sampleZKProof returns a minimal ZKMLProof for testing.
func sampleZKProof() *types.ZKMLProof {
	return &types.ZKMLProof{
		ProofSystem:      "ezkl",
		ProofBytes:       []byte("fake-proof-bytes"),
		PublicInputs:     []byte("fake-public-inputs"),
		VerifyingKeyHash: make([]byte, 32),
		CircuitHash:      make([]byte, 32),
	}
}

// sampleVerifyingKey returns a minimal VerifyingKey for testing.
func sampleVerifyingKey() *types.VerifyingKey {
	return &types.VerifyingKey{
		Hash:         make([]byte, 32),
		KeyBytes:     []byte("fake-key-bytes"),
		ProofSystem:  "ezkl",
		IsActive:     true,
		RegisteredBy: "cosmos1test",
	}
}

// sampleTEEAttestation returns a minimal TEEAttestation for testing.
func sampleTEEAttestation() *types.TEEAttestation {
	return &types.TEEAttestation{
		Platform:    types.TEEPlatformAWSNitro,
		EnclaveId:   "test-enclave-001",
		Measurement: []byte("fake-measurement"),
		Quote:       []byte("fake-quote"),
		UserData:    []byte("fake-user-data"),
		Nonce:       []byte("fake-nonce"),
	}
}

// ---------------------------------------------------------------------------
// Tests for callRemoteZKVerifier
// ---------------------------------------------------------------------------

func TestCallRemoteZKVerifier_Success(t *testing.T) {
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate request method and path.
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/verify" {
			t.Errorf("expected path /verify, got %s", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}

		// Validate request body can be decoded.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		var req zkVerifierRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("failed to unmarshal request body: %v", err)
		}
		if req.Proof == nil {
			t.Error("expected proof in request body")
		}
		if req.VerifyingKey == nil {
			t.Error("expected verifying_key in request body")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verifierResponse{Verified: true})
	}))
	defer server.Close()

	k := newZeroKeeper()
	verified, err := k.callRemoteZKVerifier(context.Background(), server.URL, sampleZKProof(), sampleVerifyingKey())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Error("expected verified to be true")
	}
}

func TestCallRemoteZKVerifier_FailedVerification(t *testing.T) {
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verifierResponse{
			Verified: false,
			Error:    "invalid proof",
		})
	}))
	defer server.Close()

	k := newZeroKeeper()
	verified, err := k.callRemoteZKVerifier(context.Background(), server.URL, sampleZKProof(), sampleVerifyingKey())
	if err == nil {
		t.Fatal("expected error for failed verification, got nil")
	}
	if verified {
		t.Error("expected verified to be false")
	}
	if err.Error() != "verification failed: invalid proof" {
		t.Errorf("expected error message 'verification failed: invalid proof', got '%s'", err.Error())
	}
}

func TestCallRemoteZKVerifier_ServerError500(t *testing.T) {
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	k := newZeroKeeper()
	verified, err := k.callRemoteZKVerifier(context.Background(), server.URL, sampleZKProof(), sampleVerifyingKey())
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
	if verified {
		t.Error("expected verified to be false")
	}
	// The error should mention the status code.
	if got := err.Error(); !containsSubstring(got, "500") {
		t.Errorf("expected error to mention status 500, got '%s'", got)
	}
}

func TestCallRemoteZKVerifier_MalformedJSON(t *testing.T) {
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{not valid json"))
	}))
	defer server.Close()

	k := newZeroKeeper()
	verified, err := k.callRemoteZKVerifier(context.Background(), server.URL, sampleZKProof(), sampleVerifyingKey())
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
	if verified {
		t.Error("expected verified to be false")
	}
	if got := err.Error(); !containsSubstring(got, "decode") {
		t.Errorf("expected error to mention decoding, got '%s'", got)
	}
}

func TestCallRemoteZKVerifier_Timeout(t *testing.T) {
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow server that takes longer than the context deadline.
		time.Sleep(2 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verifierResponse{Verified: true})
	}))
	defer server.Close()

	k := newZeroKeeper()

	// Create a context with a very short timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	verified, err := k.callRemoteZKVerifier(ctx, server.URL, sampleZKProof(), sampleVerifyingKey())
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if verified {
		t.Error("expected verified to be false on timeout")
	}
}

func TestCallRemoteZKVerifier_VerifiedTrueWithErrorField(t *testing.T) {
	// When the server returns verified=true but also sets an error field,
	// the keeper should treat it as a success because the condition in the
	// code is: if result.Error != "" && !result.Verified => return error.
	// When verified=true, the error field is ignored.
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verifierResponse{
			Verified: true,
			Error:    "some warning, but proof is valid",
		})
	}))
	defer server.Close()

	k := newZeroKeeper()
	verified, err := k.callRemoteZKVerifier(context.Background(), server.URL, sampleZKProof(), sampleVerifyingKey())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Error("expected verified to be true when server returns verified=true even with error field")
	}
}

func TestCallRemoteZKVerifier_VerifiedFalseNoError(t *testing.T) {
	// When verified=false and error is empty, the method should return
	// false with no error (the condition result.Error != "" && !result.Verified
	// is not met because Error is empty).
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verifierResponse{Verified: false})
	}))
	defer server.Close()

	k := newZeroKeeper()
	verified, err := k.callRemoteZKVerifier(context.Background(), server.URL, sampleZKProof(), sampleVerifyingKey())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Error("expected verified to be false")
	}
}

func TestCallRemoteZKVerifier_EmptyResponseBody(t *testing.T) {
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Intentionally write nothing.
	}))
	defer server.Close()

	k := newZeroKeeper()
	verified, err := k.callRemoteZKVerifier(context.Background(), server.URL, sampleZKProof(), sampleVerifyingKey())
	if err == nil {
		t.Fatal("expected error for empty response body, got nil")
	}
	if verified {
		t.Error("expected verified to be false")
	}
}

func TestCallRemoteZKVerifier_RequestPayloadFormat(t *testing.T) {
	// Verify that the request payload matches the expected JSON contract.
	var receivedPayload []byte

	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedPayload, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verifierResponse{Verified: true})
	}))
	defer server.Close()

	k := newZeroKeeper()
	_, _ = k.callRemoteZKVerifier(context.Background(), server.URL, sampleZKProof(), sampleVerifyingKey())

	// Verify the payload has the expected top-level keys.
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(receivedPayload, &payload); err != nil {
		t.Fatalf("received payload is not valid JSON: %v", err)
	}
	if _, ok := payload["proof"]; !ok {
		t.Error("expected 'proof' key in request payload")
	}
	if _, ok := payload["verifying_key"]; !ok {
		t.Error("expected 'verifying_key' key in request payload")
	}
}

// ---------------------------------------------------------------------------
// Tests for callRemoteAttestationVerifier
// ---------------------------------------------------------------------------

func TestCallRemoteAttestationVerifier_Success(t *testing.T) {
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/verify" {
			t.Errorf("expected path /verify, got %s", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}

		// Validate request body can be decoded as a TEEAttestation.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		var att types.TEEAttestation
		if err := json.Unmarshal(body, &att); err != nil {
			t.Fatalf("failed to unmarshal attestation body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verifierResponse{Verified: true})
	}))
	defer server.Close()

	k := newZeroKeeper()
	verified, err := k.callRemoteAttestationVerifier(context.Background(), server.URL, sampleTEEAttestation())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Error("expected verified to be true")
	}
}

func TestCallRemoteAttestationVerifier_FailedVerification(t *testing.T) {
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verifierResponse{
			Verified: false,
			Error:    "attestation signature invalid",
		})
	}))
	defer server.Close()

	k := newZeroKeeper()
	verified, err := k.callRemoteAttestationVerifier(context.Background(), server.URL, sampleTEEAttestation())
	if err == nil {
		t.Fatal("expected error for failed attestation verification, got nil")
	}
	if verified {
		t.Error("expected verified to be false")
	}
	if err.Error() != "attestation verification failed: attestation signature invalid" {
		t.Errorf("expected error message 'attestation verification failed: attestation signature invalid', got '%s'", err.Error())
	}
}

func TestCallRemoteAttestationVerifier_ServerError(t *testing.T) {
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("bad gateway"))
	}))
	defer server.Close()

	k := newZeroKeeper()
	verified, err := k.callRemoteAttestationVerifier(context.Background(), server.URL, sampleTEEAttestation())
	if err == nil {
		t.Fatal("expected error for 502 response, got nil")
	}
	if verified {
		t.Error("expected verified to be false")
	}
	if got := err.Error(); !containsSubstring(got, "502") {
		t.Errorf("expected error to mention status 502, got '%s'", got)
	}
}

func TestCallRemoteAttestationVerifier_MalformedJSON(t *testing.T) {
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<<<not json>>>"))
	}))
	defer server.Close()

	k := newZeroKeeper()
	verified, err := k.callRemoteAttestationVerifier(context.Background(), server.URL, sampleTEEAttestation())
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
	if verified {
		t.Error("expected verified to be false")
	}
	if got := err.Error(); !containsSubstring(got, "decode") {
		t.Errorf("expected error to mention decoding, got '%s'", got)
	}
}

func TestCallRemoteAttestationVerifier_ConnectionRefused(t *testing.T) {
	// Use a URL pointing to a port that is not listening. Port 0 is a common
	// trick but on most systems connecting to 127.0.0.1:1 will be refused.
	// We start and immediately close a server to guarantee the port is unused.
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := server.URL
	server.Close() // Port is now closed.

	k := newZeroKeeper()
	verified, err := k.callRemoteAttestationVerifier(context.Background(), closedURL, sampleTEEAttestation())
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
	if verified {
		t.Error("expected verified to be false on connection refused")
	}
}

func TestCallRemoteAttestationVerifier_VerifiedTrueWithErrorField(t *testing.T) {
	// Similar to the ZK verifier test: verified=true with an error field
	// should still succeed because the condition is:
	// if result.Error != "" && !result.Verified => return error.
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verifierResponse{
			Verified: true,
			Error:    "non-critical warning",
		})
	}))
	defer server.Close()

	k := newZeroKeeper()
	verified, err := k.callRemoteAttestationVerifier(context.Background(), server.URL, sampleTEEAttestation())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Error("expected verified to be true")
	}
}

func TestCallRemoteAttestationVerifier_Timeout(t *testing.T) {
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verifierResponse{Verified: true})
	}))
	defer server.Close()

	k := newZeroKeeper()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	verified, err := k.callRemoteAttestationVerifier(ctx, server.URL, sampleTEEAttestation())
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if verified {
		t.Error("expected verified to be false on timeout")
	}
}

func TestCallRemoteAttestationVerifier_EmptyResponseBody(t *testing.T) {
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Empty body.
	}))
	defer server.Close()

	k := newZeroKeeper()
	verified, err := k.callRemoteAttestationVerifier(context.Background(), server.URL, sampleTEEAttestation())
	if err == nil {
		t.Fatal("expected error for empty response body, got nil")
	}
	if verified {
		t.Error("expected verified to be false")
	}
}

func TestCallRemoteAttestationVerifier_RequestPayloadContainsAttestation(t *testing.T) {
	var receivedPayload []byte

	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedPayload, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verifierResponse{Verified: true})
	}))
	defer server.Close()

	k := newZeroKeeper()
	_, _ = k.callRemoteAttestationVerifier(context.Background(), server.URL, sampleTEEAttestation())

	// Verify the payload can be unmarshaled as a TEEAttestation.
	var att types.TEEAttestation
	if err := json.Unmarshal(receivedPayload, &att); err != nil {
		t.Fatalf("received payload is not valid TEEAttestation JSON: %v", err)
	}
	if att.EnclaveId != "test-enclave-001" {
		t.Errorf("expected enclave_id 'test-enclave-001', got '%s'", att.EnclaveId)
	}
}

// ---------------------------------------------------------------------------
// Tests for URL path construction
// ---------------------------------------------------------------------------

func TestCallRemoteZKVerifier_EndpointTrailingSlash(t *testing.T) {
	// The endpoint has a trailing slash; the method should still build
	// the correct URL: endpoint + "/verify" without double slashes.
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify" {
			t.Errorf("expected path /verify, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verifierResponse{Verified: true})
	}))
	defer server.Close()

	k := newZeroKeeper()
	// Pass endpoint with trailing slash.
	verified, err := k.callRemoteZKVerifier(context.Background(), server.URL+"/", sampleZKProof(), sampleVerifyingKey())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Error("expected verified to be true")
	}
}

func TestCallRemoteAttestationVerifier_EndpointTrailingSlash(t *testing.T) {
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify" {
			t.Errorf("expected path /verify, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verifierResponse{Verified: true})
	}))
	defer server.Close()

	k := newZeroKeeper()
	verified, err := k.callRemoteAttestationVerifier(context.Background(), server.URL+"/", sampleTEEAttestation())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Error("expected verified to be true")
	}
}

// ---------------------------------------------------------------------------
// Tests for various HTTP status codes
// ---------------------------------------------------------------------------

func TestCallRemoteZKVerifier_StatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"BadRequest", http.StatusBadRequest},
		{"Unauthorized", http.StatusUnauthorized},
		{"Forbidden", http.StatusForbidden},
		{"NotFound", http.StatusNotFound},
		{"ServiceUnavailable", http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte("error response"))
			}))
			defer server.Close()

			k := newZeroKeeper()
			verified, err := k.callRemoteZKVerifier(context.Background(), server.URL, sampleZKProof(), sampleVerifyingKey())
			if err == nil {
				t.Fatalf("expected error for status %d, got nil", tt.statusCode)
			}
			if verified {
				t.Error("expected verified to be false")
			}
		})
	}
}

func TestCallRemoteAttestationVerifier_StatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"BadRequest", http.StatusBadRequest},
		{"Unauthorized", http.StatusUnauthorized},
		{"Forbidden", http.StatusForbidden},
		{"NotFound", http.StatusNotFound},
		{"ServiceUnavailable", http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte("error response"))
			}))
			defer server.Close()

			k := newZeroKeeper()
			verified, err := k.callRemoteAttestationVerifier(context.Background(), server.URL, sampleTEEAttestation())
			if err == nil {
				t.Fatalf("expected error for status %d, got nil", tt.statusCode)
			}
			if verified {
				t.Error("expected verified to be false")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

// containsSubstring reports whether s contains substr. This avoids importing
// the strings package just for one helper in tests.
func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
