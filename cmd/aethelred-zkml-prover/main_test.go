package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aethelred/aethelred/x/verify/ezkl"
)

func TestHandleProveFailClosedWhenSimulationDisabled(t *testing.T) {
	s := &server{cfg: config{AllowSimulated: false}}
	reqBody, _ := json.Marshal(ezkl.ProofRequest{
		ModelHash:   []byte("model"),
		InputHash:   []byte("input"),
		OutputHash:  []byte("output"),
		CircuitHash: []byte("circuit"),
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/prove", bytes.NewReader(reqBody))
	s.handleProve(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}
}

func TestSimulatedProveAndVerify(t *testing.T) {
	s := &server{cfg: config{AllowSimulated: true}}
	verifyingKey := []byte("verifying-key")
	reqBody, _ := json.Marshal(ezkl.ProofRequest{
		RequestID:        "req-1",
		ModelHash:        []byte("model"),
		InputHash:        []byte("input"),
		OutputHash:       []byte("output"),
		CircuitHash:      []byte("circuit"),
		VerifyingKeyHash: hashBytes(verifyingKey),
	})

	proveRec := httptest.NewRecorder()
	proveReq := httptest.NewRequest(http.MethodPost, "/prove", bytes.NewReader(reqBody))
	s.handleProve(proveRec, proveReq)
	if proveRec.Code != http.StatusOK {
		t.Fatalf("expected prove status %d, got %d", http.StatusOK, proveRec.Code)
	}

	var proveResp ezkl.ProofResult
	if err := json.Unmarshal(proveRec.Body.Bytes(), &proveResp); err != nil {
		t.Fatalf("failed to decode prove response: %v", err)
	}
	if !proveResp.Success {
		t.Fatalf("expected proof success")
	}
	if len(proveResp.Proof) == 0 {
		t.Fatalf("expected non-empty proof bytes")
	}

	verifyBody, _ := json.Marshal(verifyRequest{
		Proof:        proveResp.Proof,
		PublicInputs: proveResp.PublicInputs,
		VerifyingKey: verifyingKey,
	})
	verifyRec := httptest.NewRecorder()
	verifyReq := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(verifyBody))
	s.handleVerify(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("expected verify status %d, got %d", http.StatusOK, verifyRec.Code)
	}

	var verifyResp map[string]any
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("failed to decode verify response: %v", err)
	}
	if verified, ok := verifyResp["verified"].(bool); !ok || !verified {
		t.Fatalf("expected verified=true, got %v", verifyResp["verified"])
	}
}
