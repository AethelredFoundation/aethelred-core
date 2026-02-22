package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConsensusEvidenceAuditHandler_MethodNotAllowed(t *testing.T) {
	handler := (&AethelredApp{}).ConsensusEvidenceAuditHandler()
	req := httptest.NewRequest(http.MethodGet, "/admin/consensus/evidence/audit", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestConsensusEvidenceAuditHandler_Post(t *testing.T) {
	reqPayload := ConsensusEvidenceAuditRequest{
		ConsensusThreshold: 67,
		ProposedLastCommit: testConsensusAuditCommit(),
		Txs: []json.RawMessage{
			mustMarshalRawJSON(t, map[string]interface{}{
				"type":            "create_seal_from_consensus",
				"job_id":          "job-handler-ok",
				"output_hash":     make32Bytes(),
				"validator_count": 2,
				"total_votes":     2,
				"agreement_power": 2,
				"total_power":     2,
			}),
		},
	}
	body, err := json.Marshal(reqPayload)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	handler := (&AethelredApp{}).ConsensusEvidenceAuditHandler()
	req := httptest.NewRequest(http.MethodPost, "/admin/consensus/evidence/audit", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var resp ConsensusEvidenceAuditResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Passed {
		t.Fatalf("expected audit pass, got %+v", resp)
	}
}

func TestConsensusEvidenceAuditHandler_InvalidRequestBody(t *testing.T) {
	handler := (&AethelredApp{}).ConsensusEvidenceAuditHandler()
	req := httptest.NewRequest(http.MethodPost, "/admin/consensus/evidence/audit", strings.NewReader("{"))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestConsensusEvidenceAuditHandler_InvalidTxPayload(t *testing.T) {
	body := `{
		"consensus_threshold": 67,
		"proposed_last_commit": {},
		"txs": ["%%%"]
	}`

	handler := (&AethelredApp{}).ConsensusEvidenceAuditHandler()
	req := httptest.NewRequest(http.MethodPost, "/admin/consensus/evidence/audit", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}
