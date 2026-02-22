package app

import (
	"encoding/json"
	"net/http"
)

type consensusEvidenceAuditErrorResponse struct {
	Error string `json:"error"`
}

// ConsensusEvidenceAuditHandler exposes deterministic consensus evidence
// auditing for proposal preflight checks.
func (app *AethelredApp) ConsensusEvidenceAuditHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var req ConsensusEvidenceAuditRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeConsensusAuditError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		resp, err := RunConsensusEvidenceAudit(req)
		if err != nil {
			writeConsensusAuditError(w, http.StatusBadRequest, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
}

func writeConsensusAuditError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(consensusEvidenceAuditErrorResponse{Error: msg})
}
