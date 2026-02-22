package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aethelred/aethelred/x/verify/ezkl"
)

const (
	defaultListenAddr = ":8546"
)

type config struct {
	ListenAddr     string
	BackendURL     string
	AllowSimulated bool
	Timeout        time.Duration
}

type server struct {
	cfg    config
	client *http.Client
}

type simulatedProof struct {
	Version           string `json:"version"`
	RequestDigestHex  string `json:"request_digest_hex"`
	ModelCommitment   []byte `json:"model_commitment"`
	InputCommitment   []byte `json:"input_commitment"`
	OutputCommitment  []byte `json:"output_commitment"`
	VerifyingKeyHash  []byte `json:"verifying_key_hash"`
	GeneratedUnixNano int64  `json:"generated_unix_nano"`
}

type verifyRequest struct {
	Proof        []byte             `json:"proof"`
	PublicInputs *ezkl.PublicInputs `json:"public_inputs"`
	VerifyingKey []byte             `json:"verifying_key"`
}

func main() {
	cfg := loadConfig()
	srv := &server{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", srv.handleHealth)
	mux.HandleFunc("/prove", srv.handleProve)
	mux.HandleFunc("/verify", srv.handleVerify)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("starting zkML prover service on %s (simulated=%t backend=%q)", cfg.ListenAddr, cfg.AllowSimulated, cfg.BackendURL)

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("zkML prover server failed: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("zkML prover shutdown error: %v", err)
	}
}

func loadConfig() config {
	allowSimulated := envBool("AETHELRED_ALLOW_SIMULATED")
	if !allowSimulated {
		mode := strings.ToLower(strings.TrimSpace(os.Getenv("PROVER_MODE")))
		if mode == "development" || mode == "dev" || mode == "simulated" {
			allowSimulated = true
		}
	}
	timeout := 15 * time.Second
	if v := strings.TrimSpace(os.Getenv("AETHELRED_ZKML_TIMEOUT")); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil && parsed > 0 {
			timeout = parsed
		}
	}

	return config{
		ListenAddr:     envOrDefault("AETHELRED_ZKML_LISTEN_ADDR", defaultListenAddr),
		BackendURL:     strings.TrimRight(strings.TrimSpace(os.Getenv("AETHELRED_ZKML_BACKEND_URL")), "/"),
		AllowSimulated: allowSimulated,
		Timeout:        timeout,
	}
}

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	status := map[string]any{
		"service":         "aethelred-zkml-prover",
		"status":          "ok",
		"allow_simulated": s.cfg.AllowSimulated,
		"backend_url":     s.cfg.BackendURL != "",
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *server) handleProve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	if s.cfg.BackendURL != "" {
		s.proxy(w, r, "/prove", body)
		return
	}
	if !s.cfg.AllowSimulated {
		writeError(w, http.StatusServiceUnavailable, "zkML prover backend not configured and simulation disabled")
		return
	}

	var req ezkl.ProofRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid proof request")
		return
	}

	if len(req.ModelHash) == 0 || len(req.InputHash) == 0 || len(req.OutputHash) == 0 || len(req.CircuitHash) == 0 {
		writeError(w, http.StatusBadRequest, "proof request missing required hashes")
		return
	}

	start := time.Now()
	result, err := simulateProof(&req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	result.GenerationTimeMs = time.Since(start).Milliseconds()
	writeJSON(w, http.StatusOK, result)
}

func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	if s.cfg.BackendURL != "" {
		s.proxy(w, r, "/verify", body)
		return
	}
	if !s.cfg.AllowSimulated {
		writeError(w, http.StatusServiceUnavailable, "zkML verifier backend not configured and simulation disabled")
		return
	}

	var req verifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid verification request")
		return
	}

	verified, verifyErr := verifyProof(req.Proof, req.PublicInputs, req.VerifyingKey)
	resp := map[string]any{
		"verified": verified,
	}
	if verifyErr != "" {
		resp["error"] = verifyErr
	}
	writeJSON(w, http.StatusOK, resp)
}

func simulateProof(req *ezkl.ProofRequest) (*ezkl.ProofResult, error) {
	publicInputs := &ezkl.PublicInputs{
		ModelCommitment:  hashBytes(req.ModelHash),
		InputCommitment:  hashBytes(req.InputHash),
		OutputCommitment: hashBytes(req.OutputHash),
		Instances: [][]byte{
			req.InputHash,
			req.OutputHash,
		},
	}
	metadata := simulatedProof{
		Version:           "aethelred-zkml-sim-v1",
		RequestDigestHex:  fmt.Sprintf("%x", hashMany(req.ModelHash, req.InputHash, req.OutputHash, req.CircuitHash, req.VerifyingKeyHash)),
		ModelCommitment:   publicInputs.ModelCommitment,
		InputCommitment:   publicInputs.InputCommitment,
		OutputCommitment:  publicInputs.OutputCommitment,
		VerifyingKeyHash:  req.VerifyingKeyHash,
		GeneratedUnixNano: time.Now().UTC().UnixNano(),
	}
	proofBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal simulated proof: %w", err)
	}

	return &ezkl.ProofResult{
		Success:          true,
		Proof:            proofBytes,
		PublicInputs:     publicInputs,
		VerifyingKeyHash: req.VerifyingKeyHash,
		CircuitHash:      req.CircuitHash,
		ProofSize:        int64(len(proofBytes)),
		Timestamp:        time.Now().UTC(),
		RequestID:        req.RequestID,
	}, nil
}

func verifyProof(proof []byte, publicInputs *ezkl.PublicInputs, verifyingKey []byte) (bool, string) {
	if len(proof) == 0 {
		return false, "empty proof"
	}
	if publicInputs == nil {
		return false, "missing public_inputs"
	}

	var parsed simulatedProof
	if err := json.Unmarshal(proof, &parsed); err != nil {
		return false, "invalid proof encoding"
	}
	if parsed.Version != "aethelred-zkml-sim-v1" {
		return false, "unsupported proof version"
	}
	if !bytes.Equal(publicInputs.ModelCommitment, parsed.ModelCommitment) {
		return false, "model commitment mismatch"
	}
	if !bytes.Equal(publicInputs.InputCommitment, parsed.InputCommitment) {
		return false, "input commitment mismatch"
	}
	if !bytes.Equal(publicInputs.OutputCommitment, parsed.OutputCommitment) {
		return false, "output commitment mismatch"
	}
	if len(parsed.VerifyingKeyHash) > 0 {
		if !bytes.Equal(hashBytes(verifyingKey), parsed.VerifyingKeyHash) {
			return false, "verifying key mismatch"
		}
	}
	return true, ""
}

func (s *server) proxy(w http.ResponseWriter, r *http.Request, path string, body []byte) {
	target := s.cfg.BackendURL + path
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to build backend request")
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "backend request failed")
		return
	}
	defer resp.Body.Close()

	for k, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func hashBytes(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func hashMany(chunks ...[]byte) []byte {
	h := sha256.New()
	for _, c := range chunks {
		if len(c) > 0 {
			_, _ = h.Write(c)
		}
	}
	return h.Sum(nil)
}
