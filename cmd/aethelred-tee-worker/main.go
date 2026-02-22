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

	"github.com/aethelred/aethelred/x/verify/tee"
)

const defaultListenAddr = ":8545"

type config struct {
	ListenAddr         string
	BackendURL         string
	AllowSimulated     bool
	Platform           string
	EnclaveID          string
	MaxAttestationAge  time.Duration
	Timeout            time.Duration
	SupportsZKProofGen bool
}

type server struct {
	cfg    config
	client *http.Client
}

type appExecutionRequest struct {
	JobID          string            `json:"JobID"`
	ModelHash      []byte            `json:"ModelHash"`
	ModelURI       string            `json:"ModelURI"`
	InputHash      []byte            `json:"InputHash"`
	InputData      []byte            `json:"InputData"`
	InputURI       string            `json:"InputURI"`
	Nonce          []byte            `json:"Nonce"`
	RequireZKProof bool              `json:"RequireZKProof"`
	Metadata       map[string]string `json:"Metadata"`
}

type appExecutionResult struct {
	JobID           string             `json:"JobID"`
	Success         bool               `json:"Success"`
	OutputHash      []byte             `json:"OutputHash"`
	Output          []byte             `json:"Output"`
	Attestation     *appTEEAttestation `json:"Attestation,omitempty"`
	ZKProof         *appZKProof        `json:"ZKProof,omitempty"`
	ExecutionTimeMs int64              `json:"ExecutionTimeMs"`
	ErrorCode       string             `json:"ErrorCode,omitempty"`
	ErrorMessage    string             `json:"ErrorMessage,omitempty"`
	GasUsed         int64              `json:"GasUsed"`
}

type appTEEAttestation struct {
	Platform         string    `json:"platform"`
	EnclaveID        string    `json:"enclave_id"`
	Measurement      []byte    `json:"measurement"`
	Quote            []byte    `json:"quote"`
	UserData         []byte    `json:"user_data"`
	CertificateChain [][]byte  `json:"certificate_chain,omitempty"`
	Timestamp        time.Time `json:"timestamp"`
	Nonce            []byte    `json:"nonce"`
}

type appZKProof struct {
	ProofSystem      string `json:"proof_system"`
	Proof            []byte `json:"proof"`
	PublicInputs     []byte `json:"public_inputs"`
	VerifyingKeyHash []byte `json:"verifying_key_hash"`
	CircuitHash      []byte `json:"circuit_hash"`
	ProofSize        int64  `json:"proof_size"`
}

type appCapabilities struct {
	Platform              string   `json:"Platform"`
	SupportedModels       []string `json:"SupportedModels"`
	MaxModelSize          int64    `json:"MaxModelSize"`
	MaxInputSize          int64    `json:"MaxInputSize"`
	SupportsZKML          bool     `json:"SupportsZKML"`
	SupportedProofSystems []string `json:"SupportedProofSystems"`
	MemoryAvailable       int64    `json:"MemoryAvailable"`
	GPUAvailable          bool     `json:"GPUAvailable"`
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
	mux.HandleFunc("/capabilities", srv.handleCapabilities)
	mux.HandleFunc("/execute", srv.handleExecute)
	mux.HandleFunc("/verify", srv.handleVerify)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("starting tee worker on %s (simulated=%t backend=%q)", cfg.ListenAddr, cfg.AllowSimulated, cfg.BackendURL)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("tee worker server failed: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("tee worker shutdown error: %v", err)
	}
}

func loadConfig() config {
	allowSimulated := envBool("AETHELRED_ALLOW_SIMULATED")
	if !allowSimulated {
		mode := strings.ToLower(strings.TrimSpace(os.Getenv("TEE_MODE")))
		switch mode {
		case "mock", "simulated", "nitro-simulated":
			allowSimulated = true
		}
	}

	timeout := 15 * time.Second
	if v := strings.TrimSpace(os.Getenv("AETHELRED_TEE_TIMEOUT")); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil && parsed > 0 {
			timeout = parsed
		}
	}

	maxAge := 5 * time.Minute
	if v := strings.TrimSpace(os.Getenv("AETHELRED_TEE_MAX_ATTESTATION_AGE")); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil && parsed > 0 {
			maxAge = parsed
		}
	}

	return config{
		ListenAddr:         envOrDefault("AETHELRED_TEE_LISTEN_ADDR", defaultListenAddr),
		BackendURL:         strings.TrimRight(strings.TrimSpace(os.Getenv("AETHELRED_TEE_BACKEND_URL")), "/"),
		AllowSimulated:     allowSimulated,
		Platform:           envOrDefault("AETHELRED_TEE_PLATFORM", "aws-nitro"),
		EnclaveID:          envOrDefault("AETHELRED_TEE_ENCLAVE_ID", "aethelred-tee-worker"),
		MaxAttestationAge:  maxAge,
		Timeout:            timeout,
		SupportsZKProofGen: envBool("AETHELRED_TEE_SUPPORTS_ZKML"),
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

	writeJSON(w, http.StatusOK, map[string]any{
		"service":         "aethelred-tee-worker",
		"status":          "ok",
		"platform":        s.cfg.Platform,
		"allow_simulated": s.cfg.AllowSimulated,
		"backend_url":     s.cfg.BackendURL != "",
	})
}

func (s *server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	caps := appCapabilities{
		Platform:              s.cfg.Platform,
		SupportedModels:       []string{"onnx", "torchscript"},
		MaxModelSize:          2 << 30,
		MaxInputSize:          8 << 20,
		SupportsZKML:          s.cfg.SupportsZKProofGen,
		SupportedProofSystems: []string{"ezkl"},
		MemoryAvailable:       8 << 30,
		GPUAvailable:          false,
	}
	writeJSON(w, http.StatusOK, caps)
}

func (s *server) handleExecute(w http.ResponseWriter, r *http.Request) {
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
		s.proxy(w, r, "/execute", body)
		return
	}
	if !s.cfg.AllowSimulated {
		writeError(w, http.StatusServiceUnavailable, "TEE backend not configured and simulation disabled")
		return
	}

	isEnclaveReq, err := looksLikeEnclaveRequest(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if isEnclaveReq {
		var req tee.EnclaveExecutionRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid enclave execution request")
			return
		}
		result := s.simulateEnclaveExecution(&req)
		writeJSON(w, http.StatusOK, result)
		return
	}

	var req appExecutionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid TEE execution request")
		return
	}
	result := s.simulateAppExecution(&req)
	writeJSON(w, http.StatusOK, result)
}

func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	if s.cfg.BackendURL != "" {
		s.proxy(w, r, "/verify", body)
		return
	}
	if !s.cfg.AllowSimulated {
		writeError(w, http.StatusServiceUnavailable, "attestation verifier backend not configured and simulation disabled")
		return
	}

	var doc tee.NitroAttestationDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		writeError(w, http.StatusBadRequest, "invalid attestation document")
		return
	}

	verified, verifyErr := s.verifyAttestation(&doc)
	resp := map[string]any{
		"verified": verified,
	}
	if verifyErr != "" {
		resp["error"] = verifyErr
	}
	writeJSON(w, http.StatusOK, resp)
}

func looksLikeEnclaveRequest(body []byte) (bool, error) {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return false, err
	}
	if _, ok := payload["request_id"]; ok {
		return true, nil
	}
	if _, ok := payload["RequestID"]; ok {
		return true, nil
	}
	if _, ok := payload["JobID"]; ok {
		return false, nil
	}
	return false, nil
}

func (s *server) simulateEnclaveExecution(req *tee.EnclaveExecutionRequest) *tee.EnclaveExecutionResult {
	start := time.Now()
	requestID := req.RequestID
	if requestID == "" {
		requestID = fmt.Sprintf("auto-%d", start.UnixNano())
	}

	outputData := []byte(fmt.Sprintf(`{"request_id":"%s","worker":"%s"}`, requestID, s.cfg.EnclaveID))
	outputHash := hashMany(req.ModelHash, req.InputHash, req.InputData, req.Nonce, outputData)
	pcr0 := hashMany([]byte(s.cfg.EnclaveID), []byte("pcr0"))
	pcr1 := hashMany([]byte(s.cfg.EnclaveID), []byte("pcr1"))
	pcr2 := hashMany([]byte(s.cfg.EnclaveID), []byte("pcr2"))

	result := &tee.EnclaveExecutionResult{
		RequestID:       requestID,
		Success:         true,
		OutputData:      outputData,
		OutputHash:      outputHash,
		ExecutionTimeMs: time.Since(start).Milliseconds(),
		AttestationDocument: &tee.NitroAttestationDocument{
			ModuleID:  s.cfg.EnclaveID,
			Timestamp: time.Now().UTC(),
			Digest:    "SHA256",
			PCRs: map[int][]byte{
				0: pcr0,
				1: pcr1,
				2: pcr2,
			},
			UserData: outputHash,
			Nonce:    req.Nonce,
		},
	}
	if !req.GenerateAttestation {
		result.AttestationDocument = nil
	}
	return result
}

func (s *server) simulateAppExecution(req *appExecutionRequest) *appExecutionResult {
	start := time.Now()
	output := []byte(fmt.Sprintf(`{"job_id":"%s","status":"ok","worker":"%s"}`, req.JobID, s.cfg.EnclaveID))
	outputHash := hashMany(req.ModelHash, req.InputHash, req.InputData, req.Nonce, output)

	attestation := &appTEEAttestation{
		Platform:    s.cfg.Platform,
		EnclaveID:   s.cfg.EnclaveID,
		Measurement: hashMany([]byte(s.cfg.EnclaveID), []byte("measurement")),
		Quote:       hashMany([]byte("quote"), outputHash),
		UserData:    outputHash,
		Timestamp:   time.Now().UTC(),
		Nonce:       req.Nonce,
	}

	result := &appExecutionResult{
		JobID:           req.JobID,
		Success:         true,
		OutputHash:      outputHash,
		Output:          output,
		Attestation:     attestation,
		ExecutionTimeMs: time.Since(start).Milliseconds(),
		GasUsed:         1000,
	}
	if req.RequireZKProof && s.cfg.SupportsZKProofGen {
		proof := hashMany(outputHash, []byte("zk-proof"))
		result.ZKProof = &appZKProof{
			ProofSystem:      "ezkl",
			Proof:            proof,
			PublicInputs:     outputHash,
			VerifyingKeyHash: hashMany([]byte("vk"), req.ModelHash),
			CircuitHash:      hashMany([]byte("circuit"), req.ModelHash),
			ProofSize:        int64(len(proof)),
		}
	}
	return result
}

func (s *server) verifyAttestation(doc *tee.NitroAttestationDocument) (bool, string) {
	if doc.ModuleID == "" {
		return false, "module_id is required"
	}
	if doc.Timestamp.IsZero() {
		return false, "timestamp is required"
	}
	if len(doc.UserData) == 0 {
		return false, "user_data is required"
	}
	age := time.Since(doc.Timestamp)
	if age < 0 {
		age = -age
	}
	if age > s.cfg.MaxAttestationAge {
		return false, "attestation outside allowed age window"
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

func hashMany(chunks ...[]byte) []byte {
	h := sha256.New()
	for _, c := range chunks {
		if len(c) > 0 {
			_, _ = h.Write(c)
		}
	}
	return h.Sum(nil)
}
