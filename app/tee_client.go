package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"cosmossdk.io/log"

	"github.com/aethelred/aethelred/internal/circuitbreaker"
	"github.com/aethelred/aethelred/internal/httpclient"
)

// TEEClient provides an interface for communicating with Trusted Execution Environments.
// This is the primary integration boundary between the Go chain and external compute
// services. In production, this connects to a Rust-based TEE worker service
// (crates/aethelred-core) over HTTP/gRPC, NOT via FFI. The communication flow is:
//
//	Go Chain (app/abci.go) --> TEEClient (HTTP) --> Rust TEE Worker (crates/aethelred-core)
//	                                                    |
//	                                                    v
//	                                            AWS Nitro / Intel SGX Enclave
//
// Data contract: Shared protobuf types from proto/aethelred/pouw/v1/pouw.proto
// are compiled independently for Go (x/pouw/types) and Rust (crates/).
type TEEClient interface {
	// Execute runs a computation in the TEE and returns the result with attestation
	Execute(ctx context.Context, request *TEEExecutionRequest) (*TEEExecutionResult, error)

	// GetCapabilities returns the capabilities of this TEE client
	GetCapabilities() *TEECapabilities

	// IsHealthy checks if the TEE is operational
	IsHealthy(ctx context.Context) bool

	// Close closes the TEE client connection
	Close() error
}

// TEEExecutionRequest contains the parameters for TEE execution
type TEEExecutionRequest struct {
	// JobID is the compute job identifier
	JobID string

	// ModelHash identifies the model to execute
	ModelHash []byte

	// ModelURI is where to fetch the model (if not cached)
	ModelURI string

	// InputHash is the hash of the input data
	InputHash []byte

	// InputData is the actual input (or URI to fetch it)
	InputData []byte
	InputURI  string

	// Nonce for replay protection
	Nonce []byte

	// Timeout for execution
	Timeout time.Duration

	// RequireZKProof indicates if zkML proof should also be generated
	RequireZKProof bool

	// Metadata for additional parameters
	Metadata map[string]string
}

// TEEExecutionResult contains the result of TEE execution
type TEEExecutionResult struct {
	// JobID matches the request
	JobID string

	// Success indicates if execution succeeded
	Success bool

	// OutputHash is the SHA-256 of the output
	OutputHash []byte

	// Output is the actual computation output (may be encrypted)
	Output []byte

	// Attestation is the TEE attestation
	Attestation *TEEAttestationData

	// ZKProof is the optional zkML proof
	ZKProof *ZKProofData

	// ExecutionTimeMs is how long execution took
	ExecutionTimeMs int64

	// ErrorCode if execution failed
	ErrorCode ErrorCode

	// ErrorMessage if execution failed
	ErrorMessage string

	// GasUsed for metering (if applicable)
	GasUsed int64
}

// TEECapabilities describes what a TEE can do
type TEECapabilities struct {
	// Platform is the TEE type
	Platform string

	// SupportedModels lists model architectures supported
	SupportedModels []string

	// MaxModelSize in bytes
	MaxModelSize int64

	// MaxInputSize in bytes
	MaxInputSize int64

	// SupportsZKML indicates if zkML proof generation is supported
	SupportsZKML bool

	// SupportedProofSystems for zkML
	SupportedProofSystems []string

	// MemoryAvailable in bytes
	MemoryAvailable int64

	// GPUAvailable indicates if GPU is available
	GPUAvailable bool
}

// RemoteTEEClient implements TEEClient over HTTP for production deployments.
// This is the preferred integration point for real enclave workers.
type RemoteTEEClient struct {
	logger   log.Logger
	endpoint string
	client   *http.Client
	breaker  *circuitbreaker.Breaker
}

// NewRemoteTEEClient creates a new HTTP-based TEE client.
func NewRemoteTEEClient(logger log.Logger, endpoint string) (*RemoteTEEClient, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("remote TEE endpoint is required")
	}
	return &RemoteTEEClient{
		logger:   logger,
		endpoint: endpoint,
		breaker:  circuitbreaker.NewDefault("tee_remote_execute"),
		client: httpclient.NewPooledClient(httpclient.PoolConfig{
			Timeout:             60 * time.Second,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		}),
	}, nil
}

// Execute runs a computation via the remote TEE worker.
func (c *RemoteTEEClient) Execute(ctx context.Context, request *TEEExecutionRequest) (*TEEExecutionResult, error) {
	if c.breaker != nil && !c.breaker.Allow() {
		return nil, fmt.Errorf("TEE circuit open: remote execution disabled")
	}

	reqBody, err := json.Marshal(request)
	if err != nil {
		if c.breaker != nil {
			c.breaker.RecordFailure()
		}
		return nil, fmt.Errorf("failed to marshal TEE request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"/execute", bytes.NewReader(reqBody))
	if err != nil {
		if c.breaker != nil {
			c.breaker.RecordFailure()
		}
		return nil, fmt.Errorf("failed to create TEE request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		if c.breaker != nil {
			c.breaker.RecordFailure()
		}
		return nil, fmt.Errorf("TEE request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if c.breaker != nil {
			c.breaker.RecordFailure()
		}
		return nil, fmt.Errorf("TEE worker returned status %d", resp.StatusCode)
	}

	var result TEEExecutionResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		if c.breaker != nil {
			c.breaker.RecordFailure()
		}
		return nil, fmt.Errorf("failed to decode TEE response: %w", err)
	}

	if c.breaker != nil {
		c.breaker.RecordSuccess()
	}
	return &result, nil
}

// GetCapabilities returns the remote worker's capabilities.
func (c *RemoteTEEClient) GetCapabilities() *TEECapabilities {
	if c.breaker != nil && !c.breaker.Allow() {
		return &TEECapabilities{Platform: "remote"}
	}

	httpReq, err := http.NewRequest("GET", c.endpoint+"/capabilities", nil)
	if err != nil {
		if c.breaker != nil {
			c.breaker.RecordFailure()
		}
		c.logger.Warn("Failed to create capabilities request", "error", err)
		return &TEECapabilities{Platform: "remote"}
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		if c.breaker != nil {
			c.breaker.RecordFailure()
		}
		c.logger.Warn("Failed to fetch capabilities", "error", err)
		return &TEECapabilities{Platform: "remote"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if c.breaker != nil {
			c.breaker.RecordFailure()
		}
		return &TEECapabilities{Platform: "remote"}
	}

	var caps TEECapabilities
	if err := json.NewDecoder(resp.Body).Decode(&caps); err != nil {
		if c.breaker != nil {
			c.breaker.RecordFailure()
		}
		c.logger.Warn("Failed to decode capabilities", "error", err)
		return &TEECapabilities{Platform: "remote"}
	}

	if c.breaker != nil {
		c.breaker.RecordSuccess()
	}
	return &caps
}

// IsHealthy checks the remote worker health endpoint.
func (c *RemoteTEEClient) IsHealthy(ctx context.Context) bool {
	if c.breaker != nil && !c.breaker.Allow() {
		return false
	}

	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.endpoint+"/health", nil)
	if err != nil {
		if c.breaker != nil {
			c.breaker.RecordFailure()
		}
		return false
	}
	resp, err := c.client.Do(httpReq)
	if err != nil {
		if c.breaker != nil {
			c.breaker.RecordFailure()
		}
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		if c.breaker != nil {
			c.breaker.RecordSuccess()
		}
		return true
	}
	if c.breaker != nil {
		c.breaker.RecordFailure()
	}
	return false
}

// Close closes the client (no-op for HTTP).
func (c *RemoteTEEClient) Close() error {
	return nil
}

// Breaker exposes the circuit breaker for metrics.
func (c *RemoteTEEClient) Breaker() *circuitbreaker.Breaker {
	return c.breaker
}

// NitroEnclaveClient implements TEEClient for AWS Nitro Enclaves
type NitroEnclaveClient struct {
	logger     log.Logger
	endpoint   string
	enclaveID  string
	mu         sync.RWMutex
	isHealthy  bool
	lastHealth time.Time

	// Simulated state for MVP
	models map[string][]byte // modelHash -> model data (simulated)
}

// NewNitroEnclaveClient creates a new Nitro Enclave client
func NewNitroEnclaveClient(logger log.Logger, endpoint string) (*NitroEnclaveClient, error) {
	client := &NitroEnclaveClient{
		logger:    logger,
		endpoint:  endpoint,
		enclaveID: generateEnclaveID(),
		isHealthy: true,
		models:    make(map[string][]byte),
	}

	// In production: establish vsock connection to enclave
	logger.Info("Nitro Enclave client initialized",
		"endpoint", endpoint,
		"enclave_id", client.enclaveID,
	)

	return client, nil
}

// Execute runs a computation in the Nitro Enclave
func (c *NitroEnclaveClient) Execute(ctx context.Context, request *TEEExecutionRequest) (*TEEExecutionResult, error) {
	startTime := time.Now()

	c.logger.Info("Executing computation in Nitro Enclave",
		"job_id", request.JobID,
		"model_hash", hex.EncodeToString(request.ModelHash),
	)

	result := &TEEExecutionResult{
		JobID:   request.JobID,
		Success: false,
	}

	// Check health
	if !c.IsHealthy(ctx) {
		result.ErrorCode = ErrorCodeTEEFailure
		result.ErrorMessage = "TEE enclave not healthy"
		return result, nil
	}

	// Generate nonce if not provided
	nonce := request.Nonce
	if len(nonce) == 0 {
		nonce = make([]byte, 32)
		rand.Read(nonce)
	}

	// In production, this would:
	// 1. Send request to enclave via vsock
	// 2. Enclave loads model (if not cached)
	// 3. Enclave executes inference
	// 4. Enclave generates attestation document
	// 5. Return result with attestation

	// For MVP, simulate TEE execution
	outputHash, err := c.simulateExecution(request)
	if err != nil {
		result.ErrorCode = ErrorCodeInternalError
		result.ErrorMessage = err.Error()
		result.ExecutionTimeMs = time.Since(startTime).Milliseconds()
		return result, nil
	}

	// Generate attestation
	attestation := c.generateAttestation(request, outputHash, nonce)

	result.Success = true
	result.OutputHash = outputHash
	result.Attestation = attestation
	result.ExecutionTimeMs = time.Since(startTime).Milliseconds()

	// Generate zkML proof if requested
	if request.RequireZKProof {
		zkProof, err := c.generateZKProof(request, outputHash)
		if err != nil {
			c.logger.Warn("Failed to generate zkML proof", "error", err)
		} else {
			result.ZKProof = zkProof
		}
	}

	c.logger.Info("Computation completed",
		"job_id", request.JobID,
		"success", result.Success,
		"execution_time_ms", result.ExecutionTimeMs,
	)

	return result, nil
}

// simulateExecution simulates AI model execution for the MVP
// In production, this would be replaced with actual enclave execution
func (c *NitroEnclaveClient) simulateExecution(request *TEEExecutionRequest) ([]byte, error) {
	// For deterministic testing, derive output from input + model
	// This ensures all validators get the same result
	h := sha256.New()
	h.Write(request.ModelHash)
	h.Write(request.InputHash)
	// Add a deterministic "computation" factor
	h.Write([]byte("aethelred_compute_v1"))

	return h.Sum(nil), nil
}

// generateAttestation generates a Nitro Enclave attestation document
func (c *NitroEnclaveClient) generateAttestation(
	request *TEEExecutionRequest,
	outputHash []byte,
	nonce []byte,
) *TEEAttestationData {
	// Create user data binding (output hash + input hash + nonce)
	h := sha256.New()
	h.Write(outputHash)
	h.Write(request.InputHash)
	h.Write(nonce)
	userData := h.Sum(nil)

	// Generate simulated measurement (PCR values)
	// In production: actual PCR values from enclave
	measurement := make([]byte, 48) // PCR0 + PCR1 + PCR2
	copy(measurement, request.ModelHash)

	// Generate simulated quote
	// In production: actual attestation document from Nitro
	quote := c.generateSimulatedQuote(userData, measurement)

	return &TEEAttestationData{
		Platform:    "aws-nitro",
		EnclaveID:   c.enclaveID,
		Measurement: measurement,
		Quote:       quote,
		UserData:    userData,
		Timestamp:   time.Now().UTC(),
		Nonce:       nonce,
	}
}

// generateSimulatedQuote creates a simulated attestation quote
func (c *NitroEnclaveClient) generateSimulatedQuote(userData, measurement []byte) []byte {
	// In production: actual CBOR-encoded attestation document
	// For MVP: create a deterministic "quote" structure
	h := sha256.New()
	h.Write([]byte("nitro_attestation_v1"))
	h.Write([]byte(c.enclaveID))
	h.Write(measurement)
	h.Write(userData)
	h.Write([]byte(time.Now().UTC().Format(time.RFC3339)))

	// Simulated quote structure
	quote := make([]byte, 0, 256)
	quote = append(quote, []byte("NITRO")...) // Magic bytes
	quote = append(quote, byte(1))            // Version
	quote = append(quote, measurement...)     // Measurement
	quote = append(quote, userData...)        // User data
	quote = append(quote, h.Sum(nil)...)      // Signature placeholder

	return quote
}

// generateZKProof generates a zkML proof (simulated for MVP)
func (c *NitroEnclaveClient) generateZKProof(
	request *TEEExecutionRequest,
	outputHash []byte,
) (*ZKProofData, error) {
	// In production: call EZKL or other zkML prover

	// Generate simulated proof
	h := sha256.New()
	h.Write(request.ModelHash)
	h.Write(request.InputHash)
	h.Write(outputHash)
	h.Write([]byte("ezkl_proof_v1"))

	proofData := h.Sum(nil)

	// Verifying key hash (would be from registered key)
	vkHash := sha256.Sum256(request.ModelHash)

	return &ZKProofData{
		ProofSystem:      "ezkl",
		Proof:            proofData,
		PublicInputs:     append(request.InputHash, outputHash...),
		VerifyingKeyHash: vkHash[:],
		CircuitHash:      request.ModelHash,
		ProofSize:        int64(len(proofData)),
	}, nil
}

// GetCapabilities returns the capabilities of this TEE client
func (c *NitroEnclaveClient) GetCapabilities() *TEECapabilities {
	return &TEECapabilities{
		Platform:              "aws-nitro",
		SupportedModels:       []string{"onnx", "pytorch", "tensorflow"},
		MaxModelSize:          1024 * 1024 * 1024, // 1 GB
		MaxInputSize:          100 * 1024 * 1024,  // 100 MB
		SupportsZKML:          true,
		SupportedProofSystems: []string{"ezkl"},
		MemoryAvailable:       16 * 1024 * 1024 * 1024, // 16 GB
		GPUAvailable:          false,
	}
}

// IsHealthy checks if the enclave is operational
func (c *NitroEnclaveClient) IsHealthy(ctx context.Context) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Cache health check for 10 seconds
	if time.Since(c.lastHealth) < 10*time.Second {
		return c.isHealthy
	}

	// In production: actually ping the enclave
	// For MVP: always healthy
	return true
}

// Close closes the TEE client connection
func (c *NitroEnclaveClient) Close() error {
	c.logger.Info("Closing Nitro Enclave client")
	// In production: close vsock connection
	return nil
}

// generateEnclaveID generates a unique enclave identifier
func generateEnclaveID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("enclave-%s", hex.EncodeToString(b))
}

// MockTEEClient implements TEEClient for testing
type MockTEEClient struct {
	logger      log.Logger
	shouldFail  bool
	failureRate float64
	latencyMs   int64
	results     map[string]*TEEExecutionResult
	mu          sync.RWMutex
}

// NewMockTEEClient creates a mock TEE client for testing
func NewMockTEEClient(logger log.Logger) *MockTEEClient {
	return &MockTEEClient{
		logger:      logger,
		shouldFail:  false,
		failureRate: 0,
		latencyMs:   100,
		results:     make(map[string]*TEEExecutionResult),
	}
}

// SetFailure configures the mock to fail
func (m *MockTEEClient) SetFailure(fail bool, rate float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFail = fail
	m.failureRate = rate
}

// SetResult sets a predetermined result for a job
func (m *MockTEEClient) SetResult(jobID string, result *TEEExecutionResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.results[jobID] = result
}

// Execute implements TEEClient
func (m *MockTEEClient) Execute(ctx context.Context, request *TEEExecutionRequest) (*TEEExecutionResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Simulate latency
	time.Sleep(time.Duration(m.latencyMs) * time.Millisecond)

	// Check for predetermined result
	if result, ok := m.results[request.JobID]; ok {
		return result, nil
	}

	// Check for failure
	if m.shouldFail {
		return &TEEExecutionResult{
			JobID:        request.JobID,
			Success:      false,
			ErrorCode:    ErrorCodeTEEFailure,
			ErrorMessage: "mock TEE failure",
		}, nil
	}

	// Generate deterministic result
	h := sha256.New()
	h.Write(request.ModelHash)
	h.Write(request.InputHash)
	outputHash := h.Sum(nil)

	nonce := make([]byte, 32)
	rand.Read(nonce)

	return &TEEExecutionResult{
		JobID:      request.JobID,
		Success:    true,
		OutputHash: outputHash,
		Attestation: &TEEAttestationData{
			Platform:    "mock-tee",
			EnclaveID:   "mock-enclave-1",
			Measurement: request.ModelHash,
			Quote:       []byte("mock-quote"),
			Timestamp:   time.Now().UTC(),
			Nonce:       nonce,
		},
		ExecutionTimeMs: m.latencyMs,
	}, nil
}

// GetCapabilities implements TEEClient
func (m *MockTEEClient) GetCapabilities() *TEECapabilities {
	return &TEECapabilities{
		Platform:              "mock-tee",
		SupportedModels:       []string{"any"},
		MaxModelSize:          1024 * 1024 * 1024,
		MaxInputSize:          100 * 1024 * 1024,
		SupportsZKML:          true,
		SupportedProofSystems: []string{"ezkl", "risc0"},
		MemoryAvailable:       8 * 1024 * 1024 * 1024,
		GPUAvailable:          false,
	}
}

// IsHealthy implements TEEClient
func (m *MockTEEClient) IsHealthy(ctx context.Context) bool {
	return !m.shouldFail
}

// Close implements TEEClient
func (m *MockTEEClient) Close() error {
	return nil
}

// TEEClientFactory creates TEE clients based on platform
type TEEClientFactory struct {
	logger log.Logger
}

// NewTEEClientFactory creates a new factory
func NewTEEClientFactory(logger log.Logger) *TEEClientFactory {
	return &TEEClientFactory{logger: logger}
}

// Create creates a TEE client for the specified platform
func (f *TEEClientFactory) Create(platform string, config map[string]string) (TEEClient, error) {
	switch platform {
	case "aws-nitro", "nitro", "remote", "http":
		endpoint := config["endpoint"]
		if endpoint == "" {
			return nil, fmt.Errorf("remote TEE endpoint is required for platform %s", platform)
		}
		return NewRemoteTEEClient(f.logger, endpoint)

	case "nitro-simulated":
		endpoint := config["endpoint"]
		if endpoint == "" {
			endpoint = "simulated://nitro"
		}
		return NewNitroEnclaveClient(f.logger, endpoint)

	case "mock":
		return NewMockTEEClient(f.logger), nil

	default:
		return nil, fmt.Errorf("unsupported TEE platform: %s", platform)
	}
}
