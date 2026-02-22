package ezkl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"cosmossdk.io/log"
	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/aethelred/aethelred/internal/circuitbreaker"
	"github.com/aethelred/aethelred/internal/httpclient"
)

// ProverService provides EZKL zkML proof generation capabilities
// In production, this would communicate with a dedicated EZKL prover node
// or execute EZKL directly in a TEE
type ProverService struct {
	logger log.Logger
	config ProverConfig
	client *http.Client

	// Circuit cache for faster proving
	circuitCache *lru.Cache[string, *CachedCircuit]
	cacheMutex   sync.Mutex

	// Prover pool for concurrent proving
	proverPool chan struct{}

	// Metrics
	metrics *ProverMetrics

	// Circuit breakers for external endpoints
	proverBreaker   *circuitbreaker.Breaker
	verifierBreaker *circuitbreaker.Breaker
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ProverConfig contains configuration for the prover service
type ProverConfig struct {
	// ProverEndpoint is the URL of the EZKL prover service
	ProverEndpoint string

	// MaxConcurrentProofs limits parallel proof generation
	MaxConcurrentProofs int

	// ProofTimeoutSeconds is the max time for proof generation
	ProofTimeoutSeconds int

	// CircuitCacheSize is the max number of cached circuits
	CircuitCacheSize int

	// UseGPU enables GPU acceleration for proving
	UseGPU bool

	// ValidateBeforeProving validates circuit before generating proof
	ValidateBeforeProving bool

	// AllowSimulated enables deterministic simulated proofs (dev/test only)
	AllowSimulated bool
}

// DefaultProverConfig returns sensible default configuration
func DefaultProverConfig() ProverConfig {
	return ProverConfig{
		ProverEndpoint:        "",
		MaxConcurrentProofs:   4,
		ProofTimeoutSeconds:   300, // 5 minutes
		CircuitCacheSize:      100,
		UseGPU:                true,
		ValidateBeforeProving: true,
		AllowSimulated:        false,
	}
}

// CachedCircuit represents a cached circuit for faster proving
type CachedCircuit struct {
	CircuitHash     []byte
	ModelHash       []byte
	VerifyingKey    []byte
	CompiledCircuit []byte
	InputSchema     *ModelSchema
	OutputSchema    *ModelSchema
	CachedAt        time.Time
	LastUsed        time.Time
	UseCount        int64
}

// ProverMetrics tracks prover performance
type ProverMetrics struct {
	TotalProofsGenerated int64
	TotalProofsFailed    int64
	AverageProofTimeMs   int64
	TotalProvingTimeMs   int64
	CacheHits            int64
	CacheMisses          int64
	mutex                *sync.Mutex
}

// ProofRequest represents a request to generate a zkML proof
type ProofRequest struct {
	// ModelHash identifies the model
	ModelHash []byte `json:"model_hash"`

	// CircuitHash identifies the circuit
	CircuitHash []byte `json:"circuit_hash"`

	// InputData is the model input (typically encrypted or hashed)
	InputData []byte `json:"input_data"`

	// InputHash is the SHA-256 hash of the input
	InputHash []byte `json:"input_hash"`

	// OutputData is the expected output to prove
	OutputData []byte `json:"output_data"`

	// OutputHash is the SHA-256 hash of the output
	OutputHash []byte `json:"output_hash"`

	// VerifyingKeyHash identifies the verifying key to use
	VerifyingKeyHash []byte `json:"verifying_key_hash"`

	// Witness contains the private inputs to the circuit
	Witness *Witness `json:"witness,omitempty"`

	// RequestID for tracking
	RequestID string `json:"request_id"`

	// Priority for queue ordering
	Priority int `json:"priority"`
}

// Witness contains the witness data for proof generation
type Witness struct {
	// InputTensor is the input tensor values
	InputTensor []float64 `json:"input_tensor"`

	// OutputTensor is the output tensor values
	OutputTensor []float64 `json:"output_tensor"`

	// Weights are the model weights (for private weights proving)
	Weights []float64 `json:"weights,omitempty"`

	// IntermediateValues for debugging
	IntermediateValues map[string][]float64 `json:"intermediate_values,omitempty"`
}

// ProofResult contains the generated proof and metadata
type ProofResult struct {
	// Success indicates if proof generation succeeded
	Success bool `json:"success"`

	// Proof is the serialized zkML proof
	Proof []byte `json:"proof"`

	// PublicInputs are the public inputs to the proof
	PublicInputs *PublicInputs `json:"public_inputs"`

	// VerifyingKeyHash used for this proof
	VerifyingKeyHash []byte `json:"verifying_key_hash"`

	// CircuitHash of the circuit used
	CircuitHash []byte `json:"circuit_hash"`

	// ProofSize in bytes
	ProofSize int64 `json:"proof_size"`

	// GenerationTimeMs is how long proving took
	GenerationTimeMs int64 `json:"generation_time_ms"`

	// Timestamp when proof was generated
	Timestamp time.Time `json:"timestamp"`

	// Error message if failed
	Error string `json:"error,omitempty"`

	// RequestID for correlation
	RequestID string `json:"request_id"`
}

// PublicInputs contains the public inputs to the proof
type PublicInputs struct {
	// ModelCommitment is a commitment to the model weights
	ModelCommitment []byte `json:"model_commitment"`

	// InputCommitment is a commitment to the input
	InputCommitment []byte `json:"input_commitment"`

	// OutputCommitment is a commitment to the output
	OutputCommitment []byte `json:"output_commitment"`

	// Scale factors used in quantization
	ScaleFactors []float64 `json:"scale_factors,omitempty"`

	// Instances are the public circuit instances
	Instances [][]byte `json:"instances"`
}

// ModelSchema describes the input/output schema of a model
type ModelSchema struct {
	// TensorShape is the shape of the tensor
	TensorShape []int `json:"tensor_shape"`

	// DataType is the data type (e.g., "float32", "int64")
	DataType string `json:"data_type"`

	// QuantizationScale for fixed-point arithmetic
	QuantizationScale float64 `json:"quantization_scale"`

	// QuantizationZeroPoint for fixed-point arithmetic
	QuantizationZeroPoint int `json:"quantization_zero_point"`
}

// NewProverService creates a new EZKL prover service
func NewProverService(logger log.Logger, config ProverConfig) *ProverService {
	cacheSize := config.CircuitCacheSize
	if cacheSize <= 0 {
		cacheSize = 1
	}
	cache, err := lru.New[string, *CachedCircuit](cacheSize)
	if err != nil {
		cache, _ = lru.New[string, *CachedCircuit](1)
	}

	ps := &ProverService{
		logger:          logger,
		config:          config,
		circuitCache:    cache,
		proverPool:      make(chan struct{}, config.MaxConcurrentProofs),
		metrics:         &ProverMetrics{mutex: &sync.Mutex{}},
		proverBreaker:   circuitbreaker.NewDefault("ezkl_prover"),
		verifierBreaker: circuitbreaker.NewDefault("ezkl_verifier"),
		client: httpclient.NewPooledClient(httpclient.PoolConfig{
			Timeout:             time.Duration(config.ProofTimeoutSeconds) * time.Second,
			MaxIdleConns:        max(20, config.MaxConcurrentProofs*2),
			MaxIdleConnsPerHost: max(10, config.MaxConcurrentProofs),
			MaxConnsPerHost:     max(20, config.MaxConcurrentProofs*2),
			IdleConnTimeout:     90 * time.Second,
		}),
	}

	// Initialize prover pool
	for i := 0; i < config.MaxConcurrentProofs; i++ {
		ps.proverPool <- struct{}{}
	}

	return ps
}

// GenerateProof generates a zkML proof for the given request
func (ps *ProverService) GenerateProof(ctx context.Context, req *ProofRequest) (*ProofResult, error) {
	startTime := time.Now()

	// Acquire prover slot
	select {
	case <-ps.proverPool:
		defer func() { ps.proverPool <- struct{}{} }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	ps.logger.Info("Starting proof generation",
		"request_id", req.RequestID,
		"model_hash", fmt.Sprintf("%x", req.ModelHash[:8]),
	)

	result := &ProofResult{
		RequestID:        req.RequestID,
		CircuitHash:      req.CircuitHash,
		VerifyingKeyHash: req.VerifyingKeyHash,
		Timestamp:        time.Now().UTC(),
	}

	// Check circuit cache
	circuitHashKey := fmt.Sprintf("%x", req.CircuitHash)
	ps.cacheMutex.Lock()
	cachedCircuit, cached := ps.circuitCache.Get(circuitHashKey)
	if cached {
		cachedCircuit.LastUsed = time.Now()
		cachedCircuit.UseCount++
	}
	ps.cacheMutex.Unlock()

	if cached {
		ps.metrics.mutex.Lock()
		ps.metrics.CacheHits++
		ps.metrics.mutex.Unlock()
	} else {
		ps.metrics.mutex.Lock()
		ps.metrics.CacheMisses++
		ps.metrics.mutex.Unlock()
	}

	// Generate the proof
	proof, publicInputs, err := ps.generateProofInternal(ctx, req, cachedCircuit)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		result.GenerationTimeMs = time.Since(startTime).Milliseconds()

		ps.metrics.mutex.Lock()
		ps.metrics.TotalProofsFailed++
		ps.metrics.mutex.Unlock()

		ps.logger.Error("Proof generation failed",
			"request_id", req.RequestID,
			"error", err,
		)
		return result, nil
	}

	result.Success = true
	result.Proof = proof
	result.PublicInputs = publicInputs
	result.ProofSize = int64(len(proof))
	result.GenerationTimeMs = time.Since(startTime).Milliseconds()

	// Update metrics
	ps.metrics.mutex.Lock()
	ps.metrics.TotalProofsGenerated++
	ps.metrics.TotalProvingTimeMs += result.GenerationTimeMs
	ps.metrics.AverageProofTimeMs = ps.metrics.TotalProvingTimeMs / ps.metrics.TotalProofsGenerated
	ps.metrics.mutex.Unlock()

	ps.logger.Info("Proof generated successfully",
		"request_id", req.RequestID,
		"proof_size", result.ProofSize,
		"generation_time_ms", result.GenerationTimeMs,
	)

	return result, nil
}

// generateProofInternal handles the actual proof generation
func (ps *ProverService) generateProofInternal(ctx context.Context, req *ProofRequest, cached *CachedCircuit) ([]byte, *PublicInputs, error) {
	// In production, call the remote prover if configured.
	if ps.config.ProverEndpoint != "" {
		remote, err := ps.CallRemoteProver(ctx, req)
		if err != nil {
			return nil, nil, err
		}
		return remote.Proof, remote.PublicInputs, nil
	}

	// Allow deterministic simulation only when explicitly enabled.
	if ps.config.AllowSimulated {
		return ps.simulateProofGeneration(req)
	}

	return nil, nil, fmt.Errorf("zkML prover not configured and simulation disabled")
}

// simulateProofGeneration creates a simulated but valid-looking proof
func (ps *ProverService) simulateProofGeneration(req *ProofRequest) ([]byte, *PublicInputs, error) {
	// Create deterministic "proof" based on inputs
	// This ensures all validators generate the same proof for the same input
	proofInput := bytes.NewBuffer(nil)
	proofInput.Write(req.ModelHash)
	proofInput.Write(req.InputHash)
	proofInput.Write(req.OutputHash)
	proofInput.Write(req.CircuitHash)
	proofInput.Write([]byte("EZKL_PROOF_V1"))

	// Generate proof bytes
	proofHash := sha256.Sum256(proofInput.Bytes())

	// Create a proof structure that mimics EZKL output
	simulatedProof := &SimulatedEZKLProof{
		Protocol: "halo2",
		Curve:    "bn254",
		ProofCommitments: [][]byte{
			proofHash[:16],
			proofHash[16:],
		},
		Evaluations: [][]byte{
			sha256Hash(append(proofHash[:], []byte("eval1")...)),
			sha256Hash(append(proofHash[:], []byte("eval2")...)),
		},
		Challenges: [][]byte{
			sha256Hash(append(proofHash[:], []byte("challenge")...)),
		},
	}

	proof, err := json.Marshal(simulatedProof)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal proof: %w", err)
	}

	// Create public inputs
	publicInputs := &PublicInputs{
		ModelCommitment:  sha256Hash(req.ModelHash),
		InputCommitment:  sha256Hash(req.InputHash),
		OutputCommitment: sha256Hash(req.OutputHash),
		Instances: [][]byte{
			req.InputHash,
			req.OutputHash,
		},
	}

	return proof, publicInputs, nil
}

// SimulatedEZKLProof represents a simulated EZKL proof structure
type SimulatedEZKLProof struct {
	Protocol         string   `json:"protocol"`
	Curve            string   `json:"curve"`
	ProofCommitments [][]byte `json:"proof_commitments"`
	Evaluations      [][]byte `json:"evaluations"`
	Challenges       [][]byte `json:"challenges"`
}

// VerifyProof verifies a zkML proof locally
func (ps *ProverService) VerifyProof(ctx context.Context, proof []byte, publicInputs *PublicInputs, verifyingKey []byte) (bool, error) {
	if ps.config.ProverEndpoint != "" {
		return ps.CallRemoteVerifier(ctx, proof, publicInputs, verifyingKey)
	}

	if !ps.config.AllowSimulated {
		return false, fmt.Errorf("zk verifier not configured and simulation disabled")
	}

	// Simulated verification (dev/test only)

	if len(proof) == 0 {
		return false, fmt.Errorf("empty proof")
	}

	var simProof SimulatedEZKLProof
	if err := json.Unmarshal(proof, &simProof); err != nil {
		return false, fmt.Errorf("invalid proof format: %w", err)
	}

	// Validate proof structure
	if simProof.Protocol != "halo2" {
		return false, fmt.Errorf("unsupported protocol: %s", simProof.Protocol)
	}

	if len(simProof.ProofCommitments) == 0 {
		return false, fmt.Errorf("missing proof commitments")
	}

	// In production: call halo2 verifier
	return true, nil
}

// CacheCircuit adds a circuit to the cache
func (ps *ProverService) CacheCircuit(circuitHash, modelHash, verifyingKey, compiledCircuit []byte, inputSchema, outputSchema *ModelSchema) {
	ps.cacheMutex.Lock()
	defer ps.cacheMutex.Unlock()

	hashKey := fmt.Sprintf("%x", circuitHash)
	ps.circuitCache.Add(hashKey, &CachedCircuit{
		CircuitHash:     circuitHash,
		ModelHash:       modelHash,
		VerifyingKey:    verifyingKey,
		CompiledCircuit: compiledCircuit,
		InputSchema:     inputSchema,
		OutputSchema:    outputSchema,
		CachedAt:        time.Now(),
		LastUsed:        time.Now(),
		UseCount:        0,
	})
}

// GetCachedCircuit retrieves a circuit from cache
func (ps *ProverService) GetCachedCircuit(circuitHash []byte) (*CachedCircuit, bool) {
	ps.cacheMutex.Lock()
	defer ps.cacheMutex.Unlock()

	hashKey := fmt.Sprintf("%x", circuitHash)
	cached, ok := ps.circuitCache.Get(hashKey)
	if ok {
		cached.LastUsed = time.Now()
		cached.UseCount++
	}
	return cached, ok
}

// GetMetrics returns the prover metrics
func (ps *ProverService) GetMetrics() ProverMetrics {
	ps.metrics.mutex.Lock()
	defer ps.metrics.mutex.Unlock()
	return *ps.metrics
}

// CompileCircuit compiles an ONNX model to an EZKL circuit
func (ps *ProverService) CompileCircuit(ctx context.Context, modelONNX []byte, calibrationData []byte) (*CompiledCircuitResult, error) {
	// In production, this would:
	// 1. Call EZKL to compile the ONNX model
	// 2. Generate the circuit definition
	// 3. Perform setup to get verifying key

	// For MVP: simulate circuit compilation
	modelHash := sha256Hash(modelONNX)
	circuitHash := sha256Hash(append(modelONNX, calibrationData...))

	return &CompiledCircuitResult{
		CircuitHash:   circuitHash,
		ModelHash:     modelHash,
		CircuitBytes:  ps.generateSimulatedCircuit(modelHash),
		VerifyingKey:  ps.generateSimulatedVerifyingKey(circuitHash),
		ProvingKey:    nil, // Not stored on-chain
		InputSchema:   &ModelSchema{TensorShape: []int{1, 10}, DataType: "float32"},
		OutputSchema:  &ModelSchema{TensorShape: []int{1, 1}, DataType: "float32"},
		CompileTimeMs: 5000, // Simulated 5 second compile time
	}, nil
}

// CompiledCircuitResult contains the result of circuit compilation
type CompiledCircuitResult struct {
	CircuitHash   []byte
	ModelHash     []byte
	CircuitBytes  []byte
	VerifyingKey  []byte
	ProvingKey    []byte // Large, kept locally
	InputSchema   *ModelSchema
	OutputSchema  *ModelSchema
	CompileTimeMs int64
}

// generateSimulatedCircuit creates a simulated circuit
func (ps *ProverService) generateSimulatedCircuit(modelHash []byte) []byte {
	circuit := map[string]interface{}{
		"version":    "0.1.0",
		"model_hash": fmt.Sprintf("%x", modelHash),
		"layers": []map[string]interface{}{
			{"type": "linear", "in_features": 10, "out_features": 5},
			{"type": "relu"},
			{"type": "linear", "in_features": 5, "out_features": 1},
		},
		"constraints":   1000,
		"public_inputs": []string{"input", "output"},
	}
	data, _ := json.Marshal(circuit)
	return data
}

// generateSimulatedVerifyingKey creates a simulated verifying key
func (ps *ProverService) generateSimulatedVerifyingKey(circuitHash []byte) []byte {
	vk := map[string]interface{}{
		"circuit_hash": fmt.Sprintf("%x", circuitHash),
		"curve":        "bn254",
		"commitments":  []string{"G1", "G2"},
		"size":         256,
	}
	data, _ := json.Marshal(vk)
	return data
}

// sha256Hash computes SHA-256 hash
func sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// CallRemoteProver calls a remote EZKL prover service
func (ps *ProverService) CallRemoteProver(ctx context.Context, req *ProofRequest) (*ProofResult, error) {
	if ps.proverBreaker != nil && !ps.proverBreaker.Allow() {
		return nil, fmt.Errorf("zkML prover circuit open")
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		if ps.proverBreaker != nil {
			ps.proverBreaker.RecordFailure()
		}
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", ps.config.ProverEndpoint+"/prove", bytes.NewReader(reqBody))
	if err != nil {
		if ps.proverBreaker != nil {
			ps.proverBreaker.RecordFailure()
		}
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := ps.client.Do(httpReq)
	if err != nil {
		if ps.proverBreaker != nil {
			ps.proverBreaker.RecordFailure()
		}
		return nil, fmt.Errorf("prover request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if ps.proverBreaker != nil {
			ps.proverBreaker.RecordFailure()
		}
		return nil, fmt.Errorf("prover returned error: %s", string(body))
	}

	var result ProofResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		if ps.proverBreaker != nil {
			ps.proverBreaker.RecordFailure()
		}
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if ps.proverBreaker != nil {
		ps.proverBreaker.RecordSuccess()
	}
	return &result, nil
}

// CallRemoteVerifier calls a remote verifier endpoint to validate a proof.
func (ps *ProverService) CallRemoteVerifier(ctx context.Context, proof []byte, publicInputs *PublicInputs, verifyingKey []byte) (bool, error) {
	if ps.verifierBreaker != nil && !ps.verifierBreaker.Allow() {
		return false, fmt.Errorf("zkML verifier circuit open")
	}

	payload := struct {
		Proof        []byte        `json:"proof"`
		PublicInputs *PublicInputs `json:"public_inputs"`
		VerifyingKey []byte        `json:"verifying_key"`
	}{
		Proof:        proof,
		PublicInputs: publicInputs,
		VerifyingKey: verifyingKey,
	}

	reqBody, err := json.Marshal(payload)
	if err != nil {
		if ps.verifierBreaker != nil {
			ps.verifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("failed to marshal verifier payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", ps.config.ProverEndpoint+"/verify", bytes.NewReader(reqBody))
	if err != nil {
		if ps.verifierBreaker != nil {
			ps.verifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("failed to create verifier request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := ps.client.Do(httpReq)
	if err != nil {
		if ps.verifierBreaker != nil {
			ps.verifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("verifier request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if ps.verifierBreaker != nil {
			ps.verifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("verifier returned error: %s", string(body))
	}

	var result struct {
		Verified bool   `json:"verified"`
		Error    string `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		if ps.verifierBreaker != nil {
			ps.verifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("failed to decode verifier response: %w", err)
	}
	if result.Error != "" && !result.Verified {
		if ps.verifierBreaker != nil {
			ps.verifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("verification failed: %s", result.Error)
	}
	if ps.verifierBreaker != nil {
		ps.verifierBreaker.RecordSuccess()
	}
	return result.Verified, nil
}

// ProverBreaker exposes the prover circuit breaker.
func (ps *ProverService) ProverBreaker() *circuitbreaker.Breaker {
	return ps.proverBreaker
}

// VerifierBreaker exposes the verifier circuit breaker.
func (ps *ProverService) VerifierBreaker() *circuitbreaker.Breaker {
	return ps.verifierBreaker
}

// Shutdown gracefully shuts down the prover service
func (ps *ProverService) Shutdown() {
	// Drain the prover pool
	close(ps.proverPool)

	ps.logger.Info("Prover service shut down",
		"total_proofs", ps.metrics.TotalProofsGenerated,
		"average_time_ms", ps.metrics.AverageProofTimeMs,
	)
}
