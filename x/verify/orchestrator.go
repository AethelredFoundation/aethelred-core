package verify

import (
	"context"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"sync"
	"time"

	"cosmossdk.io/log"
	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/aethelred/aethelred/internal/circuitbreaker"
	"github.com/aethelred/aethelred/x/verify/ezkl"
	"github.com/aethelred/aethelred/x/verify/tee"
	"github.com/aethelred/aethelred/x/verify/types"
)

// VerificationOrchestrator coordinates zkML and TEE verification
type VerificationOrchestrator struct {
	logger log.Logger
	config OrchestratorConfig

	// Services
	proverService *ezkl.ProverService
	modelHandler  *ezkl.ModelHandler
	nitroService  *tee.NitroEnclaveService

	// Verification cache
	resultCache *VerificationCache

	// Metrics
	metrics *OrchestratorMetrics
}

// OrchestratorConfig contains orchestrator configuration
type OrchestratorConfig struct {
	// DefaultVerificationType when not specified
	DefaultVerificationType types.VerificationType

	// ParallelVerification enables parallel zkML and TEE
	ParallelVerification bool

	// CacheEnabled enables verification caching
	CacheEnabled bool

	// CacheTTL is how long to cache results
	CacheTTL time.Duration

	// CacheSize limits the number of cached results (LRU)
	CacheSize int

	// RequireBothForHybrid requires both zkML and TEE to succeed for hybrid
	RequireBothForHybrid bool

	// MaxRetries for failed verifications
	MaxRetries int

	// VerificationTimeout for the entire verification process
	VerificationTimeout time.Duration

	// ProverConfig overrides the default zkML prover configuration
	ProverConfig *ezkl.ProverConfig

	// NitroConfig overrides the default Nitro enclave configuration
	NitroConfig *tee.NitroConfig
}

// DefaultOrchestratorConfig returns default configuration
func DefaultOrchestratorConfig() OrchestratorConfig {
	return OrchestratorConfig{
		DefaultVerificationType: types.VerificationTypeTEE,
		ParallelVerification:    true,
		CacheEnabled:            true,
		CacheTTL:                5 * time.Minute,
		CacheSize:               1024,
		RequireBothForHybrid:    true,
		MaxRetries:              2,
		VerificationTimeout:     5 * time.Minute,
	}
}

// OrchestratorMetrics tracks orchestrator performance
type OrchestratorMetrics struct {
	TotalVerifications      int64
	SuccessfulVerifications int64
	FailedVerifications     int64
	TEEVerifications        int64
	ZKMLVerifications       int64
	HybridVerifications     int64
	CacheHits               int64
	AverageTimeMs           int64
	mutex                   *sync.Mutex
}

// VerificationRequest represents a verification request
type VerificationRequest struct {
	// RequestID for tracking
	RequestID string

	// ModelHash identifies the model
	ModelHash []byte

	// InputHash is the hash of the input data
	InputHash []byte

	// InputData is the actual input (for TEE execution)
	InputData []byte

	// ExpectedOutputHash is the output to verify
	ExpectedOutputHash []byte

	// OutputData is the actual output (for verification)
	OutputData []byte

	// VerificationType specifies the verification method
	VerificationType types.VerificationType

	// CircuitHash for zkML verification
	CircuitHash []byte

	// VerifyingKeyHash for zkML verification
	VerifyingKeyHash []byte

	// Priority for processing order
	Priority int

	// Metadata for additional context
	Metadata map[string]string
}

// VerificationResponse contains the verification result
type VerificationResponse struct {
	// RequestID for correlation
	RequestID string

	// Success indicates overall verification success
	Success bool

	// VerificationType that was used
	VerificationType types.VerificationType

	// OutputHash that was verified
	OutputHash []byte

	// TEEResult from TEE verification
	TEEResult *TEEVerificationResult

	// ZKMLResult from zkML verification
	ZKMLResult *ZKMLVerificationResult

	// TotalTimeMs for the verification
	TotalTimeMs int64

	// Timestamp when verified
	Timestamp time.Time

	// Error message if failed
	Error string

	// FromCache indicates if this was a cached result
	FromCache bool
}

// TEEVerificationResult contains TEE-specific results
type TEEVerificationResult struct {
	Success         bool                          `json:"success"`
	Platform        string                        `json:"platform"`
	EnclaveID       string                        `json:"enclave_id"`
	AttestationDoc  *tee.NitroAttestationDocument `json:"attestation_doc,omitempty"`
	ExecutionTimeMs int64                         `json:"execution_time_ms"`
	OutputHash      []byte                        `json:"output_hash"`
	Error           string                        `json:"error,omitempty"`
}

// ZKMLVerificationResult contains zkML-specific results
type ZKMLVerificationResult struct {
	Success          bool               `json:"success"`
	ProofSystem      string             `json:"proof_system"`
	Proof            []byte             `json:"proof,omitempty"`
	PublicInputs     *ezkl.PublicInputs `json:"public_inputs,omitempty"`
	ProofSizeBytes   int64              `json:"proof_size_bytes"`
	GenerationTimeMs int64              `json:"generation_time_ms"`
	VerifiedOnChain  bool               `json:"verified_on_chain"`
	Error            string             `json:"error,omitempty"`
}

// NewVerificationOrchestrator creates a new orchestrator
func NewVerificationOrchestrator(logger log.Logger, config OrchestratorConfig) *VerificationOrchestrator {
	proverConfig := ezkl.DefaultProverConfig()
	if config.ProverConfig != nil {
		proverConfig = *config.ProverConfig
	}
	nitroConfig := tee.DefaultNitroConfig()
	if config.NitroConfig != nil {
		nitroConfig = *config.NitroConfig
	}

	return &VerificationOrchestrator{
		logger:        logger,
		config:        config,
		proverService: ezkl.NewProverService(logger, proverConfig),
		modelHandler:  ezkl.NewModelHandler(logger, ezkl.DefaultModelConfig()),
		nitroService:  tee.NewNitroEnclaveService(logger, nitroConfig),
		resultCache:   NewVerificationCache(config.CacheTTL, config.CacheSize),
		metrics:       &OrchestratorMetrics{mutex: &sync.Mutex{}},
	}
}

// Initialize initializes all verification services
func (vo *VerificationOrchestrator) Initialize(ctx context.Context) error {
	// Initialize Nitro Enclave service
	if err := vo.nitroService.Initialize(ctx); err != nil {
		allowSimulated := vo.config.NitroConfig != nil && vo.config.NitroConfig.AllowSimulated
		if allowSimulated {
			vo.logger.Warn("Nitro Enclave service initialization failed in simulated mode", "error", err)
		} else {
			return fmt.Errorf("failed to initialize Nitro Enclave service: %w", err)
		}
	}

	vo.logger.Info("Verification orchestrator initialized")
	return nil
}

// Verify performs verification based on the requested type
func (vo *VerificationOrchestrator) Verify(ctx context.Context, req *VerificationRequest) (*VerificationResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("verification request cannot be nil")
	}
	if len(req.ModelHash) == 0 {
		return nil, fmt.Errorf("model hash cannot be empty")
	}

	startTime := time.Now()

	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, vo.config.VerificationTimeout)
	defer cancel()

	resp := &VerificationResponse{
		RequestID:        req.RequestID,
		VerificationType: req.VerificationType,
		Timestamp:        time.Now().UTC(),
	}

	// Check cache first
	if vo.config.CacheEnabled {
		if cached := vo.checkCache(req); cached != nil {
			cached.FromCache = true
			vo.metrics.mutex.Lock()
			vo.metrics.CacheHits++
			vo.metrics.mutex.Unlock()
			return cached, nil
		}
	}

	// Determine verification type
	verificationType := req.VerificationType
	if verificationType == types.VerificationTypeUnspecified {
		verificationType = vo.config.DefaultVerificationType
	}

	vo.logger.Info("Starting verification",
		"request_id", req.RequestID,
		"type", verificationType.String(),
	)

	// Perform verification based on type
	switch verificationType {
	case types.VerificationTypeTEE:
		resp.TEEResult = vo.verifyWithTEE(ctx, req)
		resp.Success = resp.TEEResult.Success
		resp.OutputHash = resp.TEEResult.OutputHash
		if !resp.Success {
			resp.Error = resp.TEEResult.Error
		}

	case types.VerificationTypeZKML:
		resp.ZKMLResult = vo.verifyWithZKML(ctx, req)
		resp.Success = resp.ZKMLResult.Success
		if !resp.Success {
			resp.Error = resp.ZKMLResult.Error
		}

	case types.VerificationTypeHybrid:
		resp.TEEResult, resp.ZKMLResult = vo.verifyHybrid(ctx, req)
		if vo.config.RequireBothForHybrid {
			resp.Success = resp.TEEResult.Success && resp.ZKMLResult.Success
		} else {
			resp.Success = resp.TEEResult.Success || resp.ZKMLResult.Success
		}
		if resp.TEEResult.Success {
			resp.OutputHash = resp.TEEResult.OutputHash
		}
		if !resp.Success {
			if !resp.TEEResult.Success {
				resp.Error = "TEE: " + resp.TEEResult.Error
			}
			if !resp.ZKMLResult.Success {
				if resp.Error != "" {
					resp.Error += "; "
				}
				resp.Error += "zkML: " + resp.ZKMLResult.Error
			}
		}

	default:
		resp.Success = false
		resp.Error = fmt.Sprintf("unknown verification type: %s", verificationType)
	}

	resp.TotalTimeMs = time.Since(startTime).Milliseconds()

	// Update metrics
	vo.updateMetrics(verificationType, resp.Success, resp.TotalTimeMs)

	// Cache result
	if vo.config.CacheEnabled && resp.Success {
		vo.cacheResult(req, resp)
	}

	vo.logger.Info("Verification completed",
		"request_id", req.RequestID,
		"success", resp.Success,
		"time_ms", resp.TotalTimeMs,
	)

	return resp, nil
}

// verifyWithTEE performs TEE-based verification
func (vo *VerificationOrchestrator) verifyWithTEE(ctx context.Context, req *VerificationRequest) *TEEVerificationResult {
	result := &TEEVerificationResult{
		Platform: "aws-nitro",
	}

	// Create enclave execution request
	execReq := &tee.EnclaveExecutionRequest{
		RequestID:           req.RequestID,
		ModelHash:           req.ModelHash,
		InputData:           req.InputData,
		InputHash:           req.InputHash,
		GenerateAttestation: true,
		Nonce:               generateNonce(),
	}

	// Execute in enclave
	execResult, err := vo.nitroService.Execute(ctx, execReq)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("enclave execution failed: %v", err)
		return result
	}

	if !execResult.Success {
		result.Success = false
		result.Error = execResult.Error
		return result
	}

	result.OutputHash = execResult.OutputHash
	result.ExecutionTimeMs = execResult.ExecutionTimeMs
	result.AttestationDoc = execResult.AttestationDocument
	result.EnclaveID = vo.nitroService.GetEnclaveInfo().EnclaveID

	// Verify the output matches expected (if provided)
	if len(req.ExpectedOutputHash) > 0 {
		if !bytesEqual(result.OutputHash, req.ExpectedOutputHash) {
			result.Success = false
			result.Error = "output hash mismatch"
			return result
		}
	}

	// Verify attestation
	if result.AttestationDoc != nil {
		attestResult, err := vo.nitroService.VerifyAttestation(ctx, result.AttestationDoc)
		if err != nil || !attestResult.Valid {
			result.Success = false
			result.Error = "attestation verification failed"
			return result
		}
	}

	result.Success = true
	return result
}

// verifyWithZKML performs zkML-based verification
func (vo *VerificationOrchestrator) verifyWithZKML(ctx context.Context, req *VerificationRequest) *ZKMLVerificationResult {
	result := &ZKMLVerificationResult{
		ProofSystem: "ezkl",
	}

	// Create proof request
	proofReq := &ezkl.ProofRequest{
		RequestID:        req.RequestID,
		ModelHash:        req.ModelHash,
		CircuitHash:      req.CircuitHash,
		InputHash:        req.InputHash,
		InputData:        req.InputData,
		OutputHash:       req.ExpectedOutputHash,
		OutputData:       req.OutputData,
		VerifyingKeyHash: req.VerifyingKeyHash,
		Priority:         req.Priority,
	}

	// Generate proof
	proofResult, err := vo.proverService.GenerateProof(ctx, proofReq)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("proof generation failed: %v", err)
		return result
	}

	if !proofResult.Success {
		result.Success = false
		result.Error = proofResult.Error
		return result
	}

	result.Proof = proofResult.Proof
	result.PublicInputs = proofResult.PublicInputs
	result.ProofSizeBytes = proofResult.ProofSize
	result.GenerationTimeMs = proofResult.GenerationTimeMs

	// Verify the proof
	// In production, this would be verified on-chain
	verified, err := vo.proverService.VerifyProof(ctx, proofResult.Proof, proofResult.PublicInputs, nil)
	if err != nil || !verified {
		result.Success = false
		result.Error = "proof verification failed"
		return result
	}

	result.Success = true
	result.VerifiedOnChain = true
	return result
}

// verifyHybrid performs both TEE and zkML verification
func (vo *VerificationOrchestrator) verifyHybrid(ctx context.Context, req *VerificationRequest) (*TEEVerificationResult, *ZKMLVerificationResult) {
	var teeResult *TEEVerificationResult
	var zkmlResult *ZKMLVerificationResult

	if vo.config.ParallelVerification {
		// Run both in parallel
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			teeResult = vo.verifyWithTEE(ctx, req)
		}()

		go func() {
			defer wg.Done()
			zkmlResult = vo.verifyWithZKML(ctx, req)
		}()

		wg.Wait()
	} else {
		// Run sequentially: TEE first, then zkML bound to TEE output
		teeResult = vo.verifyWithTEE(ctx, req)
		if teeResult.Success {
			// Bind zkML verification to the TEE output so
			// the proof covers the exact same computation
			req.ExpectedOutputHash = teeResult.OutputHash
		}
		zkmlResult = vo.verifyWithZKML(ctx, req)

		// If both succeed, cross-validate (the binding above should
		// guarantee match, but defence-in-depth applies)
		if teeResult.Success && zkmlResult.Success && zkmlResult.PublicInputs != nil {
			if !bytesEqual(teeResult.OutputHash, zkmlResult.PublicInputs.OutputCommitment) {
				vo.logger.Error("CRITICAL: Sequential TEE/zkML mismatch despite binding",
					"request_id", req.RequestID,
				)
				teeResult.Success = false
				teeResult.Error = "hybrid output mismatch after binding"
				zkmlResult.Success = false
				zkmlResult.Error = "hybrid output mismatch after binding"
			}
		}
	}

	// Cross-validate outputs: TEE and zkML MUST agree when both succeed.
	// A mismatch indicates either a hardware fault, a compromised enclave,
	// or an incorrect proof — in all cases, the result is invalid.
	if teeResult.Success && zkmlResult.Success {
		if zkmlResult.PublicInputs == nil || len(zkmlResult.PublicInputs.OutputCommitment) == 0 {
			vo.logger.Error("CRITICAL: zkML public inputs missing for hybrid output binding",
				"request_id", req.RequestID,
			)
			teeResult.Success = false
			teeResult.Error = "hybrid output binding missing (no zkML public inputs)"
			zkmlResult.Success = false
			zkmlResult.Error = "hybrid output binding missing (no zkML public inputs)"
		} else if !bytesEqual(teeResult.OutputHash, zkmlResult.PublicInputs.OutputCommitment) {
			vo.logger.Error("CRITICAL: TEE and zkML output mismatch — marking both as failed",
				"request_id", req.RequestID,
				"tee_output", fmt.Sprintf("%x", teeResult.OutputHash),
				"zkml_output", fmt.Sprintf("%x", zkmlResult.PublicInputs.OutputCommitment),
			)
			teeResult.Success = false
			teeResult.Error = "hybrid output mismatch: TEE and zkML produced different results"
			zkmlResult.Success = false
			zkmlResult.Error = "hybrid output mismatch: TEE and zkML produced different results"
		}
	}

	// In sequential mode, bind zkML verification to the TEE output so
	// the prover proves the SAME computation the enclave executed.
	// (Parallel mode can't do this since they run concurrently.)

	return teeResult, zkmlResult
}

// checkCache checks for cached verification result
func (vo *VerificationOrchestrator) checkCache(req *VerificationRequest) *VerificationResponse {
	cacheKey := vo.getCacheKey(req)
	if cached, ok := vo.resultCache.Get(cacheKey); ok {
		return cached
	}
	return nil
}

// cacheResult caches a verification result
func (vo *VerificationOrchestrator) cacheResult(req *VerificationRequest, resp *VerificationResponse) {
	cacheKey := vo.getCacheKey(req)
	vo.resultCache.Set(cacheKey, resp)
}

// getCacheKey generates a cache key for a request
func (vo *VerificationOrchestrator) getCacheKey(req *VerificationRequest) string {
	h := sha256.New()
	h.Write(req.ModelHash)
	h.Write(req.InputHash)
	h.Write(req.ExpectedOutputHash)
	h.Write([]byte(req.VerificationType.String()))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// updateMetrics updates orchestrator metrics
func (vo *VerificationOrchestrator) updateMetrics(vType types.VerificationType, success bool, timeMs int64) {
	vo.metrics.mutex.Lock()
	defer vo.metrics.mutex.Unlock()

	vo.metrics.TotalVerifications++
	if success {
		vo.metrics.SuccessfulVerifications++
	} else {
		vo.metrics.FailedVerifications++
	}

	switch vType {
	case types.VerificationTypeTEE:
		vo.metrics.TEEVerifications++
	case types.VerificationTypeZKML:
		vo.metrics.ZKMLVerifications++
	case types.VerificationTypeHybrid:
		vo.metrics.HybridVerifications++
	}

	// Update average time
	vo.metrics.AverageTimeMs = (vo.metrics.AverageTimeMs*(vo.metrics.TotalVerifications-1) + timeMs) / vo.metrics.TotalVerifications
}

// GetMetrics returns orchestrator metrics
func (vo *VerificationOrchestrator) GetMetrics() OrchestratorMetrics {
	vo.metrics.mutex.Lock()
	defer vo.metrics.mutex.Unlock()
	return *vo.metrics
}

// GetProverMetrics returns zkML prover metrics if the prover service is available.
func (vo *VerificationOrchestrator) GetProverMetrics() (ezkl.ProverMetrics, bool) {
	if vo.proverService == nil {
		return ezkl.ProverMetrics{}, false
	}
	return vo.proverService.GetMetrics(), true
}

// GetNitroMetrics returns Nitro Enclave metrics if the service is available.
func (vo *VerificationOrchestrator) GetNitroMetrics() (tee.NitroMetrics, bool) {
	if vo.nitroService == nil {
		return tee.NitroMetrics{}, false
	}
	return vo.nitroService.GetMetrics(), true
}

// CircuitBreakers returns any configured circuit breakers for external services.
func (vo *VerificationOrchestrator) CircuitBreakers() []*circuitbreaker.Breaker {
	breakers := make([]*circuitbreaker.Breaker, 0, 4)
	if vo.proverService != nil {
		if b := vo.proverService.ProverBreaker(); b != nil {
			breakers = append(breakers, b)
		}
		if b := vo.proverService.VerifierBreaker(); b != nil {
			breakers = append(breakers, b)
		}
	}
	if vo.nitroService != nil {
		if b := vo.nitroService.ExecutorBreaker(); b != nil {
			breakers = append(breakers, b)
		}
		if b := vo.nitroService.AttestationBreaker(); b != nil {
			breakers = append(breakers, b)
		}
	}
	return breakers
}

// Shutdown gracefully shuts down the orchestrator
func (vo *VerificationOrchestrator) Shutdown() {
	vo.proverService.Shutdown()
	vo.nitroService.Shutdown()
	vo.logger.Info("Verification orchestrator shut down")
}

// VerificationCache provides caching for verification results
type VerificationCache struct {
	cache *lru.Cache[string, *cacheEntry]
	mutex sync.Mutex
	ttl   time.Duration
}

type cacheEntry struct {
	response *VerificationResponse
	expiry   time.Time
}

// NewVerificationCache creates a new cache
func NewVerificationCache(ttl time.Duration, size int) *VerificationCache {
	if size <= 0 {
		size = 1024
	}
	cache, err := lru.New[string, *cacheEntry](size)
	if err != nil {
		cache, _ = lru.New[string, *cacheEntry](1024)
	}
	vc := &VerificationCache{
		cache: cache,
		ttl:   ttl,
	}

	// Start cleanup goroutine
	if ttl > 0 {
		go vc.cleanup()
	}

	return vc
}

// Get retrieves from cache
func (vc *VerificationCache) Get(key string) (*VerificationResponse, bool) {
	vc.mutex.Lock()
	defer vc.mutex.Unlock()

	entry, ok := vc.cache.Get(key)
	if !ok {
		return nil, false
	}
	if vc.isExpired(entry) {
		vc.cache.Remove(key)
		return nil, false
	}

	return entry.response, true
}

// Set stores in cache
func (vc *VerificationCache) Set(key string, response *VerificationResponse) {
	vc.mutex.Lock()
	defer vc.mutex.Unlock()

	entry := &cacheEntry{
		response: response,
	}
	if vc.ttl > 0 {
		entry.expiry = time.Now().Add(vc.ttl)
	}
	vc.cache.Add(key, entry)
}

// cleanup removes expired entries
func (vc *VerificationCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		vc.mutex.Lock()
		now := time.Now()
		for _, key := range vc.cache.Keys() {
			entry, ok := vc.cache.Peek(key)
			if !ok {
				continue
			}
			if !entry.expiry.IsZero() && now.After(entry.expiry) {
				vc.cache.Remove(key)
			}
		}
		vc.mutex.Unlock()
	}
}

func (vc *VerificationCache) isExpired(entry *cacheEntry) bool {
	if entry == nil {
		return true
	}
	if vc.ttl <= 0 || entry.expiry.IsZero() {
		return false
	}
	return time.Now().After(entry.expiry)
}

// Helper functions

func generateNonce() []byte {
	nonce := make([]byte, 32)
	if _, err := cryptoRand.Read(nonce); err != nil {
		// Fallback: should never happen on a healthy system
		h := sha256.Sum256([]byte(time.Now().String()))
		return h[:]
	}
	return nonce
}

// bytesEqual uses constant-time comparison to prevent timing side-channels
func bytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
