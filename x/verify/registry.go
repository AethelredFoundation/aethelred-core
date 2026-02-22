package verify

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"cosmossdk.io/log"

	"github.com/aethelred/aethelred/x/verify/ezkl"
)

// ModelRegistry manages registered models and their zkML circuits.
//
// PERSISTENCE MODEL: The ModelRegistry is an in-memory service that caches
// parsed ONNX models and compiled circuits for fast proof generation.
// The authoritative on-chain state for verifying keys and circuits lives
// in the verify Keeper's collections (VerifyingKeys, Circuits).
//
// On node restart, call SyncFromKeeper() to reload circuit/key state.
// The in-memory model cache (parsed ONNX) is ephemeral — models must be
// re-registered if needed. For production, an off-chain model storage
// service (IPFS/S3) should be used alongside the on-chain hash registry.
type ModelRegistry struct {
	logger log.Logger
	config RegistryConfig

	// Model handler for ONNX processing
	modelHandler *ezkl.ModelHandler

	// Prover service for circuit compilation
	proverService *ezkl.ProverService

	// Storage (in-memory cache — ephemeral)
	models   map[string]*RegisteredModel
	circuits map[string]*RegisteredCircuit

	// Mutex for thread safety
	mutex sync.RWMutex
}

// RegistryConfig contains registry configuration
type RegistryConfig struct {
	// MaxModelSizeMB limits model size
	MaxModelSizeMB int64

	// MaxCircuitSizeMB limits circuit size
	MaxCircuitSizeMB int64

	// RequireCircuitCompilation requires circuits for zkML
	RequireCircuitCompilation bool

	// AutoCompileCircuits automatically compiles circuits
	AutoCompileCircuits bool

	// CircuitCompilationTimeout for auto-compilation
	CircuitCompilationTimeout time.Duration
}

// DefaultRegistryConfig returns default configuration
func DefaultRegistryConfig() RegistryConfig {
	return RegistryConfig{
		MaxModelSizeMB:            100,
		MaxCircuitSizeMB:          50,
		RequireCircuitCompilation: true,
		AutoCompileCircuits:       true,
		CircuitCompilationTimeout: 10 * time.Minute,
	}
}

// RegisteredModel represents a model registered for verification
type RegisteredModel struct {
	// ModelHash is the SHA-256 hash of the model
	ModelHash []byte `json:"model_hash"`

	// Name of the model
	Name string `json:"name"`

	// Description of what the model does
	Description string `json:"description"`

	// Version of the model
	Version string `json:"version"`

	// Owner who registered the model
	Owner string `json:"owner"`

	// ModelType (e.g., "credit_scoring", "fraud_detection")
	ModelType string `json:"model_type"`

	// ParsedModel contains the parsed ONNX model
	ParsedModel *ezkl.ONNXModel `json:"parsed_model,omitempty"`

	// Circuits associated with this model
	CircuitHashes [][]byte `json:"circuit_hashes"`

	// TEEMeasurement expected for this model
	TEEMeasurement []byte `json:"tee_measurement,omitempty"`

	// Metadata
	Metadata map[string]string `json:"metadata,omitempty"`

	// Status
	Status ModelStatus `json:"status"`

	// Timestamps
	RegisteredAt time.Time `json:"registered_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ModelStatus represents the status of a registered model
type ModelStatus string

const (
	ModelStatusPending   ModelStatus = "pending"
	ModelStatusCompiling ModelStatus = "compiling"
	ModelStatusActive    ModelStatus = "active"
	ModelStatusInactive  ModelStatus = "inactive"
	ModelStatusFailed    ModelStatus = "failed"
)

// RegisteredCircuit represents a compiled zkML circuit
type RegisteredCircuit struct {
	// CircuitHash is the SHA-256 hash of the circuit
	CircuitHash []byte `json:"circuit_hash"`

	// ModelHash this circuit is for
	ModelHash []byte `json:"model_hash"`

	// ProofSystem (e.g., "ezkl", "risc0")
	ProofSystem string `json:"proof_system"`

	// VerifyingKey for proof verification
	VerifyingKey []byte `json:"verifying_key"`

	// VerifyingKeyHash for quick lookup
	VerifyingKeyHash []byte `json:"verifying_key_hash"`

	// CircuitBytes is the serialized circuit
	CircuitBytes []byte `json:"circuit_bytes"`

	// InputSchema describes expected inputs
	InputSchema *ezkl.ModelSchema `json:"input_schema"`

	// OutputSchema describes expected outputs
	OutputSchema *ezkl.ModelSchema `json:"output_schema"`

	// EstimatedProofTimeMs estimated proving time
	EstimatedProofTimeMs int64 `json:"estimated_proof_time_ms"`

	// EstimatedConstraints in the circuit
	EstimatedConstraints int64 `json:"estimated_constraints"`

	// CompilationParams used for compilation
	CompilationParams *CompilationParams `json:"compilation_params,omitempty"`

	// Status
	Status CircuitStatus `json:"status"`

	// Timestamps
	CompiledAt time.Time `json:"compiled_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// CircuitStatus represents the status of a circuit
type CircuitStatus string

const (
	CircuitStatusCompiling CircuitStatus = "compiling"
	CircuitStatusActive    CircuitStatus = "active"
	CircuitStatusInactive  CircuitStatus = "inactive"
	CircuitStatusFailed    CircuitStatus = "failed"
)

// CompilationParams contains parameters used for circuit compilation
type CompilationParams struct {
	QuantizationBits     int     `json:"quantization_bits"`
	QuantizationScale    float64 `json:"quantization_scale"`
	LookupBits           int     `json:"lookup_bits"`
	Logrows              int     `json:"logrows"`
	CalibrationSamples   int     `json:"calibration_samples"`
}

// NewModelRegistry creates a new model registry
func NewModelRegistry(logger log.Logger, config RegistryConfig) *ModelRegistry {
	return &ModelRegistry{
		logger:        logger,
		config:        config,
		modelHandler:  ezkl.NewModelHandler(logger, ezkl.DefaultModelConfig()),
		proverService: ezkl.NewProverService(logger, ezkl.DefaultProverConfig()),
		models:        make(map[string]*RegisteredModel),
		circuits:      make(map[string]*RegisteredCircuit),
	}
}

// RegisterModel registers a new model
func (mr *ModelRegistry) RegisterModel(ctx context.Context, req *RegisterModelRequest) (*RegisteredModel, error) {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()

	// Check size limit
	sizeMB := int64(len(req.ModelBytes)) / (1024 * 1024)
	if sizeMB > mr.config.MaxModelSizeMB {
		return nil, fmt.Errorf("model size %dMB exceeds limit %dMB", sizeMB, mr.config.MaxModelSizeMB)
	}

	// Parse the ONNX model
	parsedModel, err := mr.modelHandler.ParseONNXModel(req.ModelBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse model: %w", err)
	}

	// Validate the model
	validation, err := mr.modelHandler.ValidateModel(parsedModel)
	if err != nil {
		return nil, fmt.Errorf("model validation error: %w", err)
	}
	if !validation.Valid {
		return nil, fmt.Errorf("model validation failed: %v", validation.Errors)
	}

	// Create registered model
	model := &RegisteredModel{
		ModelHash:     parsedModel.ModelHash,
		Name:          req.Name,
		Description:   req.Description,
		Version:       req.Version,
		Owner:         req.Owner,
		ModelType:     req.ModelType,
		ParsedModel:   parsedModel,
		CircuitHashes: make([][]byte, 0),
		Metadata:      req.Metadata,
		Status:        ModelStatusPending,
		RegisteredAt:  time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}

	// Store model
	modelHashKey := fmt.Sprintf("%x", model.ModelHash)
	mr.models[modelHashKey] = model

	mr.logger.Info("Model registered",
		"model_hash", modelHashKey[:16],
		"name", model.Name,
		"parameters", parsedModel.Graph.TotalParameters,
	)

	// Auto-compile circuit if enabled
	if mr.config.AutoCompileCircuits {
		go mr.compileCircuitAsync(ctx, model, req.CalibrationData)
	}

	return model, nil
}

// RegisterModelRequest contains model registration request data
type RegisterModelRequest struct {
	ModelBytes      []byte            `json:"model_bytes"`
	Name            string            `json:"name"`
	Description     string            `json:"description"`
	Version         string            `json:"version"`
	Owner           string            `json:"owner"`
	ModelType       string            `json:"model_type"`
	CalibrationData []byte            `json:"calibration_data,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// compileCircuitAsync compiles a circuit asynchronously
func (mr *ModelRegistry) compileCircuitAsync(ctx context.Context, model *RegisteredModel, calibrationData []byte) {
	ctx, cancel := context.WithTimeout(ctx, mr.config.CircuitCompilationTimeout)
	defer cancel()

	mr.logger.Info("Starting circuit compilation",
		"model_hash", fmt.Sprintf("%x", model.ModelHash[:8]),
	)

	// Update model status
	mr.updateModelStatus(model.ModelHash, ModelStatusCompiling)

	// Compile circuit
	result, err := mr.proverService.CompileCircuit(ctx, model.ParsedModel.RawBytes, calibrationData)
	if err != nil {
		mr.logger.Error("Circuit compilation failed",
			"model_hash", fmt.Sprintf("%x", model.ModelHash[:8]),
			"error", err,
		)
		mr.updateModelStatus(model.ModelHash, ModelStatusFailed)
		return
	}

	// Register the circuit
	circuit := &RegisteredCircuit{
		CircuitHash:      result.CircuitHash,
		ModelHash:        model.ModelHash,
		ProofSystem:      "ezkl",
		VerifyingKey:     result.VerifyingKey,
		VerifyingKeyHash: sha256Hash(result.VerifyingKey),
		CircuitBytes:     result.CircuitBytes,
		InputSchema:      result.InputSchema,
		OutputSchema:     result.OutputSchema,
		Status:           CircuitStatusActive,
		CompiledAt:       time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}

	// Store circuit
	mr.mutex.Lock()
	circuitHashKey := fmt.Sprintf("%x", circuit.CircuitHash)
	mr.circuits[circuitHashKey] = circuit
	model.CircuitHashes = append(model.CircuitHashes, circuit.CircuitHash)
	model.Status = ModelStatusActive
	model.UpdatedAt = time.Now().UTC()
	mr.mutex.Unlock()

	// Cache the circuit in prover service
	mr.proverService.CacheCircuit(
		circuit.CircuitHash,
		model.ModelHash,
		circuit.VerifyingKey,
		circuit.CircuitBytes,
		circuit.InputSchema,
		circuit.OutputSchema,
	)

	mr.logger.Info("Circuit compiled and registered",
		"circuit_hash", circuitHashKey[:16],
		"model_hash", fmt.Sprintf("%x", model.ModelHash[:8]),
	)
}

// updateModelStatus updates a model's status
func (mr *ModelRegistry) updateModelStatus(modelHash []byte, status ModelStatus) {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()

	modelHashKey := fmt.Sprintf("%x", modelHash)
	if model, ok := mr.models[modelHashKey]; ok {
		model.Status = status
		model.UpdatedAt = time.Now().UTC()
	}
}

// GetModel retrieves a registered model
func (mr *ModelRegistry) GetModel(modelHash []byte) (*RegisteredModel, error) {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()

	modelHashKey := fmt.Sprintf("%x", modelHash)
	model, ok := mr.models[modelHashKey]
	if !ok {
		return nil, fmt.Errorf("model not found: %s", modelHashKey[:16])
	}

	return model, nil
}

// GetCircuit retrieves a registered circuit
func (mr *ModelRegistry) GetCircuit(circuitHash []byte) (*RegisteredCircuit, error) {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()

	circuitHashKey := fmt.Sprintf("%x", circuitHash)
	circuit, ok := mr.circuits[circuitHashKey]
	if !ok {
		return nil, fmt.Errorf("circuit not found: %s", circuitHashKey[:16])
	}

	return circuit, nil
}

// GetCircuitsForModel returns all circuits for a model
func (mr *ModelRegistry) GetCircuitsForModel(modelHash []byte) ([]*RegisteredCircuit, error) {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()

	modelHashKey := fmt.Sprintf("%x", modelHash)
	model, ok := mr.models[modelHashKey]
	if !ok {
		return nil, fmt.Errorf("model not found")
	}

	var circuits []*RegisteredCircuit
	for _, circuitHash := range model.CircuitHashes {
		circuitHashKey := fmt.Sprintf("%x", circuitHash)
		if circuit, ok := mr.circuits[circuitHashKey]; ok {
			circuits = append(circuits, circuit)
		}
	}

	return circuits, nil
}

// GetVerifyingKey retrieves a verifying key by hash
func (mr *ModelRegistry) GetVerifyingKey(vkHash []byte) ([]byte, error) {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()

	vkHashKey := fmt.Sprintf("%x", vkHash)

	// Search through circuits
	for _, circuit := range mr.circuits {
		if fmt.Sprintf("%x", circuit.VerifyingKeyHash) == vkHashKey {
			return circuit.VerifyingKey, nil
		}
	}

	return nil, fmt.Errorf("verifying key not found")
}

// ListModels returns all registered models
func (mr *ModelRegistry) ListModels() []*RegisteredModel {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()

	var models []*RegisteredModel
	for _, model := range mr.models {
		models = append(models, model)
	}

	return models
}

// ListActiveModels returns all active models
func (mr *ModelRegistry) ListActiveModels() []*RegisteredModel {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()

	var models []*RegisteredModel
	for _, model := range mr.models {
		if model.Status == ModelStatusActive {
			models = append(models, model)
		}
	}

	return models
}

// DeactivateModel deactivates a model
func (mr *ModelRegistry) DeactivateModel(modelHash []byte) error {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()

	modelHashKey := fmt.Sprintf("%x", modelHash)
	model, ok := mr.models[modelHashKey]
	if !ok {
		return fmt.Errorf("model not found")
	}

	model.Status = ModelStatusInactive
	model.UpdatedAt = time.Now().UTC()

	// Also deactivate circuits
	for _, circuitHash := range model.CircuitHashes {
		circuitHashKey := fmt.Sprintf("%x", circuitHash)
		if circuit, ok := mr.circuits[circuitHashKey]; ok {
			circuit.Status = CircuitStatusInactive
			circuit.UpdatedAt = time.Now().UTC()
		}
	}

	mr.logger.Info("Model deactivated", "model_hash", modelHashKey[:16])
	return nil
}

// GetModelStats returns statistics about registered models
func (mr *ModelRegistry) GetModelStats() *RegistryStats {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()

	stats := &RegistryStats{
		TotalModels:   len(mr.models),
		TotalCircuits: len(mr.circuits),
	}

	for _, model := range mr.models {
		switch model.Status {
		case ModelStatusActive:
			stats.ActiveModels++
		case ModelStatusPending:
			stats.PendingModels++
		case ModelStatusCompiling:
			stats.CompilingModels++
		case ModelStatusFailed:
			stats.FailedModels++
		}
	}

	for _, circuit := range mr.circuits {
		if circuit.Status == CircuitStatusActive {
			stats.ActiveCircuits++
		}
	}

	return stats
}

// RegistryStats contains registry statistics
type RegistryStats struct {
	TotalModels     int `json:"total_models"`
	ActiveModels    int `json:"active_models"`
	PendingModels   int `json:"pending_models"`
	CompilingModels int `json:"compiling_models"`
	FailedModels    int `json:"failed_models"`
	TotalCircuits   int `json:"total_circuits"`
	ActiveCircuits  int `json:"active_circuits"`
}

// SetTEEMeasurement sets the expected TEE measurement for a model
func (mr *ModelRegistry) SetTEEMeasurement(modelHash, measurement []byte) error {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()

	modelHashKey := fmt.Sprintf("%x", modelHash)
	model, ok := mr.models[modelHashKey]
	if !ok {
		return fmt.Errorf("model not found")
	}

	model.TEEMeasurement = measurement
	model.UpdatedAt = time.Now().UTC()

	return nil
}

// SyncState represents the registry's view of persisted state that
// can be loaded from an external source (keeper, disk, etc.).
type SyncState struct {
	// Circuits keyed by hex hash
	Circuits map[string]*RegisteredCircuit
	// Models keyed by hex hash
	Models map[string]*RegisteredModel
}

// LoadState bulk-loads state into the registry, typically on node startup.
// This replaces any existing in-memory state.
func (mr *ModelRegistry) LoadState(state *SyncState) {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()

	if state.Models != nil {
		mr.models = state.Models
	}
	if state.Circuits != nil {
		mr.circuits = state.Circuits
		// Re-cache circuits in prover service
		for _, circuit := range mr.circuits {
			if circuit.Status == CircuitStatusActive {
				mr.proverService.CacheCircuit(
					circuit.CircuitHash,
					circuit.ModelHash,
					circuit.VerifyingKey,
					circuit.CircuitBytes,
					circuit.InputSchema,
					circuit.OutputSchema,
				)
			}
		}
	}

	mr.logger.Info("Registry state loaded",
		"models", len(mr.models),
		"circuits", len(mr.circuits),
	)
}

// ExportState exports the current in-memory state for persistence.
func (mr *ModelRegistry) ExportState() *SyncState {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()

	models := make(map[string]*RegisteredModel, len(mr.models))
	for k, v := range mr.models {
		models[k] = v
	}
	circuits := make(map[string]*RegisteredCircuit, len(mr.circuits))
	for k, v := range mr.circuits {
		circuits[k] = v
	}

	return &SyncState{
		Models:   models,
		Circuits: circuits,
	}
}

// sha256Hash computes SHA-256 hash
func sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}
