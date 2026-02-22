package ezkl

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"cosmossdk.io/log"
)

// ModelHandler handles ONNX model processing for zkML circuit compilation
type ModelHandler struct {
	logger log.Logger
	config ModelConfig
}

// ModelConfig contains configuration for model handling
type ModelConfig struct {
	// MaxModelSizeMB is the maximum model size in megabytes
	MaxModelSizeMB int64

	// SupportedOpsets lists supported ONNX opset versions
	SupportedOpsets []int

	// QuantizationBits is the bit width for quantization
	QuantizationBits int

	// MaxLayerCount limits the number of layers
	MaxLayerCount int

	// AllowedOperators lists allowed ONNX operators
	AllowedOperators []string
}

// DefaultModelConfig returns sensible defaults for model handling
func DefaultModelConfig() ModelConfig {
	return ModelConfig{
		MaxModelSizeMB:   100,
		SupportedOpsets:  []int{13, 14, 15, 16, 17},
		QuantizationBits: 16,
		MaxLayerCount:    100,
		AllowedOperators: []string{
			"Relu", "Sigmoid", "Tanh", "Softmax",
			"MatMul", "Gemm", "Conv", "ConvTranspose",
			"Add", "Sub", "Mul", "Div",
			"BatchNormalization", "LayerNormalization",
			"MaxPool", "AveragePool", "GlobalAveragePool",
			"Flatten", "Reshape", "Transpose",
			"Concat", "Split", "Gather",
			"Dropout", "Identity",
		},
	}
}

// ONNXModel represents a parsed ONNX model
type ONNXModel struct {
	// ModelHash is the SHA-256 hash of the model bytes
	ModelHash []byte `json:"model_hash"`

	// Name of the model
	Name string `json:"name"`

	// Version of the model
	Version string `json:"version"`

	// Description of what the model does
	Description string `json:"description"`

	// OpsetVersion is the ONNX opset version
	OpsetVersion int `json:"opset_version"`

	// ProducerName of the framework that created this model
	ProducerName string `json:"producer_name"`

	// ProducerVersion of the framework
	ProducerVersion string `json:"producer_version"`

	// Graph contains the model graph
	Graph *ModelGraph `json:"graph"`

	// Metadata stores additional model metadata
	Metadata map[string]string `json:"metadata,omitempty"`

	// RawBytes is the original ONNX bytes
	RawBytes []byte `json:"-"`

	// ParsedAt when the model was parsed
	ParsedAt time.Time `json:"parsed_at"`
}

// ModelGraph represents the ONNX computational graph
type ModelGraph struct {
	// Nodes are the computational nodes
	Nodes []*GraphNode `json:"nodes"`

	// Inputs are the graph inputs
	Inputs []*TensorInfo `json:"inputs"`

	// Outputs are the graph outputs
	Outputs []*TensorInfo `json:"outputs"`

	// Initializers are the model weights
	Initializers []*TensorData `json:"initializers"`

	// TotalParameters is the count of model parameters
	TotalParameters int64 `json:"total_parameters"`

	// TotalOperations estimates FLOPs
	TotalOperations int64 `json:"total_operations"`
}

// GraphNode represents a node in the ONNX graph
type GraphNode struct {
	// Name of the node
	Name string `json:"name"`

	// OpType is the ONNX operator type
	OpType string `json:"op_type"`

	// Inputs are the input tensor names
	Inputs []string `json:"inputs"`

	// Outputs are the output tensor names
	Outputs []string `json:"outputs"`

	// Attributes are operator-specific attributes
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// TensorInfo describes a tensor's metadata
type TensorInfo struct {
	// Name of the tensor
	Name string `json:"name"`

	// Shape is the tensor dimensions
	Shape []int64 `json:"shape"`

	// DataType is the element type
	DataType string `json:"data_type"`

	// IsOptional indicates if this input is optional
	IsOptional bool `json:"is_optional"`
}

// TensorData contains actual tensor data (weights)
type TensorData struct {
	// TensorInfo metadata
	TensorInfo

	// RawData is the serialized tensor data
	RawData []byte `json:"raw_data,omitempty"`

	// FloatData for float tensors
	FloatData []float32 `json:"float_data,omitempty"`

	// Int64Data for integer tensors
	Int64Data []int64 `json:"int64_data,omitempty"`
}

// QuantizationParams describes quantization settings
type QuantizationParams struct {
	// Scale for linear quantization
	Scale float64 `json:"scale"`

	// ZeroPoint for asymmetric quantization
	ZeroPoint int64 `json:"zero_point"`

	// BitWidth for the quantized values
	BitWidth int `json:"bit_width"`

	// IsSymmetric indicates symmetric quantization
	IsSymmetric bool `json:"is_symmetric"`

	// PerChannel indicates per-channel quantization
	PerChannel bool `json:"per_channel"`

	// ChannelScales for per-channel quantization
	ChannelScales []float64 `json:"channel_scales,omitempty"`
}

// NewModelHandler creates a new model handler
func NewModelHandler(logger log.Logger, config ModelConfig) *ModelHandler {
	return &ModelHandler{
		logger: logger,
		config: config,
	}
}

// ParseONNXModel parses an ONNX model from bytes
func (mh *ModelHandler) ParseONNXModel(modelBytes []byte) (*ONNXModel, error) {
	// Check size limit
	sizeMB := int64(len(modelBytes)) / (1024 * 1024)
	if sizeMB > mh.config.MaxModelSizeMB {
		return nil, fmt.Errorf("model size %dMB exceeds maximum %dMB", sizeMB, mh.config.MaxModelSizeMB)
	}

	// Calculate hash
	modelHash := sha256.Sum256(modelBytes)

	// In production, this would use a proper ONNX parser (e.g., onnx-go)
	// For MVP: simulate parsing with a structured response
	model := &ONNXModel{
		ModelHash:       modelHash[:],
		Name:            "unknown",
		Version:         "1.0.0",
		OpsetVersion:    15,
		ProducerName:    "pytorch",
		ProducerVersion: "2.0",
		RawBytes:        modelBytes,
		ParsedAt:        time.Now().UTC(),
		Metadata:        make(map[string]string),
	}

	// Simulate graph parsing
	model.Graph = mh.parseGraphSimulated(modelBytes)

	mh.logger.Info("ONNX model parsed",
		"model_hash", fmt.Sprintf("%x", modelHash[:8]),
		"nodes", len(model.Graph.Nodes),
		"parameters", model.Graph.TotalParameters,
	)

	return model, nil
}

// parseGraphSimulated simulates ONNX graph parsing
func (mh *ModelHandler) parseGraphSimulated(modelBytes []byte) *ModelGraph {
	// Use model bytes to create deterministic "parsed" graph
	hash := sha256.Sum256(modelBytes)

	// Create simulated nodes based on common credit scoring model architecture
	nodes := []*GraphNode{
		{Name: "linear1", OpType: "Gemm", Inputs: []string{"input"}, Outputs: []string{"linear1_out"}},
		{Name: "relu1", OpType: "Relu", Inputs: []string{"linear1_out"}, Outputs: []string{"relu1_out"}},
		{Name: "linear2", OpType: "Gemm", Inputs: []string{"relu1_out"}, Outputs: []string{"linear2_out"}},
		{Name: "relu2", OpType: "Relu", Inputs: []string{"linear2_out"}, Outputs: []string{"relu2_out"}},
		{Name: "linear3", OpType: "Gemm", Inputs: []string{"relu2_out"}, Outputs: []string{"output"}},
		{Name: "sigmoid", OpType: "Sigmoid", Inputs: []string{"output"}, Outputs: []string{"probability"}},
	}

	return &ModelGraph{
		Nodes: nodes,
		Inputs: []*TensorInfo{
			{Name: "input", Shape: []int64{1, 10}, DataType: "float32"},
		},
		Outputs: []*TensorInfo{
			{Name: "probability", Shape: []int64{1, 1}, DataType: "float32"},
		},
		Initializers: []*TensorData{
			{TensorInfo: TensorInfo{Name: "weight1", Shape: []int64{10, 64}, DataType: "float32"}},
			{TensorInfo: TensorInfo{Name: "bias1", Shape: []int64{64}, DataType: "float32"}},
			{TensorInfo: TensorInfo{Name: "weight2", Shape: []int64{64, 32}, DataType: "float32"}},
			{TensorInfo: TensorInfo{Name: "bias2", Shape: []int64{32}, DataType: "float32"}},
			{TensorInfo: TensorInfo{Name: "weight3", Shape: []int64{32, 1}, DataType: "float32"}},
			{TensorInfo: TensorInfo{Name: "bias3", Shape: []int64{1}, DataType: "float32"}},
		},
		TotalParameters: 10*64 + 64 + 64*32 + 32 + 32*1 + 1, // ~2700 params
		TotalOperations: int64(hash[0])*1000 + 50000,        // Simulated FLOPs
	}
}

// ValidateModel validates an ONNX model for zkML compatibility
func (mh *ModelHandler) ValidateModel(model *ONNXModel) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:    true,
		Warnings: make([]string, 0),
		Errors:   make([]string, 0),
	}

	// Check opset version
	opsetSupported := false
	for _, opset := range mh.config.SupportedOpsets {
		if model.OpsetVersion == opset {
			opsetSupported = true
			break
		}
	}
	if !opsetSupported {
		result.Errors = append(result.Errors, fmt.Sprintf("unsupported opset version: %d", model.OpsetVersion))
		result.Valid = false
	}

	// Check layer count
	if len(model.Graph.Nodes) > mh.config.MaxLayerCount {
		result.Errors = append(result.Errors, fmt.Sprintf("too many layers: %d > %d", len(model.Graph.Nodes), mh.config.MaxLayerCount))
		result.Valid = false
	}

	// Check operators
	allowedOps := make(map[string]bool)
	for _, op := range mh.config.AllowedOperators {
		allowedOps[op] = true
	}

	for _, node := range model.Graph.Nodes {
		if !allowedOps[node.OpType] {
			result.Warnings = append(result.Warnings, fmt.Sprintf("potentially unsupported operator: %s", node.OpType))
		}
	}

	// Estimate circuit complexity
	result.EstimatedConstraints = mh.estimateCircuitConstraints(model)
	result.EstimatedProofTimeMs = result.EstimatedConstraints / 1000 // Rough estimate

	if result.EstimatedConstraints > 10000000 {
		result.Warnings = append(result.Warnings, "large circuit may have long proving times")
	}

	return result, nil
}

// ValidationResult contains model validation results
type ValidationResult struct {
	Valid                 bool     `json:"valid"`
	Warnings              []string `json:"warnings"`
	Errors                []string `json:"errors"`
	EstimatedConstraints  int64    `json:"estimated_constraints"`
	EstimatedProofTimeMs  int64    `json:"estimated_proof_time_ms"`
}

// estimateCircuitConstraints estimates the number of circuit constraints
func (mh *ModelHandler) estimateCircuitConstraints(model *ONNXModel) int64 {
	var constraints int64

	for _, node := range model.Graph.Nodes {
		switch node.OpType {
		case "Gemm", "MatMul":
			constraints += model.Graph.TotalParameters * 100 // Matrix operations are expensive
		case "Conv", "ConvTranspose":
			constraints += model.Graph.TotalParameters * 200 // Convolutions are more expensive
		case "Relu":
			constraints += 10 // ReLU is relatively cheap
		case "Sigmoid", "Tanh":
			constraints += 100 // Activation functions require lookups
		case "Softmax":
			constraints += 500 // Softmax requires exp and division
		default:
			constraints += 50 // Default estimate
		}
	}

	return constraints
}

// PrepareForCircuitCompilation prepares a model for circuit compilation
func (mh *ModelHandler) PrepareForCircuitCompilation(model *ONNXModel) (*CircuitPreparation, error) {
	// Validate first
	validation, err := mh.ValidateModel(model)
	if err != nil {
		return nil, err
	}
	if !validation.Valid {
		return nil, fmt.Errorf("model validation failed: %v", validation.Errors)
	}

	// Create preparation result
	prep := &CircuitPreparation{
		ModelHash:        model.ModelHash,
		QuantizationParams: &QuantizationParams{
			Scale:       0.001,
			ZeroPoint:   0,
			BitWidth:    mh.config.QuantizationBits,
			IsSymmetric: true,
		},
		InputShapes:  make(map[string][]int64),
		OutputShapes: make(map[string][]int64),
		EstimatedConstraints: validation.EstimatedConstraints,
	}

	// Extract input/output shapes
	for _, input := range model.Graph.Inputs {
		prep.InputShapes[input.Name] = input.Shape
	}
	for _, output := range model.Graph.Outputs {
		prep.OutputShapes[output.Name] = output.Shape
	}

	// Generate calibration data request
	prep.CalibrationDataSpec = &CalibrationSpec{
		NumSamples:  100,
		InputRanges: mh.estimateInputRanges(model),
	}

	return prep, nil
}

// CircuitPreparation contains preparation data for circuit compilation
type CircuitPreparation struct {
	ModelHash            []byte                 `json:"model_hash"`
	QuantizationParams   *QuantizationParams    `json:"quantization_params"`
	InputShapes          map[string][]int64     `json:"input_shapes"`
	OutputShapes         map[string][]int64     `json:"output_shapes"`
	EstimatedConstraints int64                  `json:"estimated_constraints"`
	CalibrationDataSpec  *CalibrationSpec       `json:"calibration_data_spec"`
}

// CalibrationSpec specifies calibration data requirements
type CalibrationSpec struct {
	NumSamples  int                    `json:"num_samples"`
	InputRanges map[string]InputRange  `json:"input_ranges"`
}

// InputRange specifies expected input value ranges
type InputRange struct {
	Min float64 `json:"min"`
	Max float64 `json:"max"`
}

// estimateInputRanges estimates input value ranges
func (mh *ModelHandler) estimateInputRanges(model *ONNXModel) map[string]InputRange {
	ranges := make(map[string]InputRange)

	for _, input := range model.Graph.Inputs {
		// Default normalized range
		ranges[input.Name] = InputRange{Min: -1.0, Max: 1.0}
	}

	return ranges
}

// GenerateWitness generates a witness for proof generation
func (mh *ModelHandler) GenerateWitness(model *ONNXModel, inputData, outputData map[string][]float64) (*Witness, error) {
	witness := &Witness{
		IntermediateValues: make(map[string][]float64),
	}

	// Set input tensor
	if inputTensor, ok := inputData["input"]; ok {
		witness.InputTensor = inputTensor
	} else {
		return nil, fmt.Errorf("missing input tensor")
	}

	// Set output tensor
	if outputTensor, ok := outputData["output"]; ok {
		witness.OutputTensor = outputTensor
	} else if outputTensor, ok := outputData["probability"]; ok {
		witness.OutputTensor = outputTensor
	} else {
		return nil, fmt.Errorf("missing output tensor")
	}

	return witness, nil
}

// SerializeModel serializes an ONNX model for storage
func (mh *ModelHandler) SerializeModel(model *ONNXModel) ([]byte, error) {
	return json.Marshal(model)
}

// DeserializeModel deserializes an ONNX model from storage
func (mh *ModelHandler) DeserializeModel(data []byte) (*ONNXModel, error) {
	var model ONNXModel
	if err := json.Unmarshal(data, &model); err != nil {
		return nil, err
	}
	return &model, nil
}

// GetModelFingerprint returns a unique fingerprint for the model
func (mh *ModelHandler) GetModelFingerprint(model *ONNXModel) []byte {
	// Combine model hash with graph structure for a unique fingerprint
	data := bytes.NewBuffer(model.ModelHash)
	for _, node := range model.Graph.Nodes {
		data.WriteString(node.OpType)
	}
	hash := sha256.Sum256(data.Bytes())
	return hash[:]
}
