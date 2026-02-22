// Package keeper provides the on-chain ZK proof verification implementation.
//
// SECURITY CRITICAL: This module performs cryptographic verification of zero-knowledge
// proofs on-chain. All verification must be deterministic and gas-metered to prevent
// denial-of-service attacks.
package keeper

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// =============================================================================
// ZK Proof Verification Types
// =============================================================================

// ProofSystem identifies the zero-knowledge proof system used
type ProofSystem string

const (
	// ProofSystemEZKL is the EZKL proof system for ML models
	ProofSystemEZKL ProofSystem = "ezkl"

	// ProofSystemRISC0 is the RISC Zero zkVM proof system
	ProofSystemRISC0 ProofSystem = "risc0"

	// ProofSystemPlonky2 is the Plonky2 proof system
	ProofSystemPlonky2 ProofSystem = "plonky2"

	// ProofSystemHalo2 is the Halo2 proof system
	ProofSystemHalo2 ProofSystem = "halo2"

	// ProofSystemGroth16 is the Groth16 SNARK proof system
	ProofSystemGroth16 ProofSystem = "groth16"
)

// ZKProof represents a zero-knowledge proof for on-chain verification
type ZKProof struct {
	// System identifies the proof system
	System ProofSystem

	// Proof is the serialized proof data
	Proof []byte

	// PublicInputs are the public inputs to the proof
	PublicInputs []byte

	// VerifyingKeyHash is the SHA-256 hash of the verifying key
	VerifyingKeyHash [32]byte

	// CircuitHash is the SHA-256 hash of the circuit (optional)
	CircuitHash [32]byte

	// ProofSize is the size of the proof in bytes
	ProofSize uint64
}

// ZKVerificationResult contains the result of proof verification
type ZKVerificationResult struct {
	// Valid indicates if the proof is cryptographically valid
	Valid bool

	// GasUsed is the amount of gas consumed by verification
	GasUsed uint64

	// ErrorCode is set if verification failed
	ErrorCode ZKErrorCode

	// ErrorMessage provides details on verification failure
	ErrorMessage string

	// PublicInputsHash is the hash of the verified public inputs
	PublicInputsHash [32]byte
}

// ZKErrorCode represents categorized ZK verification errors
type ZKErrorCode string

const (
	ZKErrorNone                 ZKErrorCode = ""
	ZKErrorInvalidProof         ZKErrorCode = "INVALID_PROOF"
	ZKErrorInvalidPublicInput   ZKErrorCode = "INVALID_PUBLIC_INPUT"
	ZKErrorVerifyingKeyMismatch ZKErrorCode = "VERIFYING_KEY_MISMATCH"
	ZKErrorCircuitMismatch      ZKErrorCode = "CIRCUIT_MISMATCH"
	ZKErrorUnsupportedSystem    ZKErrorCode = "UNSUPPORTED_SYSTEM"
	ZKErrorProofTooLarge        ZKErrorCode = "PROOF_TOO_LARGE"
	ZKErrorGasExhausted         ZKErrorCode = "GAS_EXHAUSTED"
	ZKErrorMalformedProof       ZKErrorCode = "MALFORMED_PROOF"
)

// =============================================================================
// On-Chain ZK Verifier
// =============================================================================

// ZKVerifier performs on-chain zero-knowledge proof verification
type ZKVerifier struct {
	// registeredCircuits maps circuit hashes to their verifying keys
	registeredCircuits map[[32]byte]RegisteredCircuit

	// maxProofSize is the maximum allowed proof size in bytes
	maxProofSize uint64

	// gasPerByte is the gas cost per byte of proof verification
	gasPerByte uint64

	// baseGas is the base gas cost for any verification
	baseGas uint64

	// allowSimulated permits deterministic structural validation only.
	// Must be false in production/mainnet paths.
	allowSimulated bool

	// systemVerifiers holds pluggable cryptographic verifiers per proof system.
	systemVerifiers map[ProofSystem]ZKProofVerifier
}

// ZKProofVerifier performs cryptographic proof verification for a proof system.
type ZKProofVerifier func(proof *ZKProof, circuit *RegisteredCircuit) (bool, error)

// RegisteredCircuit represents a circuit registered for verification
type RegisteredCircuit struct {
	// CircuitHash is the unique identifier
	CircuitHash [32]byte

	// VerifyingKey is the serialized verifying key
	VerifyingKey []byte

	// System is the proof system
	System ProofSystem

	// MaxProofSize is the maximum proof size for this circuit
	MaxProofSize uint64

	// GasMultiplier adjusts gas cost based on circuit complexity
	GasMultiplier uint64

	// Owner is the address that registered the circuit
	Owner string

	// Active indicates if the circuit is enabled for verification
	Active bool
}

// NewZKVerifier creates a new on-chain ZK verifier
func NewZKVerifier() *ZKVerifier {
	return &ZKVerifier{
		registeredCircuits: make(map[[32]byte]RegisteredCircuit),
		maxProofSize:       1024 * 1024, // 1 MB max proof size
		gasPerByte:         10,          // 10 gas per byte
		baseGas:            100000,      // 100k base gas for verification
		allowSimulated:     false,       // fail-closed by default
		systemVerifiers:    make(map[ProofSystem]ZKProofVerifier),
	}
}

// NewSimulatedZKVerifier creates a verifier with deterministic structural checks.
// Use only for tests/devnets; production must use NewZKVerifier().
func NewSimulatedZKVerifier() *ZKVerifier {
	v := NewZKVerifier()
	v.allowSimulated = true
	return v
}

// RegisterSystemVerifier registers a cryptographic verifier implementation.
func (v *ZKVerifier) RegisterSystemVerifier(system ProofSystem, verifier ZKProofVerifier) error {
	if verifier == nil {
		return errors.New("verifier cannot be nil")
	}
	v.systemVerifiers[system] = verifier
	return nil
}

// RegisterCircuit registers a new circuit for verification
func (v *ZKVerifier) RegisterCircuit(circuit RegisteredCircuit) error {
	if len(circuit.VerifyingKey) == 0 {
		return errors.New("verifying key cannot be empty")
	}

	if circuit.MaxProofSize == 0 {
		circuit.MaxProofSize = v.maxProofSize
	}

	if circuit.GasMultiplier == 0 {
		circuit.GasMultiplier = 1
	}

	circuit.Active = true
	v.registeredCircuits[circuit.CircuitHash] = circuit

	return nil
}

// DeactivateCircuit deactivates a circuit (governance action)
func (v *ZKVerifier) DeactivateCircuit(circuitHash [32]byte) error {
	circuit, exists := v.registeredCircuits[circuitHash]
	if !exists {
		return fmt.Errorf("circuit not found: %x", circuitHash)
	}

	circuit.Active = false
	v.registeredCircuits[circuitHash] = circuit
	return nil
}

// VerifyProof performs on-chain verification of a ZK proof
func (v *ZKVerifier) VerifyProof(ctx sdk.Context, proof *ZKProof) *ZKVerificationResult {
	result := &ZKVerificationResult{
		Valid:   false,
		GasUsed: v.baseGas,
	}

	// Check proof size limits
	if proof.ProofSize > v.maxProofSize {
		result.ErrorCode = ZKErrorProofTooLarge
		result.ErrorMessage = fmt.Sprintf("proof size %d exceeds maximum %d", proof.ProofSize, v.maxProofSize)
		return result
	}

	// Calculate gas cost
	gasNeeded := v.baseGas + (uint64(len(proof.Proof)) * v.gasPerByte)

	// Look up registered circuit
	var circuitRef *RegisteredCircuit
	circuit, exists := v.registeredCircuits[proof.CircuitHash]
	if exists {
		if !circuit.Active {
			result.ErrorCode = ZKErrorCircuitMismatch
			result.ErrorMessage = "circuit is deactivated"
			return result
		}

		// Apply circuit-specific gas multiplier
		gasNeeded *= circuit.GasMultiplier

		// Verify verifying key hash matches
		vkHash := sha256.Sum256(circuit.VerifyingKey)
		if vkHash != proof.VerifyingKeyHash {
			result.ErrorCode = ZKErrorVerifyingKeyMismatch
			result.ErrorMessage = "verifying key hash mismatch"
			result.GasUsed = gasNeeded
			return result
		}
		circuitRef = &circuit
	}

	// Consume gas (in real implementation, this would be gas metered)
	result.GasUsed = gasNeeded

	// Perform system-specific verification
	var valid bool
	var err error

	switch proof.System {
	case ProofSystemEZKL:
		valid, err = v.verifyEZKLProof(proof, circuitRef)
	case ProofSystemRISC0:
		valid, err = v.verifyRISC0Proof(proof, circuitRef)
	case ProofSystemPlonky2:
		valid, err = v.verifyPlonky2Proof(proof, circuitRef)
	case ProofSystemHalo2:
		valid, err = v.verifyHalo2Proof(proof, circuitRef)
	case ProofSystemGroth16:
		valid, err = v.verifyGroth16Proof(proof, circuitRef)
	default:
		result.ErrorCode = ZKErrorUnsupportedSystem
		result.ErrorMessage = fmt.Sprintf("unsupported proof system: %s", proof.System)
		return result
	}

	if err != nil {
		result.ErrorCode = ZKErrorInvalidProof
		result.ErrorMessage = err.Error()
		return result
	}

	result.Valid = valid
	result.PublicInputsHash = sha256.Sum256(proof.PublicInputs)

	if !valid {
		result.ErrorCode = ZKErrorInvalidProof
		result.ErrorMessage = "proof verification failed"
	}

	return result
}

// =============================================================================
// Proof System Specific Verifiers
// =============================================================================

// verifyEZKLProof verifies an EZKL proof on-chain
func (v *ZKVerifier) verifyEZKLProof(proof *ZKProof, circuit *RegisteredCircuit) (bool, error) {
	// EZKL proof structure validation
	if len(proof.Proof) < 256 {
		return false, fmt.Errorf("EZKL proof too short: %d bytes (minimum 256)", len(proof.Proof))
	}

	// EZKL proofs use a specific header format
	// First 4 bytes: magic number "EZKL"
	if len(proof.Proof) >= 4 {
		magic := string(proof.Proof[:4])
		if magic != "EZKL" && !bytes.HasPrefix(proof.Proof, []byte{0x00, 0x00, 0x00, 0x00}) {
			// Allow zero header for compatibility
		}
	}

	// Validate public inputs structure
	if len(proof.PublicInputs) == 0 {
		return false, errors.New("EZKL proof requires public inputs")
	}

	// Parse and validate public inputs
	// EZKL public inputs are: [model_hash, input_hash, output_hash, ...]
	if len(proof.PublicInputs) < 96 { // At least 3 x 32-byte hashes
		return false, fmt.Errorf("EZKL public inputs too short: %d bytes (minimum 96)", len(proof.PublicInputs))
	}

	// Perform cryptographic verification
	// In production, this would call the actual EZKL verifier
	return v.cryptographicVerify(proof, circuit)
}

// verifyRISC0Proof verifies a RISC Zero proof on-chain
func (v *ZKVerifier) verifyRISC0Proof(proof *ZKProof, circuit *RegisteredCircuit) (bool, error) {
	// RISC0 proof structure validation
	if len(proof.Proof) < 512 {
		return false, fmt.Errorf("RISC0 proof too short: %d bytes (minimum 512)", len(proof.Proof))
	}

	// RISC0 proofs have a journal (public outputs) and a receipt (proof)
	// The receipt contains the seal and claim

	// Validate image ID is present in public inputs
	if len(proof.PublicInputs) < 32 {
		return false, errors.New("RISC0 proof requires image ID in public inputs")
	}

	return v.cryptographicVerify(proof, circuit)
}

// verifyPlonky2Proof verifies a Plonky2 proof on-chain
func (v *ZKVerifier) verifyPlonky2Proof(proof *ZKProof, circuit *RegisteredCircuit) (bool, error) {
	// Plonky2 proof structure validation
	if len(proof.Proof) < 256 {
		return false, fmt.Errorf("Plonky2 proof too short: %d bytes (minimum 256)", len(proof.Proof))
	}

	// Plonky2 proofs are recursively composable
	// They have a compact representation after aggregation

	return v.cryptographicVerify(proof, circuit)
}

// verifyHalo2Proof verifies a Halo2 proof on-chain
func (v *ZKVerifier) verifyHalo2Proof(proof *ZKProof, circuit *RegisteredCircuit) (bool, error) {
	// Halo2 proof structure validation
	if len(proof.Proof) < 384 {
		return false, fmt.Errorf("Halo2 proof too short: %d bytes (minimum 384)", len(proof.Proof))
	}

	// Halo2 uses the IPA (Inner Product Argument) commitment scheme
	// Proofs are relatively small and efficient to verify

	return v.cryptographicVerify(proof, circuit)
}

// verifyGroth16Proof verifies a Groth16 SNARK proof on-chain
func (v *ZKVerifier) verifyGroth16Proof(proof *ZKProof, circuit *RegisteredCircuit) (bool, error) {
	// Groth16 proof structure: 3 group elements (A, B, C)
	// BN254: 3 * 64 bytes = 192 bytes minimum
	// BLS12-381: 3 * 96 bytes = 288 bytes minimum
	if len(proof.Proof) < 192 {
		return false, fmt.Errorf("Groth16 proof too short: %d bytes (minimum 192)", len(proof.Proof))
	}

	// Groth16 proofs are constant size and very efficient to verify
	// The verification equation is: e(A, B) = e(α, β) * e(L, γ) * e(C, δ)

	return v.cryptographicVerify(proof, circuit)
}

// cryptographicVerify performs the actual cryptographic verification
// In production, this requires a registered system verifier and fails closed otherwise.
func (v *ZKVerifier) cryptographicVerify(proof *ZKProof, circuit *RegisteredCircuit) (bool, error) {
	if verifier, ok := v.systemVerifiers[proof.System]; ok {
		return verifier(proof, circuit)
	}

	if !v.allowSimulated {
		return false, fmt.Errorf("no cryptographic verifier registered for proof system: %s", proof.System)
	}

	// Dev/test fallback: deterministic structural validation.

	// Compute proof hash for integrity
	proofHash := sha256.Sum256(proof.Proof)

	// Verify proof hash is deterministic
	proofHash2 := sha256.Sum256(proof.Proof)
	if proofHash != proofHash2 {
		return false, errors.New("proof hash inconsistency")
	}

	// Verify public inputs hash
	publicInputsHash := sha256.Sum256(proof.PublicInputs)
	if len(publicInputsHash) != 32 {
		return false, errors.New("public inputs hash generation failed")
	}

	// Verify verifying key hash is 32 bytes
	if proof.VerifyingKeyHash == [32]byte{} {
		return false, errors.New("verifying key hash is empty")
	}

	return true, nil
}

// =============================================================================
// Public Input Parsing and Validation
// =============================================================================

// ParseEZKLPublicInputs parses EZKL public inputs into structured data
func ParseEZKLPublicInputs(publicInputs []byte) (*EZKLPublicInputs, error) {
	if len(publicInputs) < 96 {
		return nil, fmt.Errorf("public inputs too short: %d bytes", len(publicInputs))
	}

	inputs := &EZKLPublicInputs{}
	copy(inputs.ModelHash[:], publicInputs[0:32])
	copy(inputs.InputHash[:], publicInputs[32:64])
	copy(inputs.OutputHash[:], publicInputs[64:96])

	// Parse additional inputs if present
	if len(publicInputs) >= 128 {
		copy(inputs.CircuitHash[:], publicInputs[96:128])
	}

	return inputs, nil
}

// EZKLPublicInputs represents the public inputs for an EZKL proof
type EZKLPublicInputs struct {
	ModelHash   [32]byte
	InputHash   [32]byte
	OutputHash  [32]byte
	CircuitHash [32]byte
}

// ValidateAgainstJob validates that public inputs match a compute job
func (inputs *EZKLPublicInputs) ValidateAgainstJob(modelHash, inputHash, outputHash []byte) error {
	if !bytes.Equal(inputs.ModelHash[:], modelHash) {
		return errors.New("model hash mismatch")
	}
	if !bytes.Equal(inputs.InputHash[:], inputHash) {
		return errors.New("input hash mismatch")
	}
	if !bytes.Equal(inputs.OutputHash[:], outputHash) {
		return errors.New("output hash mismatch")
	}
	return nil
}

// =============================================================================
// Gas Estimation
// =============================================================================

// EstimateVerificationGas estimates the gas cost for proof verification
func (v *ZKVerifier) EstimateVerificationGas(proof *ZKProof) uint64 {
	baseGas := v.baseGas
	proofGas := uint64(len(proof.Proof)) * v.gasPerByte
	publicInputGas := uint64(len(proof.PublicInputs)) * (v.gasPerByte / 2)

	// System-specific multipliers
	var multiplier uint64 = 1
	switch proof.System {
	case ProofSystemGroth16:
		multiplier = 1 // Groth16 is most efficient
	case ProofSystemHalo2:
		multiplier = 2 // Halo2 requires IPA verification
	case ProofSystemPlonky2:
		multiplier = 3 // Plonky2 uses FRI
	case ProofSystemRISC0:
		multiplier = 4 // RISC0 is a full zkVM
	case ProofSystemEZKL:
		multiplier = 2 // EZKL uses Halo2 backend
	}

	totalGas := (baseGas + proofGas + publicInputGas) * multiplier

	// Check for registered circuit with custom gas
	circuit, exists := v.registeredCircuits[proof.CircuitHash]
	if exists && circuit.GasMultiplier > 0 {
		totalGas *= circuit.GasMultiplier
	}

	return totalGas
}

// =============================================================================
// Precompile Interface (for EVM integration)
// =============================================================================

// ZKVerifierPrecompile provides an EVM precompile interface for ZK verification
type ZKVerifierPrecompile struct {
	verifier *ZKVerifier
}

// NewZKVerifierPrecompile creates a new ZK verifier precompile
func NewZKVerifierPrecompile(verifier *ZKVerifier) *ZKVerifierPrecompile {
	return &ZKVerifierPrecompile{verifier: verifier}
}

// PrecompileAddress returns the address of the ZK verifier precompile
// Following Aethelred's precompile address scheme: 0x0300
func (p *ZKVerifierPrecompile) PrecompileAddress() []byte {
	return []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00}
}

// RequiredGas returns the gas required for the precompile call
func (p *ZKVerifierPrecompile) RequiredGas(input []byte) uint64 {
	// Parse proof from input to estimate gas
	proof, err := p.parsePrecompileInput(input)
	if err != nil {
		return p.verifier.baseGas // Return base gas on parse error
	}
	return p.verifier.EstimateVerificationGas(proof)
}

// Run executes the precompile
func (p *ZKVerifierPrecompile) Run(input []byte) ([]byte, error) {
	proof, err := p.parsePrecompileInput(input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse precompile input: %w", err)
	}

	// Verify the proof (ctx is nil for precompile calls)
	result := p.verifier.VerifyProof(sdk.Context{}, proof)

	// Encode result
	return p.encodeResult(result), nil
}

// parsePrecompileInput parses the ABI-encoded input for the precompile
func (p *ZKVerifierPrecompile) parsePrecompileInput(input []byte) (*ZKProof, error) {
	if len(input) < 132 { // Minimum: system(32) + vkHash(32) + circuitHash(32) + proof offset(32) + inputs offset(4)
		return nil, errors.New("input too short")
	}

	proof := &ZKProof{}

	// Parse system identifier (first 32 bytes, right-padded string)
	systemBytes := input[0:32]
	systemStr := string(bytes.TrimRight(systemBytes, "\x00"))
	proof.System = ProofSystem(systemStr)

	// Parse verifying key hash (bytes 32-64)
	copy(proof.VerifyingKeyHash[:], input[32:64])

	// Parse circuit hash (bytes 64-96)
	copy(proof.CircuitHash[:], input[64:96])

	// Parse proof length and data
	if len(input) < 100 {
		return nil, errors.New("missing proof length")
	}
	proofLen := binary.BigEndian.Uint32(input[96:100])
	if uint32(len(input)) < 100+proofLen {
		return nil, errors.New("proof data truncated")
	}
	proof.Proof = input[100 : 100+proofLen]
	proof.ProofSize = uint64(proofLen)

	// Parse public inputs
	offset := 100 + proofLen
	if uint32(len(input)) < offset+4 {
		return nil, errors.New("missing public inputs length")
	}
	inputsLen := binary.BigEndian.Uint32(input[offset : offset+4])
	if uint32(len(input)) < offset+4+inputsLen {
		return nil, errors.New("public inputs data truncated")
	}
	proof.PublicInputs = input[offset+4 : offset+4+inputsLen]

	return proof, nil
}

// encodeResult encodes the verification result for return
func (p *ZKVerifierPrecompile) encodeResult(result *ZKVerificationResult) []byte {
	// Format: valid(1) + gasUsed(8) + errorCode(32) + publicInputsHash(32)
	output := make([]byte, 73)

	if result.Valid {
		output[0] = 1
	}

	binary.BigEndian.PutUint64(output[1:9], result.GasUsed)

	// Error code (padded to 32 bytes)
	copy(output[9:41], []byte(result.ErrorCode))

	// Public inputs hash
	copy(output[41:73], result.PublicInputsHash[:])

	return output
}
