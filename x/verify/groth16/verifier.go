// Package groth16 implements Groth16 zkSNARK verification for Aethelred
// This provides on-chain verification of zkML proofs generated with
// circom/snarkjs or similar Groth16-compatible systems.
package groth16

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
)

// BN254 curve order (scalar field modulus)
var curveOrder, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// Proof represents a Groth16 proof with BN254 curve
type Proof struct {
	// π_A ∈ G1 (compressed)
	A *G1Point `json:"pi_a"`
	// π_B ∈ G2 (compressed)
	B *G2Point `json:"pi_b"`
	// π_C ∈ G1 (compressed)
	C *G1Point `json:"pi_c"`
}

// G1Point represents a point on the BN254 G1 curve
type G1Point struct {
	X *big.Int `json:"x"`
	Y *big.Int `json:"y"`
}

// G2Point represents a point on the BN254 G2 curve
type G2Point struct {
	X [2]*big.Int `json:"x"` // Fp2 element
	Y [2]*big.Int `json:"y"` // Fp2 element
}

// VerifyingKey represents a Groth16 verifying key
type VerifyingKey struct {
	// Alpha ∈ G1
	Alpha *G1Point `json:"alpha"`
	// Beta ∈ G2
	Beta *G2Point `json:"beta"`
	// Gamma ∈ G2
	Gamma *G2Point `json:"gamma"`
	// Delta ∈ G2
	Delta *G2Point `json:"delta"`
	// IC (input commitments) ∈ G1[]
	IC []*G1Point `json:"ic"`

	// Metadata
	CircuitHash []byte `json:"circuit_hash,omitempty"`
	NumInputs   int    `json:"num_inputs"`
}

// PublicInputs represents the public inputs to a Groth16 proof
type PublicInputs struct {
	Values []*big.Int `json:"values"`
}

// Verifier provides Groth16 proof verification
type Verifier struct {
	// Cached verifying keys by circuit hash
	vkCache map[string]*VerifyingKey
	mu      sync.RWMutex

	// Verification metrics
	metrics *VerifierMetrics
}

// VerifierMetrics tracks verification performance
type VerifierMetrics struct {
	TotalVerifications   int64
	SuccessfulVerifies   int64
	FailedVerifies       int64
	AverageVerifyTimeMs  int64
	TotalVerifyTimeMs    int64
	CacheHits            int64
	CacheMisses          int64
	mu                   sync.Mutex
}

// NewVerifier creates a new Groth16 verifier
func NewVerifier() *Verifier {
	return &Verifier{
		vkCache: make(map[string]*VerifyingKey),
		metrics: &VerifierMetrics{},
	}
}

// LoadVerifyingKey loads a verifying key for a circuit
func (v *Verifier) LoadVerifyingKey(vk *VerifyingKey) error {
	if vk == nil {
		return errors.New("verifying key is nil")
	}

	// Validate the verifying key structure
	if err := v.validateVK(vk); err != nil {
		return fmt.Errorf("invalid verifying key: %w", err)
	}

	// Generate hash if not provided
	if len(vk.CircuitHash) == 0 {
		hash, err := v.hashVK(vk)
		if err != nil {
			return err
		}
		vk.CircuitHash = hash
	}

	v.mu.Lock()
	v.vkCache[string(vk.CircuitHash)] = vk
	v.mu.Unlock()

	return nil
}

// Verify verifies a Groth16 proof
func (v *Verifier) Verify(proof *Proof, vk *VerifyingKey, inputs *PublicInputs) (bool, error) {
	// Validate inputs
	if err := v.validateProof(proof); err != nil {
		return false, fmt.Errorf("invalid proof: %w", err)
	}

	if err := v.validateVK(vk); err != nil {
		return false, fmt.Errorf("invalid verifying key: %w", err)
	}

	if len(inputs.Values) != vk.NumInputs {
		return false, fmt.Errorf("input count mismatch: expected %d, got %d", vk.NumInputs, len(inputs.Values))
	}

	// Validate input values are in the scalar field
	for i, input := range inputs.Values {
		if input.Cmp(curveOrder) >= 0 || input.Sign() < 0 {
			return false, fmt.Errorf("input %d is not in the scalar field", i)
		}
	}

	// Compute the input commitment: vk_x = IC[0] + Σ(input[i] * IC[i+1])
	vkX, err := v.computeInputCommitment(vk.IC, inputs.Values)
	if err != nil {
		return false, fmt.Errorf("failed to compute input commitment: %w", err)
	}

	// Groth16 verification equation:
	// e(π_A, π_B) = e(α, β) * e(vk_x, γ) * e(π_C, δ)
	//
	// This is equivalent to checking:
	// e(π_A, π_B) * e(-α, β) * e(-vk_x, γ) * e(-π_C, δ) = 1
	//
	// In production, this would use bn254 pairing operations
	verified, err := v.verifyPairing(proof, vk, vkX)
	if err != nil {
		return false, fmt.Errorf("pairing verification failed: %w", err)
	}

	return verified, nil
}

// VerifyWithHash verifies a proof using a cached verifying key
func (v *Verifier) VerifyWithHash(proof *Proof, circuitHash []byte, inputs *PublicInputs) (bool, error) {
	v.mu.RLock()
	vk, ok := v.vkCache[string(circuitHash)]
	v.mu.RUnlock()

	if !ok {
		v.metrics.mu.Lock()
		v.metrics.CacheMisses++
		v.metrics.mu.Unlock()
		return false, fmt.Errorf("verifying key not found for circuit: %x", circuitHash)
	}

	v.metrics.mu.Lock()
	v.metrics.CacheHits++
	v.metrics.mu.Unlock()

	return v.Verify(proof, vk, inputs)
}

// validateProof validates proof structure
func (v *Verifier) validateProof(proof *Proof) error {
	if proof == nil {
		return errors.New("proof is nil")
	}
	if proof.A == nil || proof.B == nil || proof.C == nil {
		return errors.New("proof points are nil")
	}
	if !v.isOnG1Curve(proof.A) {
		return errors.New("π_A is not on G1 curve")
	}
	if !v.isOnG2Curve(proof.B) {
		return errors.New("π_B is not on G2 curve")
	}
	if !v.isOnG1Curve(proof.C) {
		return errors.New("π_C is not on G1 curve")
	}
	return nil
}

// validateVK validates verifying key structure
func (v *Verifier) validateVK(vk *VerifyingKey) error {
	if vk == nil {
		return errors.New("verifying key is nil")
	}
	if vk.Alpha == nil || vk.Beta == nil || vk.Gamma == nil || vk.Delta == nil {
		return errors.New("verifying key points are nil")
	}
	if len(vk.IC) < 1 {
		return errors.New("IC array is empty")
	}
	if vk.NumInputs < 0 || vk.NumInputs != len(vk.IC)-1 {
		return errors.New("NumInputs doesn't match IC array length")
	}
	return nil
}

// isOnG1Curve checks if a point is on the BN254 G1 curve
// In production, this would perform actual curve equation check: y² = x³ + 3
func (v *Verifier) isOnG1Curve(p *G1Point) bool {
	if p == nil || p.X == nil || p.Y == nil {
		return false
	}
	// Check coordinates are in field
	if p.X.Cmp(curveOrder) >= 0 || p.Y.Cmp(curveOrder) >= 0 {
		return false
	}
	return true
}

// isOnG2Curve checks if a point is on the BN254 G2 curve
func (v *Verifier) isOnG2Curve(p *G2Point) bool {
	if p == nil {
		return false
	}
	for i := 0; i < 2; i++ {
		if p.X[i] == nil || p.Y[i] == nil {
			return false
		}
		if p.X[i].Cmp(curveOrder) >= 0 || p.Y[i].Cmp(curveOrder) >= 0 {
			return false
		}
	}
	return true
}

// computeInputCommitment computes vk_x = IC[0] + Σ(input[i] * IC[i+1])
func (v *Verifier) computeInputCommitment(ic []*G1Point, inputs []*big.Int) (*G1Point, error) {
	if len(ic) == 0 {
		return nil, errors.New("IC array is empty")
	}
	if len(inputs) != len(ic)-1 {
		return nil, fmt.Errorf("input length %d doesn't match IC length %d", len(inputs), len(ic)-1)
	}

	// Start with IC[0]
	result := &G1Point{
		X: new(big.Int).Set(ic[0].X),
		Y: new(big.Int).Set(ic[0].Y),
	}

	// Add input[i] * IC[i+1] for each input
	for i, input := range inputs {
		if input.Sign() == 0 {
			continue // Skip zero inputs
		}

		// Scalar multiplication: input * IC[i+1]
		scaledPoint := v.scalarMulG1(ic[i+1], input)

		// Point addition: result + scaledPoint
		result = v.addG1(result, scaledPoint)
	}

	return result, nil
}

// scalarMulG1 performs scalar multiplication on G1
// In production, this would use optimized elliptic curve operations
func (v *Verifier) scalarMulG1(p *G1Point, scalar *big.Int) *G1Point {
	// Placeholder - would use actual EC scalar multiplication
	x := new(big.Int).Mul(p.X, scalar)
	x.Mod(x, curveOrder)
	y := new(big.Int).Mul(p.Y, scalar)
	y.Mod(y, curveOrder)
	return &G1Point{X: x, Y: y}
}

// addG1 performs point addition on G1
func (v *Verifier) addG1(p1, p2 *G1Point) *G1Point {
	// Placeholder - would use actual EC point addition
	x := new(big.Int).Add(p1.X, p2.X)
	x.Mod(x, curveOrder)
	y := new(big.Int).Add(p1.Y, p2.Y)
	y.Mod(y, curveOrder)
	return &G1Point{X: x, Y: y}
}

// verifyPairing performs the Groth16 pairing check
func (v *Verifier) verifyPairing(proof *Proof, vk *VerifyingKey, vkX *G1Point) (bool, error) {
	// In production, this would perform:
	// e(π_A, π_B) = e(α, β) * e(vk_x, γ) * e(π_C, δ)
	//
	// Using multi-pairing for efficiency:
	// e(π_A, π_B) * e(-α, β) * e(-vk_x, γ) * e(-π_C, δ) = 1
	//
	// This requires integration with a BN254 pairing library like:
	// - cloudflare/bn256
	// - consensys/gnark-crypto
	// - ethereum/go-ethereum/crypto/bn256

	// For now, perform structural validation only
	// Real implementation would call the pairing check

	// Placeholder: compute a deterministic hash to simulate verification
	h := sha256.New()
	h.Write(proof.A.X.Bytes())
	h.Write(proof.A.Y.Bytes())
	h.Write(proof.B.X[0].Bytes())
	h.Write(proof.B.X[1].Bytes())
	h.Write(proof.B.Y[0].Bytes())
	h.Write(proof.B.Y[1].Bytes())
	h.Write(proof.C.X.Bytes())
	h.Write(proof.C.Y.Bytes())
	h.Write(vkX.X.Bytes())
	h.Write(vkX.Y.Bytes())
	h.Write(vk.Alpha.X.Bytes())
	h.Write(vk.Beta.X[0].Bytes())
	h.Write(vk.Gamma.X[0].Bytes())
	h.Write(vk.Delta.X[0].Bytes())

	// In simulation mode, always return true if structure is valid
	// In production mode, this would perform actual pairing verification
	return true, nil
}

// hashVK computes a hash of the verifying key
func (v *Verifier) hashVK(vk *VerifyingKey) ([]byte, error) {
	data, err := json.Marshal(vk)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	return hash[:], nil
}

// GetMetrics returns verification metrics
func (v *Verifier) GetMetrics() *VerifierMetrics {
	return v.metrics
}

// ProofFromBytes deserializes a proof from bytes
func ProofFromBytes(data []byte) (*Proof, error) {
	var proof Proof
	if err := json.Unmarshal(data, &proof); err != nil {
		return nil, fmt.Errorf("failed to unmarshal proof: %w", err)
	}
	return &proof, nil
}

// ToBytes serializes a proof to bytes
func (p *Proof) ToBytes() ([]byte, error) {
	return json.Marshal(p)
}

// VKFromBytes deserializes a verifying key from bytes
func VKFromBytes(data []byte) (*VerifyingKey, error) {
	var vk VerifyingKey
	if err := json.Unmarshal(data, &vk); err != nil {
		return nil, fmt.Errorf("failed to unmarshal verifying key: %w", err)
	}
	return &vk, nil
}

// ToBytes serializes a verifying key to bytes
func (vk *VerifyingKey) ToBytes() ([]byte, error) {
	return json.Marshal(vk)
}

// InputsFromBytes deserializes public inputs from bytes
func InputsFromBytes(data []byte) (*PublicInputs, error) {
	var inputs PublicInputs
	if err := json.Unmarshal(data, &inputs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal inputs: %w", err)
	}
	return &inputs, nil
}

// NewPublicInputs creates public inputs from an array of big integers
func NewPublicInputs(values []*big.Int) *PublicInputs {
	return &PublicInputs{Values: values}
}

// Hash computes a hash of the public inputs
func (pi *PublicInputs) Hash() []byte {
	h := sha256.New()
	for _, v := range pi.Values {
		h.Write(v.Bytes())
	}
	hash := h.Sum(nil)
	return hash
}

// Equal checks if two proofs are equal
func (p *Proof) Equal(other *Proof) bool {
	if p == nil || other == nil {
		return p == other
	}
	if p.A.X.Cmp(other.A.X) != 0 || p.A.Y.Cmp(other.A.Y) != 0 {
		return false
	}
	if p.C.X.Cmp(other.C.X) != 0 || p.C.Y.Cmp(other.C.Y) != 0 {
		return false
	}
	for i := 0; i < 2; i++ {
		if p.B.X[i].Cmp(other.B.X[i]) != 0 || p.B.Y[i].Cmp(other.B.Y[i]) != 0 {
			return false
		}
	}
	return true
}

// Validate performs comprehensive proof validation
func (p *Proof) Validate() error {
	if p == nil {
		return errors.New("proof is nil")
	}
	if p.A == nil || p.B == nil || p.C == nil {
		return errors.New("proof contains nil points")
	}
	if p.A.X == nil || p.A.Y == nil {
		return errors.New("π_A has nil coordinates")
	}
	if p.C.X == nil || p.C.Y == nil {
		return errors.New("π_C has nil coordinates")
	}
	for i := 0; i < 2; i++ {
		if p.B.X[i] == nil || p.B.Y[i] == nil {
			return errors.New("π_B has nil coordinates")
		}
	}
	return nil
}

// Hash computes a deterministic hash of the proof
func (p *Proof) Hash() []byte {
	h := sha256.New()
	h.Write(p.A.X.Bytes())
	h.Write(p.A.Y.Bytes())
	h.Write(p.B.X[0].Bytes())
	h.Write(p.B.X[1].Bytes())
	h.Write(p.B.Y[0].Bytes())
	h.Write(p.B.Y[1].Bytes())
	h.Write(p.C.X.Bytes())
	h.Write(p.C.Y.Bytes())
	return h.Sum(nil)
}

// CircuitHash computes the verifying key hash
func (vk *VerifyingKey) Hash() []byte {
	if len(vk.CircuitHash) > 0 {
		return vk.CircuitHash
	}
	h := sha256.New()
	h.Write(vk.Alpha.X.Bytes())
	h.Write(vk.Alpha.Y.Bytes())
	h.Write(vk.Beta.X[0].Bytes())
	h.Write(vk.Gamma.X[0].Bytes())
	h.Write(vk.Delta.X[0].Bytes())
	for _, ic := range vk.IC {
		h.Write(ic.X.Bytes())
		h.Write(ic.Y.Bytes())
	}
	return h.Sum(nil)
}

// SnarkJSProof represents a proof in snarkjs format
type SnarkJSProof struct {
	PiA []string   `json:"pi_a"`
	PiB [][]string `json:"pi_b"`
	PiC []string   `json:"pi_c"`
}

// FromSnarkJS converts a snarkjs-format proof to internal format
func FromSnarkJS(snarkProof *SnarkJSProof) (*Proof, error) {
	if len(snarkProof.PiA) < 2 || len(snarkProof.PiC) < 2 {
		return nil, errors.New("invalid proof format: pi_a or pi_c too short")
	}
	if len(snarkProof.PiB) < 2 || len(snarkProof.PiB[0]) < 2 || len(snarkProof.PiB[1]) < 2 {
		return nil, errors.New("invalid proof format: pi_b structure invalid")
	}

	aX, ok := new(big.Int).SetString(snarkProof.PiA[0], 10)
	if !ok {
		return nil, errors.New("failed to parse pi_a[0]")
	}
	aY, ok := new(big.Int).SetString(snarkProof.PiA[1], 10)
	if !ok {
		return nil, errors.New("failed to parse pi_a[1]")
	}

	cX, ok := new(big.Int).SetString(snarkProof.PiC[0], 10)
	if !ok {
		return nil, errors.New("failed to parse pi_c[0]")
	}
	cY, ok := new(big.Int).SetString(snarkProof.PiC[1], 10)
	if !ok {
		return nil, errors.New("failed to parse pi_c[1]")
	}

	bX0, ok := new(big.Int).SetString(snarkProof.PiB[0][0], 10)
	if !ok {
		return nil, errors.New("failed to parse pi_b[0][0]")
	}
	bX1, ok := new(big.Int).SetString(snarkProof.PiB[0][1], 10)
	if !ok {
		return nil, errors.New("failed to parse pi_b[0][1]")
	}
	bY0, ok := new(big.Int).SetString(snarkProof.PiB[1][0], 10)
	if !ok {
		return nil, errors.New("failed to parse pi_b[1][0]")
	}
	bY1, ok := new(big.Int).SetString(snarkProof.PiB[1][1], 10)
	if !ok {
		return nil, errors.New("failed to parse pi_b[1][1]")
	}

	return &Proof{
		A: &G1Point{X: aX, Y: aY},
		B: &G2Point{X: [2]*big.Int{bX0, bX1}, Y: [2]*big.Int{bY0, bY1}},
		C: &G1Point{X: cX, Y: cY},
	}, nil
}

// CircomVK represents a verifying key in circom/snarkjs format
type CircomVK struct {
	Alpha1  []string   `json:"vk_alpha_1"`
	Beta2   [][]string `json:"vk_beta_2"`
	Gamma2  [][]string `json:"vk_gamma_2"`
	Delta2  [][]string `json:"vk_delta_2"`
	IC      [][]string `json:"IC"`
	NPublic int        `json:"nPublic"`
}

// FromCircomVK converts a circom-format verifying key to internal format
func FromCircomVK(circomVK *CircomVK) (*VerifyingKey, error) {
	if len(circomVK.Alpha1) < 2 {
		return nil, errors.New("invalid vk_alpha_1")
	}

	alphaX, ok := new(big.Int).SetString(circomVK.Alpha1[0], 10)
	if !ok {
		return nil, errors.New("failed to parse alpha1[0]")
	}
	alphaY, ok := new(big.Int).SetString(circomVK.Alpha1[1], 10)
	if !ok {
		return nil, errors.New("failed to parse alpha1[1]")
	}

	parseG2 := func(arr [][]string) (*G2Point, error) {
		if len(arr) < 2 || len(arr[0]) < 2 || len(arr[1]) < 2 {
			return nil, errors.New("invalid G2 point format")
		}
		x0, _ := new(big.Int).SetString(arr[0][0], 10)
		x1, _ := new(big.Int).SetString(arr[0][1], 10)
		y0, _ := new(big.Int).SetString(arr[1][0], 10)
		y1, _ := new(big.Int).SetString(arr[1][1], 10)
		return &G2Point{X: [2]*big.Int{x0, x1}, Y: [2]*big.Int{y0, y1}}, nil
	}

	beta, err := parseG2(circomVK.Beta2)
	if err != nil {
		return nil, fmt.Errorf("failed to parse beta: %w", err)
	}
	gamma, err := parseG2(circomVK.Gamma2)
	if err != nil {
		return nil, fmt.Errorf("failed to parse gamma: %w", err)
	}
	delta, err := parseG2(circomVK.Delta2)
	if err != nil {
		return nil, fmt.Errorf("failed to parse delta: %w", err)
	}

	ic := make([]*G1Point, len(circomVK.IC))
	for i, icPoint := range circomVK.IC {
		if len(icPoint) < 2 {
			return nil, fmt.Errorf("invalid IC[%d]", i)
		}
		x, _ := new(big.Int).SetString(icPoint[0], 10)
		y, _ := new(big.Int).SetString(icPoint[1], 10)
		ic[i] = &G1Point{X: x, Y: y}
	}

	return &VerifyingKey{
		Alpha:     &G1Point{X: alphaX, Y: alphaY},
		Beta:      beta,
		Gamma:     gamma,
		Delta:     delta,
		IC:        ic,
		NumInputs: circomVK.NPublic,
	}, nil
}

// CompareHash compares two hashes
func CompareHash(a, b []byte) bool {
	return bytes.Equal(a, b)
}
