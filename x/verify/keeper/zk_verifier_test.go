package keeper

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func TestZKVerifierRegisterDeactivate(t *testing.T) {
	v := NewSimulatedZKVerifier()
	var hash [32]byte
	hash[0] = 0x01

	if err := v.RegisterCircuit(RegisteredCircuit{CircuitHash: hash}); err == nil {
		t.Fatalf("expected error for empty verifying key")
	}

	vk := []byte{0x01, 0x02}
	circuit := RegisteredCircuit{CircuitHash: hash, VerifyingKey: vk}
	if err := v.RegisterCircuit(circuit); err != nil {
		t.Fatalf("expected register to succeed, got %v", err)
	}

	stored := v.registeredCircuits[hash]
	if !stored.Active {
		t.Fatalf("expected circuit active")
	}
	if stored.MaxProofSize == 0 {
		t.Fatalf("expected default max proof size")
	}
	if stored.GasMultiplier == 0 {
		t.Fatalf("expected default gas multiplier")
	}

	var missing [32]byte
	missing[0] = 0x02
	if err := v.DeactivateCircuit(missing); err == nil {
		t.Fatalf("expected error for missing circuit")
	}

	if err := v.DeactivateCircuit(hash); err != nil {
		t.Fatalf("expected deactivate to succeed, got %v", err)
	}
	if v.registeredCircuits[hash].Active {
		t.Fatalf("expected circuit to be inactive")
	}
}

func TestZKVerifierVerifyProofErrors(t *testing.T) {
	v := NewSimulatedZKVerifier()

	// Proof too large
	proof := &ZKProof{ProofSize: v.maxProofSize + 1}
	result := v.VerifyProof(sdk.Context{}, proof)
	if result.ErrorCode != ZKErrorProofTooLarge {
		t.Fatalf("expected proof too large error")
	}

	// Unsupported system
	proof = &ZKProof{System: ProofSystem("unknown"), ProofSize: 0}
	result = v.VerifyProof(sdk.Context{}, proof)
	if result.ErrorCode != ZKErrorUnsupportedSystem {
		t.Fatalf("expected unsupported system error")
	}
}

func TestZKVerifierFailsClosedWithoutSystemVerifier(t *testing.T) {
	v := NewZKVerifier()

	proof := &ZKProof{
		System:           ProofSystemGroth16,
		Proof:            bytes.Repeat([]byte{0x01}, 192),
		PublicInputs:     []byte{},
		VerifyingKeyHash: [32]byte{0x01},
		ProofSize:        192,
	}

	result := v.VerifyProof(sdk.Context{}, proof)
	if result.Valid {
		t.Fatalf("expected strict verifier to fail closed without system verifier")
	}
	if result.ErrorCode != ZKErrorInvalidProof {
		t.Fatalf("expected invalid proof error code, got %s", result.ErrorCode)
	}
	if result.ErrorMessage == "" {
		t.Fatalf("expected explicit error message for missing verifier")
	}
}

func TestZKVerifierVerifyingKeyMismatch(t *testing.T) {
	v := NewSimulatedZKVerifier()
	var hash [32]byte
	hash[0] = 0xAA

	vk := []byte{0x10, 0x20, 0x30}
	_ = v.RegisterCircuit(RegisteredCircuit{CircuitHash: hash, VerifyingKey: vk, GasMultiplier: 2})

	proof := &ZKProof{
		System:           ProofSystemEZKL,
		Proof:            bytes.Repeat([]byte{0x01}, 256),
		PublicInputs:     bytes.Repeat([]byte{0x02}, 96),
		ProofSize:        256,
		CircuitHash:      hash,
		VerifyingKeyHash: [32]byte{0xFF},
	}

	result := v.VerifyProof(sdk.Context{}, proof)
	if result.ErrorCode != ZKErrorVerifyingKeyMismatch {
		t.Fatalf("expected verifying key mismatch")
	}
	if result.GasUsed == 0 {
		t.Fatalf("expected gas used to be set")
	}
}

func TestZKVerifierInvalidProofStructure(t *testing.T) {
	v := NewSimulatedZKVerifier()

	proof := &ZKProof{
		System:       ProofSystemEZKL,
		Proof:        []byte{0x01},
		PublicInputs: []byte{},
		ProofSize:    1,
	}

	result := v.VerifyProof(sdk.Context{}, proof)
	if result.ErrorCode != ZKErrorInvalidProof {
		t.Fatalf("expected invalid proof error")
	}
}

func TestZKVerifierCircuitDeactivated(t *testing.T) {
	v := NewSimulatedZKVerifier()
	var hash [32]byte
	hash[0] = 0xCC
	vk := bytes.Repeat([]byte{0x01}, 32)
	_ = v.RegisterCircuit(RegisteredCircuit{CircuitHash: hash, VerifyingKey: vk})
	_ = v.DeactivateCircuit(hash)

	proof := &ZKProof{
		System:           ProofSystemEZKL,
		Proof:            bytes.Repeat([]byte{0x01}, 256),
		PublicInputs:     bytes.Repeat([]byte{0x02}, 96),
		ProofSize:        256,
		CircuitHash:      hash,
		VerifyingKeyHash: sha256.Sum256(vk),
	}

	result := v.VerifyProof(sdk.Context{}, proof)
	if result.ErrorCode != ZKErrorCircuitMismatch {
		t.Fatalf("expected circuit mismatch error")
	}
}

func TestZKVerifierEmptyVerifyingKeyHash(t *testing.T) {
	v := NewSimulatedZKVerifier()
	proof := &ZKProof{
		System:       ProofSystemEZKL,
		Proof:        bytes.Repeat([]byte{0x01}, 256),
		PublicInputs: bytes.Repeat([]byte{0x02}, 96),
		ProofSize:    256,
	}

	result := v.VerifyProof(sdk.Context{}, proof)
	if result.ErrorCode != ZKErrorInvalidProof {
		t.Fatalf("expected invalid proof error")
	}
}

func TestZKVerifierEZKLPublicInputsTooShort(t *testing.T) {
	v := NewSimulatedZKVerifier()
	proof := &ZKProof{
		System:           ProofSystemEZKL,
		Proof:            bytes.Repeat([]byte{0x01}, 256),
		PublicInputs:     []byte{0x01},
		ProofSize:        256,
		VerifyingKeyHash: [32]byte{0x01},
	}

	result := v.VerifyProof(sdk.Context{}, proof)
	if result.ErrorCode != ZKErrorInvalidProof {
		t.Fatalf("expected invalid proof error")
	}
}

func TestParseEZKLPublicInputs(t *testing.T) {
	short := []byte{0x01}
	if _, err := ParseEZKLPublicInputs(short); err == nil {
		t.Fatalf("expected error for short inputs")
	}

	model := bytes.Repeat([]byte{0x01}, 32)
	input := bytes.Repeat([]byte{0x02}, 32)
	output := bytes.Repeat([]byte{0x03}, 32)
	circuit := bytes.Repeat([]byte{0x04}, 32)

	payload := append(append(model, input...), output...)
	inputs, err := ParseEZKLPublicInputs(payload)
	if err != nil {
		t.Fatalf("expected parse to succeed, got %v", err)
	}
	if !bytes.Equal(inputs.ModelHash[:], model) {
		t.Fatalf("model hash mismatch")
	}

	payload = append(payload, circuit...)
	inputs, err = ParseEZKLPublicInputs(payload)
	if err != nil {
		t.Fatalf("expected parse to succeed with circuit hash, got %v", err)
	}
	if !bytes.Equal(inputs.CircuitHash[:], circuit) {
		t.Fatalf("circuit hash mismatch")
	}
}

func TestValidateAgainstJob(t *testing.T) {
	model := bytes.Repeat([]byte{0x01}, 32)
	input := bytes.Repeat([]byte{0x02}, 32)
	output := bytes.Repeat([]byte{0x03}, 32)

	payload := append(append(model, input...), output...)
	inputs, err := ParseEZKLPublicInputs(payload)
	if err != nil {
		t.Fatalf("expected parse to succeed, got %v", err)
	}

	if err := inputs.ValidateAgainstJob(model, input, output); err != nil {
		t.Fatalf("expected validation success, got %v", err)
	}

	if err := inputs.ValidateAgainstJob(model, input, bytes.Repeat([]byte{0x04}, 32)); err == nil {
		t.Fatalf("expected output hash mismatch error")
	}
}

func TestEstimateVerificationGas(t *testing.T) {
	v := NewSimulatedZKVerifier()
	proof := &ZKProof{
		System:       ProofSystemGroth16,
		Proof:        bytes.Repeat([]byte{0x01}, 10),
		PublicInputs: bytes.Repeat([]byte{0x02}, 20),
	}

	gas := v.EstimateVerificationGas(proof)
	expected := (v.baseGas + uint64(10)*v.gasPerByte + uint64(20)*(v.gasPerByte/2)) * 1
	if gas != expected {
		t.Fatalf("expected gas %d, got %d", expected, gas)
	}

	var hash [32]byte
	hash[0] = 0x11
	_ = v.RegisterCircuit(RegisteredCircuit{CircuitHash: hash, VerifyingKey: []byte{0x01}, GasMultiplier: 3})
	proof.CircuitHash = hash

	gas = v.EstimateVerificationGas(proof)
	if gas != expected*3 {
		t.Fatalf("expected circuit multiplier applied")
	}
}

func TestZKVerifierPrecompileParseAndEncode(t *testing.T) {
	v := NewSimulatedZKVerifier()
	p := NewZKVerifierPrecompile(v)

	input := make([]byte, 0, 140)
	system := make([]byte, 32)
	copy(system, []byte("ezkl"))
	vkHash := bytes.Repeat([]byte{0x01}, 32)
	circuitHash := bytes.Repeat([]byte{0x02}, 32)
	proof := bytes.Repeat([]byte{0x03}, 20)
	pubInputs := bytes.Repeat([]byte{0x04}, 12)

	input = append(input, system...)
	input = append(input, vkHash...)
	input = append(input, circuitHash...)
	proofLen := make([]byte, 4)
	binary.BigEndian.PutUint32(proofLen, uint32(len(proof)))
	input = append(input, proofLen...)
	input = append(input, proof...)
	inputsLen := make([]byte, 4)
	binary.BigEndian.PutUint32(inputsLen, uint32(len(pubInputs)))
	input = append(input, inputsLen...)
	input = append(input, pubInputs...)

	parsed, err := p.parsePrecompileInput(input)
	if err != nil {
		t.Fatalf("expected parse to succeed, got %v", err)
	}
	if parsed.System != ProofSystemEZKL {
		t.Fatalf("expected system ezkl")
	}

	result := &ZKVerificationResult{Valid: true, GasUsed: 123, ErrorCode: ZKErrorNone}
	out := p.encodeResult(result)
	if len(out) != 73 {
		t.Fatalf("expected encoded length 73, got %d", len(out))
	}
	if out[0] != 1 {
		t.Fatalf("expected valid flag set")
	}
}

func TestZKVerifierPrecompileParseErrors(t *testing.T) {
	v := NewSimulatedZKVerifier()
	p := NewZKVerifierPrecompile(v)

	if _, err := p.parsePrecompileInput([]byte{0x01}); err == nil {
		t.Fatalf("expected error for short input")
	}

	// Proof data truncated
	base := make([]byte, 0, 132)
	system := make([]byte, 32)
	base = append(base, system...)
	base = append(base, bytes.Repeat([]byte{0x01}, 32)...)
	base = append(base, bytes.Repeat([]byte{0x02}, 32)...)
	proofLen := make([]byte, 4)
	binary.BigEndian.PutUint32(proofLen, 100)
	base = append(base, proofLen...)
	base = append(base, bytes.Repeat([]byte{0x00}, 32)...)
	if _, err := p.parsePrecompileInput(base); err == nil {
		t.Fatalf("expected error for truncated proof data")
	}

	// Public inputs data truncated
	input := make([]byte, 0, 136)
	input = append(input, system...)
	input = append(input, bytes.Repeat([]byte{0x01}, 32)...)
	input = append(input, bytes.Repeat([]byte{0x02}, 32)...)
	binary.BigEndian.PutUint32(proofLen, 10)
	input = append(input, proofLen...)
	input = append(input, bytes.Repeat([]byte{0x03}, 10)...)
	inputsLen := make([]byte, 4)
	binary.BigEndian.PutUint32(inputsLen, 50)
	input = append(input, inputsLen...)
	if _, err := p.parsePrecompileInput(input); err == nil {
		t.Fatalf("expected error for truncated public inputs")
	}

	// Missing public inputs length
	input = make([]byte, 0, 120)
	input = append(input, system...)
	input = append(input, bytes.Repeat([]byte{0x01}, 32)...)
	input = append(input, bytes.Repeat([]byte{0x02}, 32)...)
	binary.BigEndian.PutUint32(proofLen, 4)
	input = append(input, proofLen...)
	input = append(input, bytes.Repeat([]byte{0x03}, 4)...)
	if _, err := p.parsePrecompileInput(input); err == nil {
		t.Fatalf("expected error for missing public inputs length")
	}
}

func TestZKVerifierPrecompileRequiredGasOnParseError(t *testing.T) {
	v := NewSimulatedZKVerifier()
	p := NewZKVerifierPrecompile(v)

	gas := p.RequiredGas([]byte{0x01})
	if gas != v.baseGas {
		t.Fatalf("expected base gas on parse error")
	}
}

func TestZKVerifierSystemSpecificMinProofSizes(t *testing.T) {
	v := NewSimulatedZKVerifier()

	cases := []struct {
		name            string
		system          ProofSystem
		minProofSize    int
		publicInputsLen int
	}{
		{name: "ezkl", system: ProofSystemEZKL, minProofSize: 256, publicInputsLen: 96},
		{name: "risc0", system: ProofSystemRISC0, minProofSize: 512, publicInputsLen: 32},
		{name: "plonky2", system: ProofSystemPlonky2, minProofSize: 256, publicInputsLen: 0},
		{name: "halo2", system: ProofSystemHalo2, minProofSize: 384, publicInputsLen: 0},
		{name: "groth16", system: ProofSystemGroth16, minProofSize: 192, publicInputsLen: 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proof := &ZKProof{
				System:           tc.system,
				Proof:            bytes.Repeat([]byte{0x01}, tc.minProofSize-1),
				PublicInputs:     bytes.Repeat([]byte{0x02}, tc.publicInputsLen),
				VerifyingKeyHash: [32]byte{0x01},
				ProofSize:        uint64(tc.minProofSize - 1),
			}

			result := v.VerifyProof(sdk.Context{}, proof)
			if result.ErrorCode != ZKErrorInvalidProof {
				t.Fatalf("expected invalid proof error for %s", tc.system)
			}
		})
	}
}

func TestZKVerifierEZKLRequiresPublicInputs(t *testing.T) {
	v := NewSimulatedZKVerifier()

	proof := &ZKProof{
		System:           ProofSystemEZKL,
		Proof:            bytes.Repeat([]byte{0x01}, 256),
		PublicInputs:     []byte{},
		VerifyingKeyHash: [32]byte{0x01},
		ProofSize:        256,
	}

	result := v.VerifyProof(sdk.Context{}, proof)
	if result.ErrorCode != ZKErrorInvalidProof {
		t.Fatalf("expected invalid proof error for missing public inputs")
	}
}

func TestZKVerifierRISC0RequiresImageID(t *testing.T) {
	v := NewSimulatedZKVerifier()

	proof := &ZKProof{
		System:           ProofSystemRISC0,
		Proof:            bytes.Repeat([]byte{0x01}, 512),
		PublicInputs:     bytes.Repeat([]byte{0x02}, 31),
		VerifyingKeyHash: [32]byte{0x01},
		ProofSize:        512,
	}

	result := v.VerifyProof(sdk.Context{}, proof)
	if result.ErrorCode != ZKErrorInvalidProof {
		t.Fatalf("expected invalid proof error for missing image ID")
	}
}

func TestZKVerifierValidProofs(t *testing.T) {
	v := NewSimulatedZKVerifier()

	cases := []struct {
		name         string
		system       ProofSystem
		proofLen     int
		publicInputs []byte
	}{
		{
			name:         "ezkl",
			system:       ProofSystemEZKL,
			proofLen:     256,
			publicInputs: bytes.Repeat([]byte{0x02}, 96),
		},
		{
			name:         "risc0",
			system:       ProofSystemRISC0,
			proofLen:     512,
			publicInputs: bytes.Repeat([]byte{0x02}, 32),
		},
		{
			name:         "groth16",
			system:       ProofSystemGroth16,
			proofLen:     192,
			publicInputs: []byte{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proof := &ZKProof{
				System:           tc.system,
				Proof:            bytes.Repeat([]byte{0x01}, tc.proofLen),
				PublicInputs:     tc.publicInputs,
				VerifyingKeyHash: [32]byte{0x0A},
				ProofSize:        uint64(tc.proofLen),
			}

			result := v.VerifyProof(sdk.Context{}, proof)
			if !result.Valid || result.ErrorCode != ZKErrorNone {
				t.Fatalf("expected valid proof for %s", tc.system)
			}

			expectedHash := sha256.Sum256(proof.PublicInputs)
			if result.PublicInputsHash != expectedHash {
				t.Fatalf("expected public inputs hash to match for %s", tc.system)
			}
		})
	}
}

func TestZKVerifierVerifyingKeyMatchValid(t *testing.T) {
	v := NewSimulatedZKVerifier()
	var hash [32]byte
	hash[0] = 0x42
	vk := bytes.Repeat([]byte{0x0B}, 32)

	if err := v.RegisterCircuit(RegisteredCircuit{CircuitHash: hash, VerifyingKey: vk, GasMultiplier: 2}); err != nil {
		t.Fatalf("expected register circuit success, got %v", err)
	}

	proof := &ZKProof{
		System:           ProofSystemEZKL,
		Proof:            bytes.Repeat([]byte{0x01}, 256),
		PublicInputs:     bytes.Repeat([]byte{0x02}, 96),
		VerifyingKeyHash: sha256.Sum256(vk),
		CircuitHash:      hash,
		ProofSize:        256,
	}

	result := v.VerifyProof(sdk.Context{}, proof)
	if !result.Valid || result.ErrorCode != ZKErrorNone {
		t.Fatalf("expected valid proof with matching verifying key hash")
	}
}
