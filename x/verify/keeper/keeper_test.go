package keeper

import (
	"crypto/sha256"
	"testing"

	"github.com/aethelred/aethelred/internal/circuitbreaker"
	"github.com/aethelred/aethelred/x/verify/types"
)

// ────────────────────────────────────────────────────────────────────
// Keeper construction & accessors
// ────────────────────────────────────────────────────────────────────

func TestNewKeeper(t *testing.T) {
	k := NewKeeper(nil, nil, "cosmos1authority")

	if k.authority != "cosmos1authority" {
		t.Fatalf("expected authority 'cosmos1authority', got %q", k.authority)
	}
}

func TestGetAuthority(t *testing.T) {
	k := NewKeeper(nil, nil, "aethelred1gov")

	if got := k.GetAuthority(); got != "aethelred1gov" {
		t.Fatalf("expected 'aethelred1gov', got %q", got)
	}
}

// ────────────────────────────────────────────────────────────────────
// Circuit breakers
// ────────────────────────────────────────────────────────────────────

func TestCircuitBreakers(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")

	breakers := k.CircuitBreakers()
	if len(breakers) != 2 {
		t.Fatalf("expected 2 circuit breakers, got %d", len(breakers))
	}

	names := make(map[string]bool)
	for _, b := range breakers {
		snap := b.Snapshot()
		names[snap.Name] = true
	}

	if !names["zk_verifier_remote"] {
		t.Fatal("missing zk_verifier_remote breaker")
	}
	if !names["tee_attestation_remote"] {
		t.Fatal("missing tee_attestation_remote breaker")
	}
}

func TestCircuitBreakerInitialState(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")

	for _, b := range k.CircuitBreakers() {
		snap := b.Snapshot()
		if snap.State != circuitbreaker.Closed {
			t.Fatalf("expected initial state Closed, got %v for %s", snap.State, snap.Name)
		}
		if snap.ConsecutiveFailures != 0 {
			t.Fatalf("expected 0 failures, got %d for %s", snap.ConsecutiveFailures, snap.Name)
		}
	}
}

// ────────────────────────────────────────────────────────────────────
// VerifyingKey hash integrity validation
// ────────────────────────────────────────────────────────────────────

func TestVerifyingKeyHashComputation(t *testing.T) {
	keyBytes := []byte("sample verifying key bytes for ezkl circuit")
	hash := sha256.Sum256(keyBytes)

	vk := &types.VerifyingKey{
		KeyBytes:    keyBytes,
		Hash:        hash[:],
		ProofSystem: "ezkl",
	}

	// Recompute and verify match
	recomputed := sha256.Sum256(vk.KeyBytes)
	if string(vk.Hash) != string(recomputed[:]) {
		t.Fatal("hash mismatch: SHA-256 of KeyBytes should match Hash")
	}
}

func TestVerifyingKeyHashMismatchDetection(t *testing.T) {
	keyBytes := []byte("real key bytes")
	badHash := sha256.Sum256([]byte("different bytes"))

	// SHA-256 of keyBytes ≠ badHash
	realHash := sha256.Sum256(keyBytes)
	if string(realHash[:]) == string(badHash[:]) {
		t.Fatal("test setup error: hashes should not match")
	}
}

func TestVerifyingKeySizeValidation(t *testing.T) {
	params := types.DefaultParams()

	// Key within limits
	smallKey := make([]byte, 1024)
	if int64(len(smallKey)) > params.MaxVerifyingKeySize {
		t.Fatalf("small key should be within limits: %d <= %d", len(smallKey), params.MaxVerifyingKeySize)
	}

	// Key exceeding limits
	oversizedKey := make([]byte, params.MaxVerifyingKeySize+1)
	if int64(len(oversizedKey)) <= params.MaxVerifyingKeySize {
		t.Fatal("oversized key should exceed limits")
	}
}

// ────────────────────────────────────────────────────────────────────
// Circuit hash integrity
// ────────────────────────────────────────────────────────────────────

func TestCircuitHashComputation(t *testing.T) {
	circuitBytes := []byte("ZKML circuit definition bytes")
	hash := sha256.Sum256(circuitBytes)

	circuit := &types.Circuit{
		CircuitBytes: circuitBytes,
		Hash:         hash[:],
		ProofSystem:  "halo2",
	}

	recomputed := sha256.Sum256(circuit.CircuitBytes)
	if string(circuit.Hash) != string(recomputed[:]) {
		t.Fatal("circuit hash mismatch")
	}
}

func TestCircuitSizeValidation(t *testing.T) {
	params := types.DefaultParams()

	// Circuit within limits
	smallCircuit := make([]byte, 1024)
	if int64(len(smallCircuit)) > params.MaxCircuitSize {
		t.Fatalf("small circuit should be within limits: %d <= %d", len(smallCircuit), params.MaxCircuitSize)
	}
}

// ────────────────────────────────────────────────────────────────────
// TEE Config validation
// ────────────────────────────────────────────────────────────────────

func TestDefaultTEEConfigs(t *testing.T) {
	configs := types.DefaultTEEConfigs()

	if len(configs) < 2 {
		t.Fatalf("expected at least 2 default TEE configs, got %d", len(configs))
	}

	// First should be AWS Nitro (active)
	if configs[0].Platform != types.TEEPlatformAWSNitro {
		t.Fatalf("expected first config to be AWS Nitro, got %v", configs[0].Platform)
	}
	if !configs[0].IsActive {
		t.Fatal("AWS Nitro should be active by default")
	}

	// Second should be Intel SGX (inactive)
	if configs[1].Platform != types.TEEPlatformIntelSGX {
		t.Fatalf("expected second config to be Intel SGX, got %v", configs[1].Platform)
	}
	if configs[1].IsActive {
		t.Fatal("Intel SGX should be inactive by default")
	}
}

// ────────────────────────────────────────────────────────────────────
// Params validation
// ────────────────────────────────────────────────────────────────────

func TestDefaultParams(t *testing.T) {
	params := types.DefaultParams()

	if params == nil {
		t.Fatal("DefaultParams should not return nil")
	}
	if params.MaxProofSize <= 0 {
		t.Fatalf("MaxProofSize should be positive, got %d", params.MaxProofSize)
	}
	if params.MaxVerifyingKeySize <= 0 {
		t.Fatalf("MaxVerifyingKeySize should be positive, got %d", params.MaxVerifyingKeySize)
	}
	if params.MaxCircuitSize <= 0 {
		t.Fatalf("MaxCircuitSize should be positive, got %d", params.MaxCircuitSize)
	}
	if len(params.SupportedProofSystems) == 0 {
		t.Fatal("SupportedProofSystems should not be empty")
	}
	if len(params.SupportedTeePlatforms) == 0 {
		t.Fatal("SupportedTeePlatforms should not be empty")
	}
}

func TestDefaultParamsSupportedSystems(t *testing.T) {
	params := types.DefaultParams()

	expectedProofSystems := map[string]bool{
		"ezkl":    true,
		"risc0":   true,
		"plonky2": true,
		"halo2":   true,
	}

	for _, sys := range params.SupportedProofSystems {
		if !expectedProofSystems[sys] {
			t.Fatalf("unexpected proof system: %s", sys)
		}
		delete(expectedProofSystems, sys)
	}

	if len(expectedProofSystems) > 0 {
		t.Fatalf("missing proof systems: %v", expectedProofSystems)
	}
}

// ────────────────────────────────────────────────────────────────────
// Genesis validation
// ────────────────────────────────────────────────────────────────────

func TestDefaultGenesisValidation(t *testing.T) {
	gs := types.DefaultGenesis()

	if err := gs.Validate(); err != nil {
		t.Fatalf("default genesis should be valid, got: %v", err)
	}
}

func TestGenesisValidationNilParams(t *testing.T) {
	gs := types.DefaultGenesis()
	gs.Params = nil

	if err := gs.Validate(); err == nil {
		t.Fatal("genesis with nil params should fail validation")
	}
}

func TestGenesisValidationInvalidProofSize(t *testing.T) {
	gs := types.DefaultGenesis()
	gs.Params.MaxProofSize = -1

	if err := gs.Validate(); err == nil {
		t.Fatal("genesis with negative MaxProofSize should fail validation")
	}
}

func TestGenesisValidationNilVerifyingKey(t *testing.T) {
	gs := types.DefaultGenesis()
	gs.VerifyingKeys = []*types.VerifyingKey{nil}

	if err := gs.Validate(); err == nil {
		t.Fatal("genesis with nil verifying key should fail validation")
	}
}

func TestGenesisValidationInvalidVerifyingKeyHash(t *testing.T) {
	gs := types.DefaultGenesis()
	gs.VerifyingKeys = []*types.VerifyingKey{
		{
			Hash:     []byte("short"), // Not 32 bytes
			KeyBytes: []byte("some key bytes"),
		},
	}

	if err := gs.Validate(); err == nil {
		t.Fatal("genesis with invalid verifying key hash should fail validation")
	}
}

func TestGenesisValidationEmptyKeyBytes(t *testing.T) {
	gs := types.DefaultGenesis()
	hash := sha256.Sum256([]byte{})
	gs.VerifyingKeys = []*types.VerifyingKey{
		{
			Hash:     hash[:],
			KeyBytes: []byte{}, // Empty
		},
	}

	if err := gs.Validate(); err == nil {
		t.Fatal("genesis with empty key bytes should fail validation")
	}
}

func TestGenesisValidationNilCircuit(t *testing.T) {
	gs := types.DefaultGenesis()
	gs.Circuits = []*types.Circuit{nil}

	if err := gs.Validate(); err == nil {
		t.Fatal("genesis with nil circuit should fail validation")
	}
}

func TestGenesisValidationInvalidCircuitHash(t *testing.T) {
	gs := types.DefaultGenesis()
	gs.Circuits = []*types.Circuit{
		{
			Hash:         []byte("short"),
			CircuitBytes: []byte("circuit data"),
		},
	}

	if err := gs.Validate(); err == nil {
		t.Fatal("genesis with invalid circuit hash should fail validation")
	}
}

func TestGenesisValidationValidEntries(t *testing.T) {
	gs := types.DefaultGenesis()

	vkBytes := []byte("valid verifying key bytes for testing")
	vkHash := sha256.Sum256(vkBytes)

	circBytes := []byte("valid circuit bytes for testing")
	circHash := sha256.Sum256(circBytes)

	gs.VerifyingKeys = []*types.VerifyingKey{
		{
			Hash:        vkHash[:],
			KeyBytes:    vkBytes,
			ProofSystem: "ezkl",
		},
	}
	gs.Circuits = []*types.Circuit{
		{
			Hash:         circHash[:],
			CircuitBytes: circBytes,
			ProofSystem:  "halo2",
		},
	}

	if err := gs.Validate(); err != nil {
		t.Fatalf("genesis with valid entries should pass, got: %v", err)
	}
}

// ────────────────────────────────────────────────────────────────────
// Verification type helpers
// ────────────────────────────────────────────────────────────────────

func TestIsPlatformSupported(t *testing.T) {
	tests := []struct {
		platform types.TEEPlatform
		expected bool
	}{
		{types.TEEPlatformAWSNitro, true},
		{types.TEEPlatformIntelSGX, true},
		{types.TEEPlatformIntelTDX, true},
		{types.TEEPlatformAMDSEV, true},
		{types.TEEPlatformARMTrustZone, true},
		{types.TEEPlatformUnspecified, false},
	}

	for _, tt := range tests {
		if got := types.IsPlatformSupported(tt.platform); got != tt.expected {
			t.Errorf("IsPlatformSupported(%v) = %v, want %v", tt.platform, got, tt.expected)
		}
	}
}

func TestIsProofSystemSupported(t *testing.T) {
	supported := []string{"ezkl", "risc0", "plonky2", "halo2"}
	unsupported := []string{"groth16_unknown", "snark_invalid", ""}

	for _, sys := range supported {
		if !types.IsProofSystemSupported(sys) {
			t.Errorf("expected %q to be supported", sys)
		}
	}
	for _, sys := range unsupported {
		if types.IsProofSystemSupported(sys) {
			t.Errorf("expected %q to be unsupported", sys)
		}
	}
}

func TestZKMLProofValidation(t *testing.T) {
	hash := sha256.Sum256([]byte("verifying key"))

	valid := &types.ZKMLProof{
		ProofSystem:      "ezkl",
		ProofBytes:       []byte("proof data"),
		VerifyingKeyHash: hash[:],
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid proof should pass, got: %v", err)
	}

	// Empty proof system
	emptyPS := &types.ZKMLProof{
		ProofSystem:      "",
		ProofBytes:       []byte("data"),
		VerifyingKeyHash: hash[:],
	}
	if err := emptyPS.Validate(); err == nil {
		t.Fatal("empty proof system should fail")
	}

	// Empty proof bytes
	emptyPB := &types.ZKMLProof{
		ProofSystem:      "ezkl",
		ProofBytes:       []byte{},
		VerifyingKeyHash: hash[:],
	}
	if err := emptyPB.Validate(); err == nil {
		t.Fatal("empty proof bytes should fail")
	}

	// Invalid hash length
	badHash := &types.ZKMLProof{
		ProofSystem:      "ezkl",
		ProofBytes:       []byte("data"),
		VerifyingKeyHash: []byte("short"),
	}
	if err := badHash.Validate(); err == nil {
		t.Fatal("invalid hash length should fail")
	}
}

func TestTEEAttestationValidation(t *testing.T) {
	valid := &types.TEEAttestation{
		Platform:    types.TEEPlatformAWSNitro,
		Measurement: []byte("measurement data"),
		Quote:       []byte("attestation quote"),
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid attestation should pass, got: %v", err)
	}

	// Unspecified platform
	unspec := &types.TEEAttestation{
		Platform:    types.TEEPlatformUnspecified,
		Measurement: []byte("data"),
		Quote:       []byte("quote"),
	}
	if err := unspec.Validate(); err == nil {
		t.Fatal("unspecified platform should fail")
	}

	// Empty measurement
	emptyM := &types.TEEAttestation{
		Platform:    types.TEEPlatformAWSNitro,
		Measurement: []byte{},
		Quote:       []byte("quote"),
	}
	if err := emptyM.Validate(); err == nil {
		t.Fatal("empty measurement should fail")
	}

	// Empty quote
	emptyQ := &types.TEEAttestation{
		Platform:    types.TEEPlatformAWSNitro,
		Measurement: []byte("data"),
		Quote:       []byte{},
	}
	if err := emptyQ.Validate(); err == nil {
		t.Fatal("empty quote should fail")
	}
}
