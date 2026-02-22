package keeper

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"cosmossdk.io/log"
	"cosmossdk.io/store"
	"cosmossdk.io/store/metrics"
	storetypes "cosmossdk.io/store/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	vtypes "github.com/aethelred/aethelred/x/verify/types"
)

func createVerifyKeeper(t *testing.T) (Keeper, sdk.Context) {
	t.Helper()

	storeKey := storetypes.NewKVStoreKey(vtypes.StoreKey)
	memStoreKey := storetypes.NewMemoryStoreKey(vtypes.MemStoreKey)
	db := dbm.NewMemDB()

	stateStore := store.NewCommitMultiStore(db, log.NewNopLogger(), metrics.NewNoOpMetrics())
	stateStore.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, db)
	stateStore.MountStoreWithDB(memStoreKey, storetypes.StoreTypeMemory, nil)
	require.NoError(t, stateStore.LoadLatestVersion())

	registry := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(registry)
	storeService := runtime.NewKVStoreService(storeKey)

	ctx := sdk.NewContext(stateStore, tmproto.Header{
		ChainID: "aethelred-test-verify",
		Height:  100,
		Time:    time.Now().UTC(),
	}, false, log.NewNopLogger())
	ctx = ctx.WithEventManager(sdk.NewEventManager())

	k := NewKeeper(cdc, storeService, "authority")
	return k, ctx
}

func mustSetVerifyParams(t *testing.T, k Keeper, ctx sdk.Context, allowSim bool, supported []string) *vtypes.Params {
	t.Helper()
	params := vtypes.DefaultParams()
	params.AllowSimulated = allowSim
	if supported != nil {
		params.SupportedProofSystems = supported
	}
	require.NoError(t, k.SetParams(ctx, params))
	return params
}

func TestRegistryKeyCircuitLifecycle(t *testing.T) {
	k, ctx := createVerifyKeeper(t)
	params := vtypes.DefaultParams()
	params.MaxVerifyingKeySize = 64
	params.MaxCircuitSize = 64
	require.NoError(t, k.SetParams(ctx, params))

	vk := &vtypes.VerifyingKey{
		KeyBytes:     []byte("valid-verifying-key"),
		ProofSystem:  "ezkl",
		RegisteredBy: "governance",
		IsActive:     true,
	}
	require.NoError(t, k.RegisterVerifyingKey(ctx, vk))

	vkHash := sha256.Sum256(vk.KeyBytes)
	require.Equal(t, vkHash[:], vk.Hash)
	gotVK, err := k.GetVerifyingKey(ctx, vkHash[:])
	require.NoError(t, err)
	require.Equal(t, "ezkl", gotVK.ProofSystem)

	require.ErrorContains(t, k.RegisterVerifyingKey(ctx, &vtypes.VerifyingKey{
		KeyBytes: []byte("valid-verifying-key"),
	}), "already registered")

	badHash := sha256.Sum256([]byte("different"))
	require.ErrorContains(t, k.RegisterVerifyingKey(ctx, &vtypes.VerifyingKey{
		KeyBytes: []byte("another-key"),
		Hash:     badHash[:],
	}), "hash mismatch")

	require.ErrorContains(t, k.RegisterVerifyingKey(ctx, &vtypes.VerifyingKey{
		KeyBytes: bytes.Repeat([]byte{0x01}, 65),
	}), "exceeds max size")

	circuit := &vtypes.Circuit{
		CircuitBytes: []byte("circuit-bytes"),
		ProofSystem:  "ezkl",
		RegisteredBy: "governance",
		IsActive:     true,
	}
	require.NoError(t, k.RegisterCircuit(ctx, circuit))

	circuitHash := sha256.Sum256(circuit.CircuitBytes)
	require.Equal(t, circuitHash[:], circuit.Hash)
	gotCircuit, err := k.GetCircuit(ctx, circuitHash[:])
	require.NoError(t, err)
	require.Equal(t, "ezkl", gotCircuit.ProofSystem)

	require.ErrorContains(t, k.RegisterCircuit(ctx, &vtypes.Circuit{
		CircuitBytes: []byte("circuit-bytes"),
	}), "already registered")

	require.ErrorContains(t, k.RegisterCircuit(ctx, &vtypes.Circuit{
		CircuitBytes: bytes.Repeat([]byte{0x02}, 65),
	}), "exceeds max size")
}

func TestConfigParamsAndGenesisRoundTrip(t *testing.T) {
	k, ctx := createVerifyKeeper(t)

	require.ErrorContains(t, k.SetParams(ctx, nil), "params cannot be nil")
	require.ErrorContains(t, k.SetTEEConfig(ctx, nil), "cannot be nil")

	defaultParams, err := k.GetParams(ctx)
	require.NoError(t, err)
	require.NotNil(t, defaultParams)

	cfg := &vtypes.TEEConfig{
		Platform:            vtypes.TEEPlatformAWSNitro,
		TrustedMeasurements: [][]byte{[]byte("trusted")},
		MaxQuoteAge:         durationpb.New(2 * time.Hour),
		IsActive:            true,
	}
	require.NoError(t, k.SetTEEConfig(ctx, cfg))
	gotCfg, err := k.GetTEEConfig(ctx, vtypes.TEEPlatformAWSNitro)
	require.NoError(t, err)
	require.True(t, gotCfg.IsActive)

	_, err = k.GetTEEConfig(ctx, vtypes.TEEPlatformIntelSGX)
	require.Error(t, err)

	vkBytes := []byte("genesis-vk")
	vkHash := sha256.Sum256(vkBytes)
	circuitBytes := []byte("genesis-circuit")
	circuitHash := sha256.Sum256(circuitBytes)

	genesis := &vtypes.GenesisState{
		Params: vtypes.DefaultParams(),
		VerifyingKeys: []*vtypes.VerifyingKey{
			{
				Hash:        vkHash[:],
				KeyBytes:    vkBytes,
				ProofSystem: "ezkl",
				IsActive:    true,
			},
		},
		Circuits: []*vtypes.Circuit{
			{
				Hash:         circuitHash[:],
				CircuitBytes: circuitBytes,
				ProofSystem:  "ezkl",
				IsActive:     true,
			},
		},
		TeeConfigs: []*vtypes.TEEConfig{cfg},
	}
	require.NoError(t, k.InitGenesis(ctx, genesis))

	exported, err := k.ExportGenesis(ctx)
	require.NoError(t, err)
	require.NotNil(t, exported.Params)
	require.Len(t, exported.VerifyingKeys, 1)
	require.Len(t, exported.Circuits, 1)
	require.Len(t, exported.TeeConfigs, 1)

	require.ErrorContains(t, k.InitGenesis(ctx, &vtypes.GenesisState{
		Params:        vtypes.DefaultParams(),
		VerifyingKeys: []*vtypes.VerifyingKey{nil},
	}), "nil verifying key")

	require.ErrorContains(t, k.InitGenesis(ctx, &vtypes.GenesisState{
		Params:   vtypes.DefaultParams(),
		Circuits: []*vtypes.Circuit{nil},
	}), "nil circuit")

	require.ErrorContains(t, k.InitGenesis(ctx, &vtypes.GenesisState{
		Params:     vtypes.DefaultParams(),
		TeeConfigs: []*vtypes.TEEConfig{nil},
	}), "nil TEE config")
}

func TestVerifyTEEAttestationPath(t *testing.T) {
	k, ctx := createVerifyKeeper(t)
	mustSetVerifyParams(t, k, ctx, true, nil)

	trustedMeasurement := []byte("trusted-measurement")
	require.NoError(t, k.SetTEEConfig(ctx, &vtypes.TEEConfig{
		Platform:            vtypes.TEEPlatformAWSNitro,
		TrustedMeasurements: [][]byte{trustedMeasurement},
		MaxQuoteAge:         durationpb.New(2 * time.Hour),
		IsActive:            true,
	}))

	successAttestation := &vtypes.TEEAttestation{
		Platform:    vtypes.TEEPlatformAWSNitro,
		Measurement: trustedMeasurement,
		Quote:       bytes.Repeat([]byte{0xAA}, 1200),
		Timestamp:   timestamppb.New(ctx.BlockTime()),
		Nonce:       []byte("nonce"),
	}
	result, err := k.VerifyTEEAttestation(ctx, successAttestation)
	require.NoError(t, err)
	require.True(t, result.Success)
	require.True(t, result.TeeAttestationVerified)

	oldAttestation := *successAttestation
	oldAttestation.Timestamp = timestamppb.New(ctx.BlockTime().Add(-3 * time.Hour))
	result, err = k.VerifyTEEAttestation(ctx, &oldAttestation)
	require.NoError(t, err)
	require.False(t, result.Success)
	require.Contains(t, result.ErrorMessage, "too old")

	futureAttestation := *successAttestation
	futureAttestation.Timestamp = timestamppb.New(ctx.BlockTime().Add(10 * time.Minute))
	result, err = k.VerifyTEEAttestation(ctx, &futureAttestation)
	require.NoError(t, err)
	require.False(t, result.Success)
	require.Contains(t, result.ErrorMessage, "future")

	badMeasurement := *successAttestation
	badMeasurement.Measurement = []byte("untrusted")
	result, err = k.VerifyTEEAttestation(ctx, &badMeasurement)
	require.NoError(t, err)
	require.False(t, result.Success)
	require.Contains(t, result.ErrorMessage, "not in trusted list")

	require.NoError(t, k.SetTEEConfig(ctx, &vtypes.TEEConfig{
		Platform:    vtypes.TEEPlatformIntelSGX,
		IsActive:    false,
		MaxQuoteAge: durationpb.New(2 * time.Hour),
	}))
	inactive := &vtypes.TEEAttestation{
		Platform:    vtypes.TEEPlatformIntelSGX,
		Measurement: []byte("m"),
		Quote:       bytes.Repeat([]byte{0xBB}, 500),
		Timestamp:   timestamppb.New(ctx.BlockTime()),
	}
	result, err = k.VerifyTEEAttestation(ctx, inactive)
	require.NoError(t, err)
	require.False(t, result.Success)
	require.Contains(t, result.ErrorMessage, "not active")

	mustSetVerifyParams(t, k, ctx, false, nil)
	require.NoError(t, k.SetTEEConfig(ctx, &vtypes.TEEConfig{
		Platform:            vtypes.TEEPlatformAMDSEV,
		TrustedMeasurements: [][]byte{},
		MaxQuoteAge:         durationpb.New(time.Hour),
		IsActive:            true,
	}))
	noTrusted := &vtypes.TEEAttestation{
		Platform:    vtypes.TEEPlatformAMDSEV,
		Measurement: []byte("measurement"),
		Quote:       bytes.Repeat([]byte{0xCC}, 700),
		Timestamp:   timestamppb.New(ctx.BlockTime()),
	}
	result, err = k.VerifyTEEAttestation(ctx, noTrusted)
	require.NoError(t, err)
	require.False(t, result.Success)
	require.Contains(t, result.ErrorMessage, "no trusted measurements configured")

	// Production Nitro must enforce explicit freshness configuration and nonce.
	require.NoError(t, k.SetTEEConfig(ctx, &vtypes.TEEConfig{
		Platform:            vtypes.TEEPlatformAWSNitro,
		TrustedMeasurements: [][]byte{trustedMeasurement},
		IsActive:            true,
	}))
	prodNitroNoMaxAge := &vtypes.TEEAttestation{
		Platform:    vtypes.TEEPlatformAWSNitro,
		Measurement: trustedMeasurement,
		Quote:       bytes.Repeat([]byte{0xAB}, 1200),
		Timestamp:   timestamppb.New(ctx.BlockTime()),
		Nonce:       []byte("nonce"),
	}
	result, err = k.VerifyTEEAttestation(ctx, prodNitroNoMaxAge)
	require.NoError(t, err)
	require.False(t, result.Success)
	require.Contains(t, result.ErrorMessage, "max quote age")

	require.NoError(t, k.SetTEEConfig(ctx, &vtypes.TEEConfig{
		Platform:            vtypes.TEEPlatformAWSNitro,
		TrustedMeasurements: [][]byte{trustedMeasurement},
		MaxQuoteAge:         durationpb.New(5 * time.Minute),
		IsActive:            true,
	}))
	prodNitroNoNonce := &vtypes.TEEAttestation{
		Platform:    vtypes.TEEPlatformAWSNitro,
		Measurement: trustedMeasurement,
		Quote:       bytes.Repeat([]byte{0xAB}, 1200),
		Timestamp:   timestamppb.New(ctx.BlockTime()),
	}
	result, err = k.VerifyTEEAttestation(ctx, prodNitroNoNonce)
	require.NoError(t, err)
	require.False(t, result.Success)
	require.Contains(t, result.ErrorMessage, "nonce")

	// Unknown platform config should surface cleanly.
	unknown := &vtypes.TEEAttestation{
		Platform:    vtypes.TEEPlatformARMTrustZone,
		Measurement: []byte("measurement"),
		Quote:       bytes.Repeat([]byte{0xDD}, 800),
		Timestamp:   timestamppb.New(ctx.BlockTime()),
	}
	result, err = k.VerifyTEEAttestation(ctx, unknown)
	require.NoError(t, err)
	require.False(t, result.Success)
	require.Contains(t, result.ErrorMessage, "unknown TEE platform")
}

func TestVerifyTEEAttestation_ReplayRegistryRejectsDuplicatesAndExpires(t *testing.T) {
	k, ctx := createVerifyKeeper(t)
	// Replay registry behavior is independent of remote attestation; run in simulated
	// mode so the test exercises replay persistence without requiring an external verifier.
	mustSetVerifyParams(t, k, ctx, true, nil)

	trustedMeasurement := []byte("trusted-measurement")
	require.NoError(t, k.SetTEEConfig(ctx, &vtypes.TEEConfig{
		Platform:            vtypes.TEEPlatformAWSNitro,
		TrustedMeasurements: [][]byte{trustedMeasurement},
		MaxQuoteAge:         durationpb.New(2 * time.Hour),
		RequireFreshNonce:   true,
		IsActive:            true,
	}))

	baseQuote := bytes.Repeat([]byte{0xA1}, 1200)
	baseNonce := []byte("nonce-replay-test")
	base := &vtypes.TEEAttestation{
		Platform:    vtypes.TEEPlatformAWSNitro,
		Measurement: trustedMeasurement,
		Quote:       baseQuote,
		Timestamp:   timestamppb.New(ctx.BlockTime()),
		Nonce:       baseNonce,
	}

	result, err := k.VerifyTEEAttestation(ctx, base)
	require.NoError(t, err)
	require.True(t, result.Success)

	dupQuote, err := k.VerifyTEEAttestation(ctx, base)
	require.NoError(t, err)
	require.False(t, dupQuote.Success)
	require.Contains(t, dupQuote.ErrorMessage, "replay")

	diffQuoteSameNonce := &vtypes.TEEAttestation{
		Platform:    vtypes.TEEPlatformAWSNitro,
		Measurement: trustedMeasurement,
		Quote:       bytes.Repeat([]byte{0xA2}, 1200),
		Timestamp:   timestamppb.New(ctx.BlockTime()),
		Nonce:       baseNonce,
	}
	result, err = k.VerifyTEEAttestation(ctx, diffQuoteSameNonce)
	require.NoError(t, err)
	require.False(t, result.Success)
	require.Contains(t, result.ErrorMessage, "nonce replay")

	ctxAfterExpiry := ctx.WithBlockTime(ctx.BlockTime().Add(3 * time.Hour))
	reusedAfterExpiry := &vtypes.TEEAttestation{
		Platform:    vtypes.TEEPlatformAWSNitro,
		Measurement: trustedMeasurement,
		Quote:       baseQuote,
		Timestamp:   timestamppb.New(ctxAfterExpiry.BlockTime()),
		Nonce:       baseNonce,
	}
	result, err = k.VerifyTEEAttestation(ctxAfterExpiry, reusedAfterExpiry)
	require.NoError(t, err)
	require.True(t, result.Success, "expired replay entries should not permanently poison quote/nonce")
}

func TestVerifyZKMLProofPath(t *testing.T) {
	k, ctx := createVerifyKeeper(t)
	mustSetVerifyParams(t, k, ctx, true, []string{"ezkl", "custom"})

	vk := &vtypes.VerifyingKey{
		KeyBytes:     []byte("vk-ezkl"),
		ProofSystem:  "ezkl",
		RegisteredBy: "gov",
		IsActive:     true,
	}
	require.NoError(t, k.RegisterVerifyingKey(ctx, vk))
	vkHash := sha256.Sum256(vk.KeyBytes)

	proof := &vtypes.ZKMLProof{
		ProofSystem:      "ezkl",
		ProofBytes:       append([]byte("EZKL"), bytes.Repeat([]byte{0x11}, 252)...),
		PublicInputs:     bytes.Repeat([]byte{0x22}, 96),
		VerifyingKeyHash: vkHash[:],
		CircuitHash:      bytes.Repeat([]byte{0x33}, 32),
		Timestamp:        timestamppb.New(ctx.BlockTime()),
	}
	result, err := k.VerifyZKMLProof(ctx, proof)
	require.NoError(t, err)
	require.True(t, result.Success)
	require.True(t, result.ZkProofVerified)

	unsupported := *proof
	unsupported.ProofSystem = "unsupported"
	result, err = k.VerifyZKMLProof(ctx, &unsupported)
	require.NoError(t, err)
	require.False(t, result.Success)
	require.Contains(t, result.ErrorMessage, "unsupported proof system")

	missingKey := *proof
	missingKey.VerifyingKeyHash = bytes.Repeat([]byte{0x99}, 32)
	result, err = k.VerifyZKMLProof(ctx, &missingKey)
	require.NoError(t, err)
	require.False(t, result.Success)
	require.Contains(t, result.ErrorMessage, "verifying key not found")

	inactiveVK := &vtypes.VerifyingKey{
		KeyBytes:     []byte("vk-inactive"),
		ProofSystem:  "ezkl",
		RegisteredBy: "gov",
		IsActive:     false,
	}
	require.NoError(t, k.RegisterVerifyingKey(ctx, inactiveVK))
	inactiveHash := sha256.Sum256(inactiveVK.KeyBytes)
	inactiveProof := *proof
	inactiveProof.VerifyingKeyHash = inactiveHash[:]
	result, err = k.VerifyZKMLProof(ctx, &inactiveProof)
	require.NoError(t, err)
	require.False(t, result.Success)
	require.Contains(t, result.ErrorMessage, "inactive")

	mustSetVerifyParams(t, k, ctx, false, []string{"ezkl"})
	result, err = k.VerifyZKMLProof(ctx, proof)
	require.NoError(t, err)
	require.False(t, result.Success)
	require.Contains(t, result.ErrorMessage, "SECURITY")

	mustSetVerifyParams(t, k, ctx, true, []string{"custom"})
	customVK := &vtypes.VerifyingKey{
		KeyBytes:     []byte("vk-custom"),
		ProofSystem:  "custom",
		RegisteredBy: "gov",
		IsActive:     true,
	}
	require.NoError(t, k.RegisterVerifyingKey(ctx, customVK))
	customHash := sha256.Sum256(customVK.KeyBytes)
	customProof := &vtypes.ZKMLProof{
		ProofSystem:      "custom",
		ProofBytes:       bytes.Repeat([]byte{0x44}, 256),
		PublicInputs:     bytes.Repeat([]byte{0x55}, 96),
		VerifyingKeyHash: customHash[:],
		CircuitHash:      bytes.Repeat([]byte{0x66}, 32),
	}
	result, err = k.VerifyZKMLProof(ctx, customProof)
	require.NoError(t, err)
	require.False(t, result.Success)
	require.Contains(t, result.ErrorMessage, "unknown proof system")
}

func TestZKVerifierPrecompileAndSystemVerifier(t *testing.T) {
	verifier := NewZKVerifier()
	require.ErrorContains(t, verifier.RegisterSystemVerifier(ProofSystemEZKL, nil), "cannot be nil")

	require.NoError(t, verifier.RegisterSystemVerifier(ProofSystemEZKL, func(proof *ZKProof, circuit *RegisteredCircuit) (bool, error) {
		return true, nil
	}))

	vk := []byte("precompile-vk")
	vkHash := sha256.Sum256(vk)
	circuitHash := sha256.Sum256([]byte("precompile-circuit"))
	require.NoError(t, verifier.RegisterCircuit(RegisteredCircuit{
		CircuitHash:  circuitHash,
		VerifyingKey: vk,
		System:       ProofSystemEZKL,
	}))

	proofBytes := append([]byte("EZKL"), bytes.Repeat([]byte{0xAB}, 252)...)
	publicInputs := bytes.Repeat([]byte{0xBC}, 96)
	input := buildPrecompileInput(ProofSystemEZKL, vkHash, circuitHash, proofBytes, publicInputs)

	precompile := NewZKVerifierPrecompile(verifier)
	addr := precompile.PrecompileAddress()
	require.Len(t, addr, 16)
	require.Equal(t, byte(0x03), addr[14])
	require.Equal(t, byte(0x00), addr[15])

	require.Greater(t, precompile.RequiredGas(input), uint64(0))
	out, err := precompile.Run(input)
	require.NoError(t, err)
	require.Len(t, out, 73)
	require.Equal(t, byte(1), out[0])
}

func TestVerifyAttestationInternalBranches(t *testing.T) {
	k, ctx := createVerifyKeeper(t)
	config := &vtypes.TEEConfig{}

	tests := []struct {
		name      string
		platform  vtypes.TEEPlatform
		quoteSize int
		wantOK    bool
	}{
		{name: "aws nitro", platform: vtypes.TEEPlatformAWSNitro, quoteSize: 1000, wantOK: true},
		{name: "intel sgx", platform: vtypes.TEEPlatformIntelSGX, quoteSize: 432, wantOK: true},
		{name: "intel tdx", platform: vtypes.TEEPlatformIntelTDX, quoteSize: 584, wantOK: true},
		{name: "amd sev", platform: vtypes.TEEPlatformAMDSEV, quoteSize: 672, wantOK: true},
		{name: "too short", platform: vtypes.TEEPlatformIntelSGX, quoteSize: 100, wantOK: false},
		{name: "unsupported", platform: vtypes.TEEPlatformARMTrustZone, quoteSize: 1000, wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := k.verifyAttestationInternal(ctx, &vtypes.TEEAttestation{
				Platform:    tc.platform,
				Measurement: []byte("m"),
				Quote:       bytes.Repeat([]byte{0xAB}, tc.quoteSize),
			}, config, true)
			if tc.wantOK {
				require.NoError(t, err)
				require.True(t, ok)
			} else {
				require.Error(t, err)
				require.False(t, ok)
			}
		})
	}

	ok, err := k.verifyAttestationInternal(ctx, &vtypes.TEEAttestation{
		Platform:    vtypes.TEEPlatformAWSNitro,
		Measurement: []byte("m"),
		Quote:       bytes.Repeat([]byte{0xAB}, 1000),
	}, config, false)
	require.ErrorContains(t, err, "SECURITY")
	require.False(t, ok)
}

func TestVerifyProofInternalBranches(t *testing.T) {
	k, ctx := createVerifyKeeper(t)
	vk := &vtypes.VerifyingKey{IsActive: true}
	params := vtypes.DefaultParams()
	params.AllowSimulated = true

	cases := []struct {
		name      string
		system    string
		proofSize int
		wantOK    bool
	}{
		{name: "groth16", system: "groth16", proofSize: 192, wantOK: true},
		{name: "ezkl", system: "ezkl", proofSize: 256, wantOK: true},
		{name: "halo2", system: "halo2", proofSize: 384, wantOK: true},
		{name: "plonky2", system: "plonky2", proofSize: 256, wantOK: true},
		{name: "risc0", system: "risc0", proofSize: 512, wantOK: true},
		{name: "unknown", system: "custom", proofSize: 256, wantOK: false},
		{name: "small ezkl", system: "ezkl", proofSize: 120, wantOK: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := k.verifyProofInternal(ctx, &vtypes.ZKMLProof{
				ProofSystem:  tc.system,
				ProofBytes:   bytes.Repeat([]byte{0xCD}, tc.proofSize),
				PublicInputs: bytes.Repeat([]byte{0xEF}, 96),
			}, vk, params)
			if tc.wantOK {
				require.NoError(t, err)
				require.True(t, ok)
			} else {
				require.Error(t, err)
				require.False(t, ok)
			}
		})
	}

	params.AllowSimulated = false
	ok, err := k.verifyProofInternal(ctx, &vtypes.ZKMLProof{
		ProofSystem:  "ezkl",
		ProofBytes:   bytes.Repeat([]byte{0xCC}, 256),
		PublicInputs: bytes.Repeat([]byte{0xEE}, 96),
	}, vk, params)
	require.ErrorContains(t, err, "SECURITY")
	require.False(t, ok)
}

func buildPrecompileInput(system ProofSystem, vkHash [32]byte, circuitHash [32]byte, proof []byte, inputs []byte) []byte {
	out := make([]byte, 0, 32+32+32+4+len(proof)+4+len(inputs))

	systemField := make([]byte, 32)
	copy(systemField, []byte(system))
	out = append(out, systemField...)
	out = append(out, vkHash[:]...)
	out = append(out, circuitHash[:]...)

	proofLen := make([]byte, 4)
	binary.BigEndian.PutUint32(proofLen, uint32(len(proof)))
	out = append(out, proofLen...)
	out = append(out, proof...)

	inputLen := make([]byte, 4)
	binary.BigEndian.PutUint32(inputLen, uint32(len(inputs)))
	out = append(out, inputLen...)
	out = append(out, inputs...)

	return out
}
