package types

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
)

// DefaultGenesis returns the default genesis state
func DefaultGenesis() *GenesisState {
	return &GenesisState{
		VerifyingKeys: []*VerifyingKey{},
		Circuits:      []*Circuit{},
		TeeConfigs:    DefaultTEEConfigs(),
		Params:        DefaultParams(),
	}
}

// DefaultParams returns default module parameters
func DefaultParams() *Params {
	return &Params{
		MaxProofSize:           10 * 1024 * 1024,   // 10 MB
		MaxVerifyingKeySize:    1024 * 1024,        // 1 MB
		MaxCircuitSize:         100 * 1024 * 1024,  // 100 MB
		DefaultTeeQuoteMaxAge:  durationpb.New(24 * time.Hour),
		RequireTeeForHighValue: true,
		HighValueThreshold:     "1000000uaeth", // 1 AETH
		SupportedProofSystems:  []string{"ezkl", "risc0", "plonky2", "halo2"},
		SupportedTeePlatforms:  []string{"aws-nitro", "intel-sgx", "intel-tdx", "amd-sev"},
		VerificationFee:        "100uaeth",
		ZkVerifierEndpoint:     "",
		AllowSimulated:         false,
	}
}

// DefaultTEEConfigs returns default TEE configurations
func DefaultTEEConfigs() []*TEEConfig {
	return []*TEEConfig{
		{
			Platform:            TEEPlatformAWSNitro,
			TrustedMeasurements: [][]byte{}, // Set during deployment
			MaxQuoteAge:         durationpb.New(24 * time.Hour),
			RequireFreshNonce:   true,
			IsActive:            true,
		},
		{
			Platform:            TEEPlatformIntelSGX,
			TrustedMeasurements: [][]byte{},
			MaxQuoteAge:         durationpb.New(24 * time.Hour),
			RequireFreshNonce:   true,
			IsActive:            false, // Disabled by default
		},
	}
}

// Validate performs basic genesis state validation
func (gs GenesisState) Validate() error {
	// Validate verifying keys
	for i, key := range gs.VerifyingKeys {
		if key == nil {
			return fmt.Errorf("nil verifying key at index %d", i)
		}
		if len(key.Hash) != 32 {
			return fmt.Errorf("invalid verifying key hash at index %d", i)
		}
		if len(key.KeyBytes) == 0 {
			return fmt.Errorf("empty key bytes at index %d", i)
		}
	}

	// Validate circuits
	for i, circuit := range gs.Circuits {
		if circuit == nil {
			return fmt.Errorf("nil circuit at index %d", i)
		}
		if len(circuit.Hash) != 32 {
			return fmt.Errorf("invalid circuit hash at index %d", i)
		}
		if len(circuit.CircuitBytes) == 0 {
			return fmt.Errorf("empty circuit bytes at index %d", i)
		}
	}

	// Validate params
	if gs.Params == nil {
		return fmt.Errorf("params cannot be nil")
	}
	if gs.Params.MaxProofSize <= 0 {
		return fmt.Errorf("max_proof_size must be positive")
	}
	if gs.Params.MaxVerifyingKeySize <= 0 {
		return fmt.Errorf("max_verifying_key_size must be positive")
	}

	return nil
}
