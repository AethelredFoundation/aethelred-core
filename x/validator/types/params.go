package types

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
)

// DefaultParams returns default module parameters
func DefaultParams() *Params {
	return &Params{
		MinReputationScore:           10,
		HeartbeatTimeout:             durationpb.New(5 * time.Minute),
		MaxConcurrentJobs:            5,
		SlashFractionInvalidOutput:   "1.00",
		SlashFractionFakeAttestation: "1.00",
		SlashFractionDoubleSign:      "0.50",
		SlashFractionDowntime:        "0.05",
		JailDuration:                 durationpb.New(24 * time.Hour),
		MinValidatorsRequired:        3,
		ConsensusThreshold:           67,
	}
}

// Validate validates the parameters
func (p *Params) Validate() error {
	if p == nil {
		return fmt.Errorf("params cannot be nil")
	}

	if p.MinReputationScore < 0 || p.MinReputationScore > 100 {
		return fmt.Errorf("min reputation score must be between 0 and 100")
	}

	if p.HeartbeatTimeout == nil || p.HeartbeatTimeout.AsDuration() <= 0 {
		return fmt.Errorf("heartbeat timeout must be positive")
	}

	if p.MaxConcurrentJobs <= 0 {
		return fmt.Errorf("max concurrent jobs must be positive")
	}

	if p.MinValidatorsRequired < 1 {
		return fmt.Errorf("min validators required must be at least 1")
	}

	if p.ConsensusThreshold < 50 || p.ConsensusThreshold > 100 {
		return fmt.Errorf("consensus threshold must be between 50 and 100")
	}

	return nil
}

// DefaultGenesisState returns a default genesis state
func DefaultGenesisState() *GenesisState {
	return &GenesisState{
		Params:               DefaultParams(),
		HardwareCapabilities: []*HardwareCapability{},
	}
}

// Validate validates the genesis state
func (gs GenesisState) Validate() error {
	if err := gs.Params.Validate(); err != nil {
		return fmt.Errorf("invalid params: %w", err)
	}

	for i, cap := range gs.HardwareCapabilities {
		if cap == nil {
			return fmt.Errorf("nil hardware capability at index %d", i)
		}
		if err := cap.Validate(); err != nil {
			return fmt.Errorf("invalid hardware capability at index %d: %w", i, err)
		}
	}

	return nil
}
