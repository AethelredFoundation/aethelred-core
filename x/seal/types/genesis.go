package types

import "fmt"

// DefaultGenesis returns the default genesis state
func DefaultGenesis() *GenesisState {
	return &GenesisState{
		Seals:  []*DigitalSeal{},
		Params: DefaultParams(),
	}
}

// DefaultParams returns default module parameters
func DefaultParams() *Params {
	return &Params{
		MinValidatorAttestations:   3,
		SealCreationFee:            "1000uaeth",
		DefaultRetentionPeriodDays: 365 * 7, // 7 years for regulatory compliance
		AllowedPurposes: []string{
			"credit_scoring",
			"fraud_detection",
			"risk_assessment",
			"identity_verification",
			"medical_diagnosis",
			"autonomous_decision",
			"content_moderation",
			"recommendation",
			"general",
		},
	}
}

// Validate performs basic genesis state validation
func (gs GenesisState) Validate() error {
	// Validate each seal
	for i, seal := range gs.Seals {
		if seal == nil {
			return fmt.Errorf("nil seal at index %d", i)
		}
		if err := seal.Validate(); err != nil {
			return fmt.Errorf("invalid seal at index %d: %w", i, err)
		}
	}

	// Validate params
	if gs.Params == nil {
		return fmt.Errorf("params cannot be nil")
	}
	if gs.Params.MinValidatorAttestations <= 0 {
		return fmt.Errorf("min_validator_attestations must be positive")
	}
	if gs.Params.DefaultRetentionPeriodDays <= 0 {
		return fmt.Errorf("default_retention_period_days must be positive")
	}

	return nil
}
