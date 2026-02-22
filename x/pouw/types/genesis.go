package types

import "fmt"

// DefaultGenesis returns the default genesis state
func DefaultGenesis() *GenesisState {
	return &GenesisState{
		Jobs:                  []*ComputeJob{},
		RegisteredModels:      []*RegisteredModel{},
		ValidatorStats:        []*ValidatorStats{},
		ValidatorCapabilities: []*ValidatorCapability{},
		Params:                DefaultParams(),
	}
}

// DefaultParams returns default module parameters
func DefaultParams() *Params {
	return &Params{
		MinValidators:                  3,
		ConsensusThreshold:             67,  // 2/3 majority
		JobTimeoutBlocks:               100, // ~10 minutes with 6s blocks
		BaseJobFee:                     "1000uaeth",
		VerificationReward:             "100uaeth",
		SlashingPenalty:                "10000uaeth",
		MaxJobsPerBlock:                10,
		AllowedProofTypes:              []string{"tee", "zkml", "hybrid"},
		RequireTeeAttestation:          true,
		AllowZkmlFallback:              true,
		AllowSimulated:                 false,
		VoteExtensionMaxPastSkewSecs:   600, // 10 minutes
		VoteExtensionMaxFutureSkewSecs: 60,  // 1 minute
	}
}

// Validate performs basic genesis state validation
func (gs GenesisState) Validate() error {
	// Validate each job
	for i, job := range gs.Jobs {
		if job == nil {
			return fmt.Errorf("job at index %d is nil", i)
		}
		if err := job.Validate(); err != nil {
			return fmt.Errorf("invalid job at index %d: %w", i, err)
		}
	}

	// Validate validator capabilities
	for i, cap := range gs.ValidatorCapabilities {
		if cap == nil || len(cap.Address) == 0 {
			return fmt.Errorf("validator capability missing address at index %d", i)
		}
	}

	// Validate params
	if gs.Params == nil {
		return fmt.Errorf("params must be set")
	}
	if gs.Params.MinValidators <= 0 {
		return fmt.Errorf("min_validators must be positive")
	}
	if gs.Params.ConsensusThreshold < 50 || gs.Params.ConsensusThreshold > 100 {
		return fmt.Errorf("consensus_threshold must be between 50 and 100")
	}
	if gs.Params.JobTimeoutBlocks <= 0 {
		return fmt.Errorf("job_timeout_blocks must be positive")
	}
	if gs.Params.MaxJobsPerBlock <= 0 {
		return fmt.Errorf("max_jobs_per_block must be positive")
	}
	if gs.Params.VoteExtensionMaxPastSkewSecs <= 0 {
		return fmt.Errorf("vote_extension_max_past_skew_secs must be positive")
	}
	if gs.Params.VoteExtensionMaxFutureSkewSecs <= 0 {
		return fmt.Errorf("vote_extension_max_future_skew_secs must be positive")
	}
	if gs.Params.VoteExtensionMaxFutureSkewSecs > gs.Params.VoteExtensionMaxPastSkewSecs {
		return fmt.Errorf("vote_extension_max_future_skew_secs cannot exceed vote_extension_max_past_skew_secs")
	}

	return nil
}
