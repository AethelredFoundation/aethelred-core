package cmd

import (
	"fmt"

	"github.com/cosmos/cosmos-sdk/client"
	genutilcli "github.com/cosmos/cosmos-sdk/x/genutil/client/cli"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"

	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
)

func genesisMigrationMap() genutiltypes.MigrationMap {
	migrations := genutiltypes.MigrationMap{}
	for k, v := range genutilcli.MigrationMap {
		migrations[k] = v
	}

	// App-level genesis migration for v0.2.0.
	migrations["v0.2.0"] = func(state genutiltypes.AppMap, clientCtx client.Context) (genutiltypes.AppMap, error) {
		bz, ok := state[pouwtypes.ModuleName]
		if !ok || len(bz) == 0 {
			gs := pouwtypes.DefaultGenesis()
			out, err := clientCtx.Codec.MarshalJSON(gs)
			if err != nil {
				return nil, err
			}
			state[pouwtypes.ModuleName] = out
			return state, nil
		}

		var gs pouwtypes.GenesisState
		if err := clientCtx.Codec.UnmarshalJSON(bz, &gs); err != nil {
			return nil, fmt.Errorf("pouw genesis unmarshal: %w", err)
		}

		updated := false
		defaults := pouwtypes.DefaultParams()
		if gs.Params == nil {
			gs.Params = defaults
			updated = true
		} else {
			if gs.Params.MinValidators == 0 {
				gs.Params.MinValidators = defaults.MinValidators
				updated = true
			}
			if gs.Params.ConsensusThreshold == 0 {
				gs.Params.ConsensusThreshold = defaults.ConsensusThreshold
				updated = true
			}
			if gs.Params.JobTimeoutBlocks == 0 {
				gs.Params.JobTimeoutBlocks = defaults.JobTimeoutBlocks
				updated = true
			}
			if gs.Params.BaseJobFee == "" {
				gs.Params.BaseJobFee = defaults.BaseJobFee
				updated = true
			}
			if gs.Params.VerificationReward == "" {
				gs.Params.VerificationReward = defaults.VerificationReward
				updated = true
			}
			if gs.Params.SlashingPenalty == "" {
				gs.Params.SlashingPenalty = defaults.SlashingPenalty
				updated = true
			}
			if gs.Params.MaxJobsPerBlock == 0 {
				gs.Params.MaxJobsPerBlock = defaults.MaxJobsPerBlock
				updated = true
			}
			if len(gs.Params.AllowedProofTypes) == 0 {
				gs.Params.AllowedProofTypes = defaults.AllowedProofTypes
				updated = true
			}
		}

		if updated {
			out, err := clientCtx.Codec.MarshalJSON(&gs)
			if err != nil {
				return nil, fmt.Errorf("pouw genesis marshal: %w", err)
			}
			state[pouwtypes.ModuleName] = out
		}

		return state, nil
	}

	return migrations
}
