package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

const (
	schedulerMetaAssignedTo   = "scheduler.assigned_to"
	schedulerMetaBeaconSource = "scheduler.beacon_source"
	dkgBeaconSource           = "dkg-threshold-beacon"
)

// CmdQueryValidatorPCR0 creates a CLI query command for validator PCR0 mappings.
func CmdQueryValidatorPCR0() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validator-pcr0 [validator-address]",
		Short: "Query a validator's registered AWS Nitro PCR0 hash",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)
			res, err := queryClient.ValidatorPCR0(cmd.Context(), &types.QueryValidatorPCR0Request{
				ValidatorAddress: args[0],
			})
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

type validatorPoUWStatusReport struct {
	InputAddress         string   `json:"input_address"`
	ValidatorAddress     string   `json:"validator_address"`
	OperatorAddress      string   `json:"operator_address"`
	Bonded               bool     `json:"bonded"`
	BondedStake          string   `json:"bonded_stake"`
	MinimumStake         string   `json:"minimum_stake"`
	StakeRequirementMet  bool     `json:"stake_requirement_met"`
	PCR0Registered       bool     `json:"pcr0_registered"`
	PCR0Hex              string   `json:"pcr0_hex,omitempty"`
	ValidatorStatsFound  bool     `json:"validator_stats_found"`
	TotalJobsProcessed   int64    `json:"total_jobs_processed,omitempty"`
	SuccessfulJobs       int64    `json:"successful_jobs,omitempty"`
	FailedJobs           int64    `json:"failed_jobs,omitempty"`
	PendingAssignments   int      `json:"pending_assignments"`
	DKGBackedAssignments int      `json:"dkg_backed_assignments"`
	DKGState             string   `json:"dkg_state"`
	ReadyForPoUW         bool     `json:"ready_for_pouw"`
	Notes                []string `json:"notes,omitempty"`
}

// CmdQueryPoUWStatus creates a CLI query command for validator PoUW onboarding status.
func CmdQueryPoUWStatus() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Query validator onboarding status for PoUW readiness and DKG eligibility",
		Long: "Returns a single status report that combines staking, PCR0 attestation,\n" +
			"validator stats, and DKG-backed assignment signals for the requested validator.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			inputAddr, err := cmd.Flags().GetString(flagValidator)
			if err != nil {
				return err
			}
			inputAddr = strings.TrimSpace(inputAddr)
			if inputAddr == "" {
				if clientCtx.FromAddress.Empty() {
					return fmt.Errorf("set --%s or provide --from to resolve validator address", flagValidator)
				}
				inputAddr = clientCtx.FromAddress.String()
			}

			validatorAddr, operatorAddr, err := resolveValidatorAddresses(inputAddr)
			if err != nil {
				return err
			}

			report := validatorPoUWStatusReport{
				InputAddress:     inputAddr,
				ValidatorAddress: validatorAddr,
				OperatorAddress:  operatorAddr,
				BondedStake:      "0" + stakeBaseDenom,
				MinimumStake:     minimumStakeUAETH().String() + stakeBaseDenom,
				Notes:            []string{},
			}

			minimumStake := minimumStakeUAETH()
			pouwQuery := types.NewQueryClient(clientCtx)
			stakingQuery := stakingtypes.NewQueryClient(clientCtx)

			if stakingRes, stakingErr := stakingQuery.Validator(cmd.Context(), &stakingtypes.QueryValidatorRequest{
				ValidatorAddr: operatorAddr,
			}); stakingErr == nil && stakingRes != nil {
				report.Bonded = stakingRes.Validator.Status == stakingtypes.Bonded
				report.BondedStake = stakingRes.Validator.Tokens.String() + stakeBaseDenom
				report.StakeRequirementMet = report.Bonded && stakingRes.Validator.Tokens.GTE(minimumStake)
			} else {
				report.Notes = append(report.Notes, "validator operator not found in staking set")
			}

			if pcr0Res, pcr0Err := pouwQuery.ValidatorPCR0(cmd.Context(), &types.QueryValidatorPCR0Request{
				ValidatorAddress: validatorAddr,
			}); pcr0Err == nil && pcr0Res != nil && pcr0Res.Pcr0Hex != "" {
				report.PCR0Registered = true
				report.PCR0Hex = pcr0Res.Pcr0Hex
			} else {
				report.Notes = append(report.Notes, "validator PCR0 is not registered")
			}

			if statsRes, statsErr := pouwQuery.ValidatorStats(cmd.Context(), &types.QueryValidatorStatsRequest{
				ValidatorAddress: validatorAddr,
			}); statsErr == nil && statsRes != nil && statsRes.Stats != nil {
				report.ValidatorStatsFound = true
				report.TotalJobsProcessed = statsRes.Stats.TotalJobsProcessed
				report.SuccessfulJobs = statsRes.Stats.SuccessfulJobs
				report.FailedJobs = statsRes.Stats.FailedJobs
			} else {
				report.Notes = append(report.Notes, "validator stats not found (capability not observed yet)")
			}

			if pendingRes, pendingErr := pouwQuery.PendingJobs(cmd.Context(), &types.QueryPendingJobsRequest{}); pendingErr == nil && pendingRes != nil {
				candidates := map[string]struct{}{
					validatorAddr: {},
					operatorAddr:  {},
				}
				report.PendingAssignments, report.DKGBackedAssignments = assignmentSnapshot(pendingRes.Jobs, candidates)
			}

			switch {
			case !report.StakeRequirementMet || !report.PCR0Registered:
				report.DKGState = "blocked"
			case report.DKGBackedAssignments > 0:
				report.DKGState = "active"
			default:
				report.DKGState = "eligible"
			}

			report.ReadyForPoUW = report.StakeRequirementMet && report.PCR0Registered
			if report.ReadyForPoUW && !report.ValidatorStatsFound {
				report.Notes = append(report.Notes, "validator has not produced finalized PoUW jobs yet")
			}
			if !report.ReadyForPoUW {
				if !report.StakeRequirementMet {
					report.Notes = append(report.Notes, "stake not bonded or below 100000aethel minimum")
				}
				report.Notes = append(report.Notes, "submit tx pouw register-validator-capability to join assignment pool")
			}

			rendered, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return err
			}

			return clientCtx.PrintString(string(rendered) + "\n")
		},
	}

	cmd.Flags().String(flagValidator, "", "Validator account or valoper address (defaults to --from)")
	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

func resolveValidatorAddresses(input string) (validatorAddr string, operatorAddr string, err error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", "", fmt.Errorf("validator address cannot be empty")
	}

	if accAddr, accErr := sdk.AccAddressFromBech32(trimmed); accErr == nil {
		return accAddr.String(), sdk.ValAddress(accAddr).String(), nil
	}

	if valAddr, valErr := sdk.ValAddressFromBech32(trimmed); valErr == nil {
		return sdk.AccAddress(valAddr).String(), valAddr.String(), nil
	}

	return "", "", fmt.Errorf("invalid validator address %q: provide account or valoper bech32", input)
}

func assignmentSnapshot(jobs []*types.ComputeJob, candidates map[string]struct{}) (assigned int, dkgBacked int) {
	for _, job := range jobs {
		if job == nil || len(job.Metadata) == 0 {
			continue
		}

		assignedValidators := parseAssignedValidators(job.Metadata[schedulerMetaAssignedTo])
		if !containsAnyAddress(assignedValidators, candidates) {
			continue
		}

		assigned++
		if strings.EqualFold(job.Metadata[schedulerMetaBeaconSource], dkgBeaconSource) {
			dkgBacked++
		}
	}

	return assigned, dkgBacked
}

func parseAssignedValidators(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}

	var jsonList []string
	if err := json.Unmarshal([]byte(trimmed), &jsonList); err == nil {
		out := make([]string, 0, len(jsonList))
		for _, item := range jsonList {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
		return out
	}

	parts := strings.Split(trimmed, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func containsAnyAddress(assigned []string, candidates map[string]struct{}) bool {
	for _, addr := range assigned {
		if _, ok := candidates[addr]; ok {
			return true
		}
	}
	return false
}

// CmdQueryIsPCR0Registered creates a CLI query command for global PCR0 registry membership.
func CmdQueryIsPCR0Registered() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "is-pcr0-registered [pcr0-hex]",
		Short: "Query whether a PCR0 hash is globally trusted",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)
			res, err := queryClient.IsPCR0Registered(cmd.Context(), &types.QueryIsPCR0RegisteredRequest{
				Pcr0Hex: args[0],
			})
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}
