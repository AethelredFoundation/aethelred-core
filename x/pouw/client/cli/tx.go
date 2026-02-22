package cli

import (
	"fmt"
	"strings"

	sdkmath "cosmossdk.io/math"
	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

const (
	flagTEEPlatforms      = "tee-platforms"
	flagZKMLSystems       = "zkml-systems"
	flagMaxConcurrentJobs = "max-concurrent-jobs"
	flagIsOnline          = "is-online"
	flagStakeAmount       = "amount"
	flagValidator         = "validator"

	stakeDisplayDenom = "aethel"
	stakeBaseDenom    = "uaeth"

	// 1 AETHEL = 1,000,000 uaeth.
	stakeBaseUnitsPerAETHEL int64 = 1_000_000
	// Hard minimum for April 1 testnet Sybil resistance.
	minStakeAETHEL int64 = 100_000
)

// CmdRegisterValidatorCapability creates a CLI command for registering validator capabilities.
func CmdRegisterValidatorCapability() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register-validator-capability",
		Short: "Register validator compute capabilities",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			teePlatforms, err := cmd.Flags().GetStringSlice(flagTEEPlatforms)
			if err != nil {
				return err
			}

			zkmlSystems, err := cmd.Flags().GetStringSlice(flagZKMLSystems)
			if err != nil {
				return err
			}

			maxConcurrentJobs, err := cmd.Flags().GetInt64(flagMaxConcurrentJobs)
			if err != nil {
				return err
			}

			isOnline, err := cmd.Flags().GetBool(flagIsOnline)
			if err != nil {
				return err
			}

			msg := &types.MsgRegisterValidatorCapability{
				Creator:           clientCtx.GetFromAddress().String(),
				TeePlatforms:      teePlatforms,
				ZkmlSystems:       zkmlSystems,
				MaxConcurrentJobs: maxConcurrentJobs,
				IsOnline:          isOnline,
			}

			if err := msg.ValidateBasic(); err != nil {
				return err
			}

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	cmd.Flags().StringSlice(flagTEEPlatforms, []string{}, "Comma-separated list of supported TEE platforms")
	cmd.Flags().StringSlice(flagZKMLSystems, []string{}, "Comma-separated list of supported zkML systems")
	cmd.Flags().Int64(flagMaxConcurrentJobs, 1, "Maximum concurrent jobs the validator can handle")
	cmd.Flags().Bool(flagIsOnline, true, "Whether the validator is currently online")
	_ = cmd.MarkFlagRequired(flagMaxConcurrentJobs)

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}

// CmdStakeForPoUW creates a CLI command for staking the minimum required amount
// to participate in PoUW validator assignment.
func CmdStakeForPoUW() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stake",
		Short: "Stake for PoUW validator eligibility (minimum 100000aethel)",
		Long: "Delegate stake to a validator operator address for PoUW participation.\n" +
			"Accepted denoms: aethel, uaeth.\n" +
			"Minimum required amount is 100000aethel (100000000000uaeth).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			rawAmount, err := cmd.Flags().GetString(flagStakeAmount)
			if err != nil {
				return err
			}

			stakeCoin, err := parseStakeAmount(rawAmount)
			if err != nil {
				return err
			}
			if err := enforceMinimumStake(stakeCoin); err != nil {
				return err
			}

			validatorAddr, err := cmd.Flags().GetString(flagValidator)
			if err != nil {
				return err
			}
			if strings.TrimSpace(validatorAddr) == "" {
				validatorAddr = sdk.ValAddress(clientCtx.GetFromAddress()).String()
			}

			msg := stakingtypes.NewMsgDelegate(
				clientCtx.GetFromAddress().String(),
				validatorAddr,
				stakeCoin,
			)

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	cmd.Flags().String(
		flagStakeAmount,
		fmt.Sprintf("%d%s", minStakeAETHEL, stakeDisplayDenom),
		"Stake amount (accepted denoms: aethel, uaeth)",
	)
	cmd.Flags().String(
		flagValidator,
		"",
		"Validator operator address (defaults to your valoper address)",
	)
	flags.AddTxFlagsToCmd(cmd)

	return cmd
}

// CmdRegisterValidatorPCR0 creates a CLI command for explicitly registering a validator PCR0 hash.
func CmdRegisterValidatorPCR0() *cobra.Command {
	cmd := &cobra.Command{
		Use: "register-pcr0 [pcr0-hex]",
		Aliases: []string{
			"register-validator-pcr0",
		},
		Short: "Register AWS Nitro PCR0 measurement for the signing validator",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			validator := clientCtx.GetFromAddress().String()
			msg := &types.MsgRegisterValidatorPCR0{
				Creator:          validator,
				ValidatorAddress: validator,
				Pcr0Hex:          args[0],
			}

			if err := msg.ValidateBasic(); err != nil {
				return err
			}

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}

func minimumStakeUAETH() sdkmath.Int {
	return sdkmath.NewInt(minStakeAETHEL * stakeBaseUnitsPerAETHEL)
}

func parseStakeAmount(raw string) (sdk.Coin, error) {
	coin, err := sdk.ParseCoinNormalized(strings.TrimSpace(raw))
	if err != nil {
		return sdk.Coin{}, fmt.Errorf("invalid stake amount %q: %w", raw, err)
	}
	if !coin.IsPositive() {
		return sdk.Coin{}, fmt.Errorf("stake amount must be positive")
	}

	switch strings.ToLower(coin.Denom) {
	case stakeDisplayDenom:
		return sdk.NewCoin(stakeBaseDenom, coin.Amount.MulRaw(stakeBaseUnitsPerAETHEL)), nil
	case stakeBaseDenom:
		return coin, nil
	default:
		return sdk.Coin{}, fmt.Errorf(
			"unsupported stake denom %q (supported: %s, %s)",
			coin.Denom,
			stakeDisplayDenom,
			stakeBaseDenom,
		)
	}
}

func enforceMinimumStake(coin sdk.Coin) error {
	if coin.Denom != stakeBaseDenom {
		return fmt.Errorf("stake denom must be %s", stakeBaseDenom)
	}

	minimum := minimumStakeUAETH()
	if coin.Amount.LT(minimum) {
		return fmt.Errorf(
			"minimum stake not met: got %s%s, need at least %d%s (%s%s)",
			coin.Amount.String(),
			stakeBaseDenom,
			minStakeAETHEL,
			stakeDisplayDenom,
			minimum.String(),
			stakeBaseDenom,
		)
	}

	return nil
}
