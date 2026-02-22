package cmd

import (
	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"

	pouwcli "github.com/aethelred/aethelred/x/pouw/client/cli"
)

func attestationTxCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "attestation",
		Short:                      "Attestation transaction subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	registerPCR0 := pouwcli.CmdRegisterValidatorPCR0()
	registerPCR0.Use = "register-pcr0 [pcr0-hex]"
	registerPCR0.Short = "Register AWS Nitro PCR0 measurement for the signing validator"
	registerPCR0.Aliases = []string{"register-validator-pcr0"}
	cmd.AddCommand(registerPCR0)

	return cmd
}
