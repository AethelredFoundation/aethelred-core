package cmd

import (
	"io"
	"os"
	"strings"

	dbm "github.com/cosmos/cosmos-db"
	"github.com/spf13/cobra"

	"cosmossdk.io/log"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/config"
	"github.com/cosmos/cosmos-sdk/client/debug"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/keys"
	"github.com/cosmos/cosmos-sdk/client/rpc"
	"github.com/cosmos/cosmos-sdk/server"
	serverconfig "github.com/cosmos/cosmos-sdk/server/config"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authcmd "github.com/cosmos/cosmos-sdk/x/auth/client/cli"
	"github.com/cosmos/cosmos-sdk/x/auth/types"
	genutilcli "github.com/cosmos/cosmos-sdk/x/genutil/client/cli"

	"github.com/aethelred/aethelred/app"
	"github.com/aethelred/aethelred/x/pouw"
	"github.com/aethelred/aethelred/x/seal"
	"github.com/aethelred/aethelred/x/verify"

	// Suppress unused import warning - these are registered via imports
	_ "github.com/cosmos/cosmos-sdk/client/rpc"
)

// NewRootCmd creates the root command for aethelredd
func NewRootCmd() *cobra.Command {
	// Set config
	initConfig()

	encodingConfig := app.MakeEncodingConfig()
	initClientCtx := client.Context{}.
		WithCodec(encodingConfig.Codec).
		WithInterfaceRegistry(encodingConfig.InterfaceRegistry).
		WithTxConfig(encodingConfig.TxConfig).
		WithLegacyAmino(encodingConfig.Amino).
		WithInput(os.Stdin).
		WithAccountRetriever(types.AccountRetriever{}).
		WithHomeDir(app.DefaultNodeHome).
		WithViper("AETHELRED")

	rootCmd := &cobra.Command{
		Use:   "aethelredd",
		Short: "Aethelred - The Digital Seal for Verifiable Intelligence",
		Long: `Aethelred is a sovereign Layer 1 blockchain with Proof-of-Useful-Work consensus
for cryptographic verification of AI computations.

Key Features:
- Proof-of-Useful-Work consensus with zkML and TEE verification
- Digital Seals for immutable AI audit trails
- Enterprise-grade compliance for regulated industries
- Cross-chain interoperability for verification proofs

Learn more at https://aethelred.io`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			initClientCtx, err := client.ReadPersistentCommandFlags(initClientCtx, cmd.Flags())
			if err != nil {
				return err
			}
			initClientCtx, err = config.ReadFromClientConfig(initClientCtx)
			if err != nil {
				return err
			}
			if err := client.SetCmdClientContextHandler(initClientCtx, cmd); err != nil {
				return err
			}
			customAppTemplate, customAppConfig := initAppConfig()
			if err := server.InterceptConfigsPreRunHandler(cmd, customAppTemplate, customAppConfig, nil); err != nil {
				return err
			}
			return validateAppConfig(cmd)
		},
	}

	initRootCmd(rootCmd, encodingConfig)

	return rootCmd
}

// initConfig sets the SDK configuration
func initConfig() {
	// Set the address prefixes
	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount(app.AccountAddressPrefix, app.AccountAddressPrefix+"pub")
	config.SetBech32PrefixForValidator(app.AccountAddressPrefix+"valoper", app.AccountAddressPrefix+"valoperpub")
	config.SetBech32PrefixForConsensusNode(app.AccountAddressPrefix+"valcons", app.AccountAddressPrefix+"valconspub")
	config.Seal()
}

// AppConfig defines custom app configuration for Aethelred.
type AppConfig struct {
	serverconfig.Config
	TEE TEEConfig `mapstructure:"tee"`
}

// TEEConfig defines configuration for the TEE worker integration.
type TEEConfig struct {
	Mode     string `mapstructure:"mode"`
	Endpoint string `mapstructure:"endpoint"`
}

// initAppConfig sets custom app configuration
func initAppConfig() (string, interface{}) {
	customAppTemplate := strings.TrimSpace(serverconfig.DefaultConfigTemplate) + "\n\n" + strings.TrimSpace(`
[tee]
# TEE client mode: disabled | remote | http | nitro | mock | nitro-simulated
mode = "{{ .TEE.Mode }}"

# Remote TEE worker endpoint (required for remote/http/nitro)
endpoint = "{{ .TEE.Endpoint }}"
`) + "\n"

	customAppConfig := AppConfig{
		Config: *serverconfig.DefaultConfig(),
		TEE: TEEConfig{
			Mode:     "disabled",
			Endpoint: "",
		},
	}
	customAppConfig.MinGasPrices = "0.001uaeth"

	return customAppTemplate, customAppConfig
}

// initRootCmd adds subcommands to the root command
func initRootCmd(rootCmd *cobra.Command, encodingConfig app.EncodingConfig) {
	cfg := sdk.GetConfig()
	cfg.Seal()

	rootCmd.AddCommand(
		genutilcli.InitCmd(app.ModuleBasics, app.DefaultNodeHome),
		genutilcli.MigrateGenesisCmd(genesisMigrationMap()),
		debug.Cmd(),
	)

	server.AddCommands(rootCmd, app.DefaultNodeHome, newApp, appExport, addModuleInitFlags)

	// Add query and tx commands
	rootCmd.AddCommand(
		queryCommand(),
		txCommand(),
		auditCommand(),
		keys.Commands(),
	)
}

// newApp creates a new Aethelred app for the server
func newApp(
	logger log.Logger,
	db dbm.DB,
	traceStore io.Writer,
	appOpts servertypes.AppOptions,
) servertypes.Application {
	return app.New(
		logger,
		db,
		traceStore,
		true,
		appOpts,
	)
}

// appExport exports app state
func appExport(
	logger log.Logger,
	db dbm.DB,
	traceStore io.Writer,
	height int64,
	forZeroHeight bool,
	jailAllowedAddrs []string,
	appOpts servertypes.AppOptions,
	modulesToExport []string,
) (servertypes.ExportedApp, error) {
	aethelredApp := app.New(
		logger,
		db,
		traceStore,
		false,
		appOpts,
	)

	// Export genesis
	return aethelredApp.ExportAppStateAndValidators(forZeroHeight, jailAllowedAddrs, modulesToExport)
}

// addModuleInitFlags adds module-specific init flags
func addModuleInitFlags(startCmd *cobra.Command) {
	// Add custom flags here
}

// queryCommand returns the query command group
func queryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "query",
		Aliases:                    []string{"q"},
		Short:                      "Querying subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		rpc.ValidatorCommand(),
		rpc.QueryEventForTxCmd(),
		rpc.WaitTxCmd(),
		authcmd.QueryTxsByEventsCmd(),
		authcmd.QueryTxCmd(),
	)

	// Add custom module query commands
	cmd.AddCommand(seal.GetQueryCmd())
	cmd.AddCommand(pouw.GetQueryCmd())
	cmd.AddCommand(verify.GetQueryCmd())

	cmd.PersistentFlags().String(flags.FlagChainID, "", "The network chain ID")

	return cmd
}

// txCommand returns the tx command group
func txCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "tx",
		Short:                      "Transactions subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		authcmd.GetSignCommand(),
		authcmd.GetSignBatchCommand(),
		authcmd.GetMultiSignCommand(),
		authcmd.GetMultiSignBatchCmd(),
		authcmd.GetValidateSignaturesCommand(),
		authcmd.GetBroadcastCommand(),
		authcmd.GetEncodeCommand(),
		authcmd.GetDecodeCommand(),
	)

	// Add custom module tx commands
	cmd.AddCommand(seal.GetTxCmd())
	cmd.AddCommand(pouw.GetTxCmd())
	cmd.AddCommand(verify.GetTxCmd())
	cmd.AddCommand(attestationTxCommand())

	cmd.PersistentFlags().String(flags.FlagChainID, "", "The network chain ID")

	return cmd
}
