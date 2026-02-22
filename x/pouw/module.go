package pouw

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/spf13/cobra"

	abci "github.com/cometbft/cometbft/abci/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"

	"github.com/aethelred/aethelred/x/pouw/client/cli"
	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

var (
	_ module.AppModule      = AppModule{}
	_ module.AppModuleBasic = AppModuleBasic{}
)

// AppModuleBasic implements the AppModuleBasic interface for the pouw (Proof-of-Useful-Work) module.
type AppModuleBasic struct{}

// Name returns the module's name.
func (AppModuleBasic) Name() string {
	return types.ModuleName
}

// RegisterLegacyAminoCodec registers the module's types on the LegacyAmino codec.
func (AppModuleBasic) RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
	types.RegisterLegacyAminoCodec(cdc)
}

// RegisterInterfaces registers the module's interface types.
func (AppModuleBasic) RegisterInterfaces(reg cdctypes.InterfaceRegistry) {
	types.RegisterInterfaces(reg)
}

// DefaultGenesis returns the module's default genesis state.
func (AppModuleBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	return cdc.MustMarshalJSON(types.DefaultGenesis())
}

// ValidateGenesis performs genesis state validation.
func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, config client.TxEncodingConfig, bz json.RawMessage) error {
	var gs types.GenesisState
	if err := cdc.UnmarshalJSON(bz, &gs); err != nil {
		return fmt.Errorf("failed to unmarshal %s genesis state: %w", types.ModuleName, err)
	}
	return gs.Validate()
}

// RegisterGRPCGatewayRoutes registers the gRPC Gateway routes for the module.
func (AppModuleBasic) RegisterGRPCGatewayRoutes(clientCtx client.Context, mux *runtime.ServeMux) {
	// Register gRPC gateway routes here
}

// GetTxCmd returns the module's root tx command.
func (AppModuleBasic) GetTxCmd() *cobra.Command {
	return GetTxCmd()
}

// GetQueryCmd returns the module's root query command.
func (AppModuleBasic) GetQueryCmd() *cobra.Command {
	return GetQueryCmd()
}

// AppModule implements the AppModule interface for the pouw module.
type AppModule struct {
	AppModuleBasic

	keeper keeper.Keeper
}

// NewAppModule creates a new AppModule object.
func NewAppModule(cdc codec.Codec, keeper keeper.Keeper) AppModule {
	return AppModule{
		AppModuleBasic: AppModuleBasic{},
		keeper:         keeper,
	}
}

// Name returns the module's name.
func (am AppModule) Name() string {
	return types.ModuleName
}

// RegisterServices registers module services.
func (am AppModule) RegisterServices(cfg module.Configurator) {
	// Register msg server
	types.RegisterMsgServer(cfg.MsgServer(), keeper.NewMsgServerImpl(am.keeper))

	// Register query server
	types.RegisterQueryServer(cfg.QueryServer(), keeper.NewQueryServerImpl(am.keeper))

	// Register migrations
	if err := cfg.RegisterMigration(types.ModuleName, 1, func(ctx sdk.Context) error {
		return keeper.RunMigrations(ctx, am.keeper, 1, 2)
	}); err != nil {
		panic(err)
	}
}

// RegisterInvariants registers the module's invariants.
func (am AppModule) RegisterInvariants(ir sdk.InvariantRegistry) {
	keeper.RegisterInvariants(ir, am.keeper)
}

// InitGenesis performs the module's genesis initialization.
func (am AppModule) InitGenesis(ctx sdk.Context, cdc codec.JSONCodec, gs json.RawMessage) []abci.ValidatorUpdate {
	var genesisState types.GenesisState
	cdc.MustUnmarshalJSON(gs, &genesisState)

	if err := am.keeper.InitGenesis(ctx, &genesisState); err != nil {
		panic(err)
	}

	return []abci.ValidatorUpdate{}
}

// ExportGenesis returns the module's exported genesis state.
func (am AppModule) ExportGenesis(ctx sdk.Context, cdc codec.JSONCodec) json.RawMessage {
	gs, err := am.keeper.ExportGenesis(ctx)
	if err != nil {
		panic(err)
	}
	return cdc.MustMarshalJSON(gs)
}

// ConsensusVersion implements AppModule/ConsensusVersion.
func (AppModule) ConsensusVersion() uint64 { return keeper.ModuleConsensusVersion }

// BeginBlock executes all ABCI BeginBlock logic.
func (am AppModule) BeginBlock(ctx context.Context) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Process any pending jobs that have reached consensus
	// This is handled by the ABCI++ vote extensions in app/abci.go
	_ = sdkCtx

	return nil
}

// EndBlock executes all ABCI EndBlock logic.
func (am AppModule) EndBlock(ctx context.Context) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Expire old jobs using deterministic block-height-based expiry.
	// DETERMINISM: Use block height (not wall-clock time) to ensure all
	// validators agree on which jobs are expired.
	pendingJobs := am.keeper.GetPendingJobs(ctx)
	currentHeight := sdkCtx.BlockHeight()
	for _, job := range pendingJobs {
		if job == nil {
			continue
		}
		if job.IsExpiredAtHeight(currentHeight) {
			if err := job.MarkExpired(); err != nil {
				// Log but don't halt consensus for invalid transitions
				sdkCtx.Logger().Warn("failed to expire job",
					"job_id", job.Id,
					"current_status", job.Status,
					"error", err,
				)
				continue
			}
			_ = am.keeper.UpdateJob(ctx, job)

			sdkCtx.EventManager().EmitEvent(
				sdk.NewEvent(
					"job_expired",
					sdk.NewAttribute("job_id", job.Id),
					sdk.NewAttribute("block_height", fmt.Sprintf("%d", currentHeight)),
				),
			)
		}
	}

	return nil
}

// IsOnePerModuleType implements the depinject.OnePerModuleType interface.
func (am AppModule) IsOnePerModuleType() {}

// IsAppModule implements the appmodule.AppModule interface.
func (am AppModule) IsAppModule() {}

// GetTxCmd returns the transaction commands for the module
func GetTxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      fmt.Sprintf("%s transactions subcommands", types.ModuleName),
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	// Add tx commands here
	// cmd.AddCommand(CmdSubmitJob())
	// cmd.AddCommand(CmdRegisterModel())
	cmd.AddCommand(cli.CmdStakeForPoUW())
	cmd.AddCommand(cli.CmdRegisterValidatorCapability())
	cmd.AddCommand(cli.CmdRegisterValidatorPCR0())

	return cmd
}

// GetQueryCmd returns the query commands for the module
func GetQueryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      fmt.Sprintf("Querying commands for the %s module", types.ModuleName),
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	// Add query commands here
	// cmd.AddCommand(CmdQueryJob())
	// cmd.AddCommand(CmdListJobs())
	cmd.AddCommand(cli.CmdQueryPoUWStatus())
	cmd.AddCommand(cli.CmdQueryValidatorPCR0())
	cmd.AddCommand(cli.CmdQueryIsPCR0Registered())

	return cmd
}
