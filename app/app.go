package app

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	dbm "github.com/cosmos/cosmos-db"
	"github.com/spf13/cast"

	"cosmossdk.io/log"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/tmhash"

	storetypes "cosmossdk.io/store/types"
	"cosmossdk.io/x/evidence"
	evidencekeeper "cosmossdk.io/x/evidence/keeper"
	evidencetypes "cosmossdk.io/x/evidence/types"
	"cosmossdk.io/x/feegrant"
	feegrantkeeper "cosmossdk.io/x/feegrant/keeper"
	feegrantmodule "cosmossdk.io/x/feegrant/module"
	"cosmossdk.io/x/upgrade"
	upgradekeeper "cosmossdk.io/x/upgrade/keeper"
	upgradetypes "cosmossdk.io/x/upgrade/types"

	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	authcodec "github.com/cosmos/cosmos-sdk/codec/address"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/server/api"
	"github.com/cosmos/cosmos-sdk/server/config"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/cosmos/cosmos-sdk/x/auth"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/auth/vesting"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	authzkeeper "github.com/cosmos/cosmos-sdk/x/authz/keeper"
	authzmodule "github.com/cosmos/cosmos-sdk/x/authz/module"
	"github.com/cosmos/cosmos-sdk/x/bank"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/cosmos-sdk/x/consensus"
	consensuskeeper "github.com/cosmos/cosmos-sdk/x/consensus/keeper"
	"github.com/cosmos/cosmos-sdk/x/crisis"
	crisiskeeper "github.com/cosmos/cosmos-sdk/x/crisis/keeper"
	crisistypes "github.com/cosmos/cosmos-sdk/x/crisis/types"
	distr "github.com/cosmos/cosmos-sdk/x/distribution"
	distrkeeper "github.com/cosmos/cosmos-sdk/x/distribution/keeper"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	"github.com/cosmos/cosmos-sdk/x/genutil"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	"github.com/cosmos/cosmos-sdk/x/gov"
	govclient "github.com/cosmos/cosmos-sdk/x/gov/client"
	govkeeper "github.com/cosmos/cosmos-sdk/x/gov/keeper"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	"github.com/cosmos/cosmos-sdk/x/mint"
	mintkeeper "github.com/cosmos/cosmos-sdk/x/mint/keeper"
	minttypes "github.com/cosmos/cosmos-sdk/x/mint/types"
	"github.com/cosmos/cosmos-sdk/x/params"
	paramsclient "github.com/cosmos/cosmos-sdk/x/params/client"
	paramskeeper "github.com/cosmos/cosmos-sdk/x/params/keeper"
	paramstypes "github.com/cosmos/cosmos-sdk/x/params/types"
	"github.com/cosmos/cosmos-sdk/x/slashing"
	slashingkeeper "github.com/cosmos/cosmos-sdk/x/slashing/keeper"
	slashingtypes "github.com/cosmos/cosmos-sdk/x/slashing/types"
	"github.com/cosmos/cosmos-sdk/x/staking"
	stakingkeeper "github.com/cosmos/cosmos-sdk/x/staking/keeper"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/cosmos/gogoproto/grpc"

	// Aethelred custom modules
	sovereigncrisiskeeper "github.com/aethelred/aethelred/x/crisis/keeper"
	sovereigncrisistypes "github.com/aethelred/aethelred/x/crisis/types"
	insurancekeeper "github.com/aethelred/aethelred/x/insurance/keeper"
	insurancetypes "github.com/aethelred/aethelred/x/insurance/types"
	"github.com/aethelred/aethelred/x/pouw"
	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
	"github.com/aethelred/aethelred/x/seal"
	sealkeeper "github.com/aethelred/aethelred/x/seal/keeper"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
	"github.com/aethelred/aethelred/x/verify"
	verifykeeper "github.com/aethelred/aethelred/x/verify/keeper"
	verifytypes "github.com/aethelred/aethelred/x/verify/types"
)

const (
	// Name is the name of the application
	Name = "aethelred"
	// AccountAddressPrefix is the prefix for account addresses
	AccountAddressPrefix = "aeth"
	// BondDenom is the staking token denomination
	BondDenom = "uaeth"
)

var (
	// DefaultNodeHome is the default home directory for the application
	DefaultNodeHome string

	// ModuleBasics defines the module BasicManager that is in charge of setting up basic,
	// non-dependant module elements, such as codec registration and genesis verification.
	ModuleBasics = module.NewBasicManager(
		auth.AppModuleBasic{},
		genutil.NewAppModuleBasic(genutiltypes.DefaultMessageValidator),
		bank.AppModuleBasic{},
		staking.AppModuleBasic{},
		mint.AppModuleBasic{},
		distr.AppModuleBasic{},
		gov.NewAppModuleBasic([]govclient.ProposalHandler{
			paramsclient.ProposalHandler,
		}),
		params.AppModuleBasic{},
		crisis.AppModuleBasic{},
		slashing.AppModuleBasic{},
		feegrantmodule.AppModuleBasic{},
		authzmodule.AppModuleBasic{},
		consensus.AppModuleBasic{},
		vesting.AppModuleBasic{},
		upgrade.AppModuleBasic{},
		evidence.AppModuleBasic{},
		// Aethelred custom modules
		seal.AppModuleBasic{},
		pouw.AppModuleBasic{},
		verify.AppModuleBasic{},
	)
)

func init() {
	// Use SafeGetDefaultNodeHome for graceful degradation instead of panic
	home, err := SafeGetDefaultNodeHome()
	if err != nil {
		// Log warning but continue with the fallback path
		fmt.Fprintf(os.Stderr, "WARNING: %v\n", err)
	}
	DefaultNodeHome = home
}

// AethelredApp extends an ABCI application with Proof-of-Useful-Work consensus
type AethelredApp struct {
	*baseapp.BaseApp

	legacyAmino       *codec.LegacyAmino
	appCodec          codec.Codec
	txConfig          client.TxConfig
	interfaceRegistry codectypes.InterfaceRegistry

	// keys to access the substores
	keys    map[string]*storetypes.KVStoreKey
	tkeys   map[string]*storetypes.TransientStoreKey
	memKeys map[string]*storetypes.MemoryStoreKey

	// keepers - standard Cosmos SDK modules
	AccountKeeper         authkeeper.AccountKeeper
	BankKeeper            bankkeeper.Keeper
	StakingKeeper         *stakingkeeper.Keeper
	SlashingKeeper        slashingkeeper.Keeper
	MintKeeper            mintkeeper.Keeper
	DistrKeeper           distrkeeper.Keeper
	GovKeeper             govkeeper.Keeper
	CrisisKeeper          *crisiskeeper.Keeper
	UpgradeKeeper         *upgradekeeper.Keeper
	ParamsKeeper          paramskeeper.Keeper
	AuthzKeeper           authzkeeper.Keeper
	EvidenceKeeper        evidencekeeper.Keeper
	FeeGrantKeeper        feegrantkeeper.Keeper
	ConsensusParamsKeeper consensuskeeper.Keeper

	// keepers - Aethelred custom modules
	SealKeeper            sealkeeper.Keeper
	PouwKeeper            pouwkeeper.Keeper
	VerifyKeeper          verifykeeper.Keeper
	InsuranceKeeper       insurancekeeper.Keeper
	SovereignCrisisKeeper sovereigncrisiskeeper.Keeper

	// TEE client for compute verification
	teeClient TEEClient

	// orchestrator coordinates zkML and TEE verification services.
	// Created during initVerificationPipeline().
	orchestrator *verify.VerificationOrchestrator

	// consensusHandler manages Proof-of-Useful-Work consensus logic.
	// It holds the JobVerifier (OrchestratorBridge) that delegates to
	// the real TEE/zkML verification pipeline.
	consensusHandler *pouwkeeper.ConsensusHandler

	// evidenceProcessor handles downtime and equivocation evidence processing.
	evidenceProcessor *pouwkeeper.EvidenceProcessor

	// Module manager
	ModuleManager *module.Manager

	// Module configurator
	configurator module.Configurator

	// simulation manager
	sm *module.SimulationManager

	// readinessChecked tracks whether the one-time production readiness
	// check has been performed. It runs on the first BeginBlock.
	readinessChecked bool

	// validatorPrivKey is the validator's ed25519 private key for signing
	// vote extensions. This is REQUIRED in production mode (AllowSimulated=false).
	// Set via SetValidatorPrivateKey() during node initialization.
	// SECURITY: This key MUST be kept secure and never exposed.
	validatorPrivKey []byte

	// validatorConsAddr is the consensus address derived from validatorPrivKey.
	// This is used to stamp vote extensions with the validator's own address.
	validatorConsAddr []byte

	// voteExtensionCache stores verified vote extensions by height so
	// ProcessProposal can enforce computation finality.
	voteExtensionCache *VoteExtensionCache

	// shutdownManager coordinates graceful shutdown of all components.
	// Initialized via InitShutdownManager() during app creation.
	shutdownManager *ShutdownManager

	// rateLimiter provides rate limiting for API endpoints and transactions.
	// Initialized via InitRateLimiter() during app creation.
	rateLimiter *RateLimiter

	// integratedEvidenceProcessor handles downtime and equivocation evidence
	// with full Cosmos SDK slashing module integration (AS-16).
	integratedEvidenceProcessor *pouwkeeper.IntegratedEvidenceProcessor

	// voteExtensionSigner handles application-level signing of vote extensions (AS-17).
	voteExtensionSigner *VoteExtensionSigner

	// voteExtensionVerifier verifies vote extensions from other validators (AS-17).
	voteExtensionVerifier *VoteExtensionVerifier
}

// New returns a reference to an initialized AethelredApp.
func New(
	logger log.Logger,
	db dbm.DB,
	traceStore io.Writer,
	loadLatest bool,
	appOpts servertypes.AppOptions,
	baseAppOptions ...func(*baseapp.BaseApp),
) *AethelredApp {
	// Initialize encodings
	encodingConfig := MakeEncodingConfig()
	appCodec := encodingConfig.Codec
	legacyAmino := encodingConfig.Amino
	interfaceRegistry := encodingConfig.InterfaceRegistry
	txConfig := encodingConfig.TxConfig

	// Create base application
	bApp := baseapp.NewBaseApp(
		Name,
		logger,
		db,
		txConfig.TxDecoder(),
		baseAppOptions...,
	)
	bApp.SetCommitMultiStoreTracer(traceStore)
	bApp.SetVersion(Version)
	bApp.SetInterfaceRegistry(interfaceRegistry)
	bApp.SetTxEncoder(txConfig.TxEncoder())

	// Use safe PQC initialization with graceful degradation (AS-16 compliance)
	if err := SafeInitPQCMode(logger, appOpts); err != nil {
		logger.Error("PQC initialization returned error, continuing with classical crypto", "error", err)
	}

	// Initialize store keys
	keys := storetypes.NewKVStoreKeys(
		authtypes.StoreKey,
		banktypes.StoreKey,
		stakingtypes.StoreKey,
		minttypes.StoreKey,
		distrtypes.StoreKey,
		slashingtypes.StoreKey,
		govtypes.StoreKey,
		paramstypes.StoreKey,
		upgradetypes.StoreKey,
		feegrant.StoreKey,
		evidencetypes.StoreKey,
		authzkeeper.StoreKey,
		crisistypes.StoreKey,
		// Aethelred custom module store keys
		sealtypes.StoreKey,
		pouwtypes.StoreKey,
		verifytypes.StoreKey,
		insurancetypes.StoreKey,
		sovereigncrisistypes.StoreKey,
	)
	tkeys := storetypes.NewTransientStoreKeys(paramstypes.TStoreKey)
	memKeys := storetypes.NewMemoryStoreKeys()

	// Create the application
	app := &AethelredApp{
		BaseApp:            bApp,
		legacyAmino:        legacyAmino,
		appCodec:           appCodec,
		txConfig:           txConfig,
		interfaceRegistry:  interfaceRegistry,
		keys:               keys,
		tkeys:              tkeys,
		memKeys:            memKeys,
		voteExtensionCache: NewVoteExtensionCache(4),
	}
	app.InitShutdownManager()
	app.InitRateLimiter()

	// Initialize params keeper and subspaces
	app.ParamsKeeper = initParamsKeeper(
		appCodec,
		legacyAmino,
		keys[paramstypes.StoreKey],
		tkeys[paramstypes.TStoreKey],
	)

	// Set the BaseApp's parameter store
	app.ConsensusParamsKeeper = consensuskeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[paramstypes.StoreKey]),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
		runtime.EventService{},
	)
	bApp.SetParamStore(app.ConsensusParamsKeeper.ParamsStore)

	// Initialize keepers for standard modules
	app.initStandardKeepers(keys, appCodec, legacyAmino)
	app.initUpgradeKeeper(keys, appCodec, appOpts)

	// Initialize Aethelred custom module keepers
	app.initAethelredKeepers(keys, appCodec)

	// Create module manager with all modules
	app.setupModuleManager()
	app.configurator = module.NewConfigurator(app.appCodec, app.MsgServiceRouter(), app.GRPCQueryRouter())
	app.ModuleManager.RegisterServices(app.configurator)
	app.RegisterUpgradeHandlers()
	app.UpgradeKeeper.SetInitVersionMap(app.ModuleManager.GetVersionMap())

	// Initialize TEE client (required for production verification)
	app.initTEEClient(appOpts)

	// Build the full verification pipeline:
	// VerificationOrchestrator → OrchestratorBridge → ConsensusHandler
	app.initVerificationPipeline()
	app.RegisterShutdownComponents()

	// Initialize integrated slashing system (AS-16)
	app.InitIntegratedSlashing()

	// Initialize vote extension signing/verification (AS-17)
	chainID := cast.ToString(appOpts.Get("chain-id"))
	if chainID == "" {
		chainID = "aethelred-1"
	}
	app.InitVoteExtensionSigner(chainID)
	app.InitVoteExtensionVerifier(chainID)

	// Initialize stores
	app.MountKVStores(keys)
	app.MountTransientStores(tkeys)
	app.MountMemoryStores(memKeys)

	// Initialize BaseApp
	app.SetInitChainer(app.InitChainer)
	app.SetBeginBlocker(app.BeginBlocker)
	app.SetEndBlocker(app.EndBlocker)

	// Set ABCI++ handlers for Proof-of-Useful-Work
	app.SetExtendVoteHandler(app.ExtendVoteHandler())
	app.SetVerifyVoteExtensionHandler(app.VerifyVoteExtensionHandler())
	app.SetPrepareProposal(app.PrepareProposalHandler())
	app.SetProcessProposal(app.ProcessProposalHandler())

	// Set ante handler
	app.SetAnteHandler(NewAnteHandler(app))

	app.SetupUpgradeStoreLoader()

	if loadLatest {
		if err := SafeLoadLatestVersion(app, logger); err != nil {
			// Critical error - cannot recover from state loading failure
			logger.Error("CRITICAL: Failed to load latest version, cannot continue", "error", err)
			panic(err) // This panic is intentional - state corruption is unrecoverable
		}
	}

	return app
}

// initStandardKeepers initializes all standard Cosmos SDK keepers
func (app *AethelredApp) initStandardKeepers(
	keys map[string]*storetypes.KVStoreKey,
	appCodec codec.Codec,
	legacyAmino *codec.LegacyAmino,
) {
	// Account keeper
	app.AccountKeeper = authkeeper.NewAccountKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[authtypes.StoreKey]),
		authtypes.ProtoBaseAccount,
		maccPerms,
		authcodec.NewBech32Codec(AccountAddressPrefix),
		AccountAddressPrefix,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// Bank keeper
	app.BankKeeper = bankkeeper.NewBaseKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[banktypes.StoreKey]),
		app.AccountKeeper,
		BlockedAddresses(),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
		app.Logger(),
	)

	// Staking keeper
	app.StakingKeeper = stakingkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[stakingtypes.StoreKey]),
		app.AccountKeeper,
		app.BankKeeper,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
		authcodec.NewBech32Codec(sdk.GetConfig().GetBech32ValidatorAddrPrefix()),
		authcodec.NewBech32Codec(sdk.GetConfig().GetBech32ConsensusAddrPrefix()),
	)

	// Mint keeper
	app.MintKeeper = mintkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[minttypes.StoreKey]),
		app.StakingKeeper,
		app.AccountKeeper,
		app.BankKeeper,
		authtypes.FeeCollectorName,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// Distribution keeper
	app.DistrKeeper = distrkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[distrtypes.StoreKey]),
		app.AccountKeeper,
		app.BankKeeper,
		app.StakingKeeper,
		authtypes.FeeCollectorName,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// Slashing keeper
	app.SlashingKeeper = slashingkeeper.NewKeeper(
		appCodec,
		legacyAmino,
		runtime.NewKVStoreService(keys[slashingtypes.StoreKey]),
		app.StakingKeeper,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)
}

// initAethelredKeepers initializes Aethelred custom module keepers
func (app *AethelredApp) initAethelredKeepers(
	keys map[string]*storetypes.KVStoreKey,
	appCodec codec.Codec,
) {
	// Seal keeper - manages Digital Seals for verified computations
	app.SealKeeper = sealkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[sealtypes.StoreKey]),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// Verify keeper - handles zkML and TEE verification
	app.VerifyKeeper = verifykeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[verifytypes.StoreKey]),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// PoUW keeper - manages Proof-of-Useful-Work consensus and jobs
	app.PouwKeeper = pouwkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[pouwtypes.StoreKey]),
		app.StakingKeeper,
		app.BankKeeper,
		app.SealKeeper,
		app.VerifyKeeper,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// Insurance keeper - escrow and appeal tribunal for fraud slashes.
	app.InsuranceKeeper = insurancekeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[insurancetypes.StoreKey]),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)
	app.InsuranceKeeper.SetValidatorSource(NewPoUWTribunalValidatorSource(&app.PouwKeeper))

	// Sovereign crisis keeper - emergency halt controls for bridge and PoUW allocation.
	app.SovereignCrisisKeeper = sovereigncrisiskeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[sovereigncrisistypes.StoreKey]),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)
}

// initTEEClient configures the TEE client based on app options.
// Supported modes:
// - disabled (default)
// - remote / http / nitro (requires aethelred.tee.endpoint)
// - nitro-simulated (dev/test only)
// - mock (dev/test only)
func (app *AethelredApp) initTEEClient(appOpts servertypes.AppOptions) {
	mode := strings.ToLower(firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.tee.mode")),
		cast.ToString(appOpts.Get("tee.mode")),
	))
	if mode == "" {
		mode = strings.ToLower(os.Getenv("AETHELRED_TEE_MODE"))
	}
	if mode == "" {
		mode = "disabled"
	}

	if mode == "disabled" {
		app.Logger().Info("TEE client disabled")
		return
	}

	endpoint := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.tee.endpoint")),
		cast.ToString(appOpts.Get("tee.endpoint")),
	)
	if endpoint == "" {
		endpoint = os.Getenv("AETHELRED_TEE_ENDPOINT")
	}
	factory := NewTEEClientFactory(app.Logger())
	client, err := factory.Create(mode, map[string]string{
		"endpoint": endpoint,
	})
	if err != nil {
		// Log error but don't panic - allow graceful degradation
		app.Logger().Error("TEE client initialization failed, running in degraded mode",
			"error", err,
			"mode", mode,
		)
		return // Continue without TEE client
	}

	app.teeClient = client
	app.Logger().Info("TEE client initialized",
		"mode", mode,
		"endpoint", endpoint,
	)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// setupModuleManager creates and configures the module manager
func (app *AethelredApp) setupModuleManager() {
	app.ModuleManager = module.NewManager(
		genutil.NewAppModule(app.AccountKeeper, app.StakingKeeper, app, app.txConfig),
		auth.NewAppModule(app.appCodec, app.AccountKeeper, nil, app.GetSubspace(authtypes.ModuleName)),
		vesting.NewAppModule(app.AccountKeeper, app.BankKeeper),
		bank.NewAppModule(app.appCodec, app.BankKeeper, app.AccountKeeper, app.GetSubspace(banktypes.ModuleName)),
		staking.NewAppModule(app.appCodec, app.StakingKeeper, app.AccountKeeper, app.BankKeeper, app.GetSubspace(stakingtypes.ModuleName)),
		mint.NewAppModule(app.appCodec, app.MintKeeper, app.AccountKeeper, nil, app.GetSubspace(minttypes.ModuleName)),
		distr.NewAppModule(app.appCodec, app.DistrKeeper, app.AccountKeeper, app.BankKeeper, app.StakingKeeper, app.GetSubspace(distrtypes.ModuleName)),
		slashing.NewAppModule(app.appCodec, app.SlashingKeeper, app.AccountKeeper, app.BankKeeper, app.StakingKeeper, app.GetSubspace(slashingtypes.ModuleName), app.interfaceRegistry),
		params.NewAppModule(app.ParamsKeeper),
		consensus.NewAppModule(app.appCodec, app.ConsensusParamsKeeper),
		// Aethelred custom modules
		seal.NewAppModule(app.appCodec, app.SealKeeper),
		pouw.NewAppModule(app.appCodec, app.PouwKeeper),
		verify.NewAppModule(app.appCodec, app.VerifyKeeper),
	)

	// Set order of module operations
	app.ModuleManager.SetOrderBeginBlockers(
		upgradetypes.ModuleName,
		minttypes.ModuleName,
		distrtypes.ModuleName,
		slashingtypes.ModuleName,
		evidencetypes.ModuleName,
		stakingtypes.ModuleName,
		authtypes.ModuleName,
		banktypes.ModuleName,
		govtypes.ModuleName,
		crisistypes.ModuleName,
		genutiltypes.ModuleName,
		authz.ModuleName,
		feegrant.ModuleName,
		paramstypes.ModuleName,
		vestingtypes.ModuleName,
		// Aethelred modules
		pouwtypes.ModuleName,
		sealtypes.ModuleName,
		verifytypes.ModuleName,
	)

	app.ModuleManager.SetOrderEndBlockers(
		crisistypes.ModuleName,
		govtypes.ModuleName,
		stakingtypes.ModuleName,
		// Aethelred modules - process compute jobs at end of block
		pouwtypes.ModuleName,
		sealtypes.ModuleName,
		verifytypes.ModuleName,
	)

	app.ModuleManager.SetOrderInitGenesis(
		authtypes.ModuleName,
		banktypes.ModuleName,
		distrtypes.ModuleName,
		stakingtypes.ModuleName,
		slashingtypes.ModuleName,
		govtypes.ModuleName,
		minttypes.ModuleName,
		crisistypes.ModuleName,
		genutiltypes.ModuleName,
		evidencetypes.ModuleName,
		authz.ModuleName,
		feegrant.ModuleName,
		paramstypes.ModuleName,
		upgradetypes.ModuleName,
		vestingtypes.ModuleName,
		// Aethelred modules
		sealtypes.ModuleName,
		verifytypes.ModuleName,
		pouwtypes.ModuleName,
	)
}

// Name returns the name of the App
func (app *AethelredApp) Name() string { return Name }

// BeginBlocker application updates at every begin block
func (app *AethelredApp) BeginBlocker(ctx sdk.Context) (resp sdk.BeginBlock, err error) {
	defer app.recoverABCI("BeginBlocker", &err)

	app.persistLastBlockTime(ctx)

	// Run the one-time production readiness check on the first block.
	// This ensures genesis state is loaded and params are available.
	if !app.readinessChecked {
		app.readinessChecked = true
		app.RunProductionReadinessChecks(ctx)
	}

	if metrics := app.PouwKeeper.Metrics(); metrics != nil {
		metrics.BlocksProcessed.Inc()
		metrics.LastBlockHeight.Set(ctx.BlockHeight())
		total, online := app.PouwKeeper.CountValidators(ctx)
		metrics.TotalValidators.Set(int64(total))
		metrics.ActiveValidators.Set(int64(online))
	}

	if expired, processErr := app.InsuranceKeeper.ProcessEscrowExpiries(ctx); processErr != nil {
		app.Logger().Error("Insurance escrow expiry processing failed", "error", processErr)
	} else if expired > 0 {
		app.Logger().Info("Insurance escrows forfeited after expiry", "count", expired)
	}

	return app.ModuleManager.BeginBlock(ctx)
}

// EndBlocker application updates at every end block
func (app *AethelredApp) EndBlocker(ctx sdk.Context) (resp sdk.EndBlock, err error) {
	defer app.recoverABCI("EndBlocker", &err)

	resp, err = app.ModuleManager.EndBlock(ctx)
	if err != nil {
		return resp, err
	}

	app.processEndBlockEvidence(ctx)

	return resp, nil
}

// InitChainer application update at chain initialization
func (app *AethelredApp) InitChainer(ctx sdk.Context, req *abci.RequestInitChain) (resp *abci.ResponseInitChain, err error) {
	defer app.recoverABCI("InitChainer", &err)

	var genesisState GenesisState
	if err := json.Unmarshal(req.AppStateBytes, &genesisState); err != nil {
		return nil, err
	}
	return app.ModuleManager.InitGenesis(ctx, app.appCodec, genesisState)
}

// LoadHeight loads a particular height
func (app *AethelredApp) LoadHeight(height int64) error {
	return app.LoadVersion(height)
}

// LegacyAmino returns the legacy amino codec
func (app *AethelredApp) LegacyAmino() *codec.LegacyAmino {
	return app.legacyAmino
}

// AppCodec returns the app codec
func (app *AethelredApp) AppCodec() codec.Codec {
	return app.appCodec
}

// InterfaceRegistry returns the interface registry
func (app *AethelredApp) InterfaceRegistry() codectypes.InterfaceRegistry {
	return app.interfaceRegistry
}

// TxConfig returns the tx config
func (app *AethelredApp) TxConfig() client.TxConfig {
	return app.txConfig
}

// GetSubspace returns a param subspace for a given module name
func (app *AethelredApp) GetSubspace(moduleName string) paramstypes.Subspace {
	subspace, _ := app.ParamsKeeper.GetSubspace(moduleName)
	return subspace
}

// RegisterAPIRoutes registers all application module routes with the provided API server
func (app *AethelredApp) RegisterAPIRoutes(apiSvr *api.Server, apiConfig config.APIConfig) {
	// In Cosmos SDK v0.50, gRPC gateway routes are registered via the module manager
	ModuleBasics.RegisterGRPCGatewayRoutes(apiSvr.ClientCtx, apiSvr.GRPCGatewayRouter)

	// Aethelred-specific metrics endpoint
	apiSvr.Router.Handle("/metrics/aethelred", app.MetricsHandler()).Methods("GET")
	// Aethelred-specific health endpoint (component-level)
	apiSvr.Router.Handle("/health/aethelred", app.HealthHandler()).Methods("GET")
	// Admin endpoint for deterministic pre-proposal consensus evidence auditing.
	apiSvr.Router.Handle("/admin/consensus/evidence/audit", app.ConsensusEvidenceAuditHandler()).Methods("POST")
}

// GetMaccPerms returns a copy of the module account permissions
func GetMaccPerms() map[string][]string {
	dupMaccPerms := make(map[string][]string)
	for k, v := range maccPerms {
		dupMaccPerms[k] = v
	}
	return dupMaccPerms
}

// BlockedAddresses returns all the app's blocked account addresses
func BlockedAddresses() map[string]bool {
	modAccAddrs := make(map[string]bool)
	for acc := range GetMaccPerms() {
		modAccAddrs[authtypes.NewModuleAddress(acc).String()] = true
	}
	return modAccAddrs
}

// initParamsKeeper initializes the params keeper and subspaces
func initParamsKeeper(
	appCodec codec.Codec,
	legacyAmino *codec.LegacyAmino,
	key storetypes.StoreKey,
	tkey storetypes.StoreKey,
) paramskeeper.Keeper {
	paramsKeeper := paramskeeper.NewKeeper(appCodec, legacyAmino, key, tkey)

	// Register param subspaces
	paramsKeeper.Subspace(authtypes.ModuleName)
	paramsKeeper.Subspace(banktypes.ModuleName)
	paramsKeeper.Subspace(stakingtypes.ModuleName)
	paramsKeeper.Subspace(minttypes.ModuleName)
	paramsKeeper.Subspace(distrtypes.ModuleName)
	paramsKeeper.Subspace(slashingtypes.ModuleName)
	paramsKeeper.Subspace(govtypes.ModuleName)
	paramsKeeper.Subspace(crisistypes.ModuleName)
	// Aethelred custom modules
	paramsKeeper.Subspace(sealtypes.ModuleName)
	paramsKeeper.Subspace(pouwtypes.ModuleName)
	paramsKeeper.Subspace(verifytypes.ModuleName)
	paramsKeeper.Subspace(insurancetypes.ModuleName)
	paramsKeeper.Subspace(sovereigncrisistypes.ModuleName)

	return paramsKeeper
}

// maccPerms is a map of module account permissions
var maccPerms = map[string][]string{
	authtypes.FeeCollectorName:     nil,
	distrtypes.ModuleName:          nil,
	minttypes.ModuleName:           {authtypes.Minter},
	stakingtypes.BondedPoolName:    {authtypes.Burner, authtypes.Staking},
	stakingtypes.NotBondedPoolName: {authtypes.Burner, authtypes.Staking},
	govtypes.ModuleName:            {authtypes.Burner},
	// Aethelred modules - pouw module can mint rewards and burn slashed tokens
	pouwtypes.ModuleName:          {authtypes.Minter, authtypes.Burner},
	pouwtypes.TreasuryModuleName:  nil,
	pouwtypes.InsuranceModuleName: nil,
}

// Version is the application version
const Version = "0.1.0"

// GenesisState represents the genesis state of the blockchain
type GenesisState map[string]json.RawMessage

// NewDefaultGenesisState generates the default state for the application
func NewDefaultGenesisState(cdc codec.Codec) GenesisState {
	return ModuleBasics.DefaultGenesis(cdc)
}

// SetValidatorPrivateKey sets the validator's ed25519 private key for signing
// vote extensions. This MUST be called during node initialization before the
// chain starts producing blocks.
//
// SECURITY REQUIREMENTS:
//   - The key must be exactly 64 bytes (ed25519 private key format)
//   - The key must be kept secure and never logged or exposed
//   - In production mode (AllowSimulated=false), unsigned vote extensions
//     will be rejected by other validators
//
// This method should be called from the node's startup sequence after loading
// the validator's key from the keyring or secure storage.
func (app *AethelredApp) SetValidatorPrivateKey(privKey []byte) error {
	if len(privKey) != 64 {
		return fmt.Errorf("invalid ed25519 private key length: expected 64, got %d", len(privKey))
	}

	// Make a copy to prevent external modification
	app.validatorPrivKey = make([]byte, 64)
	copy(app.validatorPrivKey, privKey)

	consAddr, err := app.validatorConsensusAddress()
	if err != nil {
		return fmt.Errorf("failed to derive validator consensus address: %w", err)
	}
	app.validatorConsAddr = make([]byte, len(consAddr))
	copy(app.validatorConsAddr, consAddr)

	app.Logger().Info("Validator private key configured for vote extension signing")
	return nil
}

// validatorConsensusAddress derives the consensus address from the configured
// ed25519 private key. It does not mutate app state.
func (app *AethelredApp) validatorConsensusAddress() ([]byte, error) {
	if len(app.validatorPrivKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("validator private key not configured")
	}

	pubKey := ed25519.PrivateKey(app.validatorPrivKey).Public().(ed25519.PublicKey)
	return tmhash.SumTruncated(pubKey), nil
}

// HasValidatorPrivateKey returns true if the validator private key is configured
func (app *AethelredApp) HasValidatorPrivateKey() bool {
	return len(app.validatorPrivKey) == 64
}

// RegisterNodeService implements the Application.RegisterNodeService method
func (app *AethelredApp) RegisterNodeService(clientCtx client.Context, cfg config.Config) {
	// Node service registration for Cosmos SDK v0.50+
	// This is called by the server to register node-related services
}

// RegisterTendermintService implements the Application.RegisterTendermintService method
func (app *AethelredApp) RegisterTendermintService(clientCtx client.Context) {
	// CometBFT service registration for Cosmos SDK v0.50+
}

// RegisterTxService implements the Application.RegisterTxService method
func (app *AethelredApp) RegisterTxService(clientCtx client.Context) {
	// Tx service registration for Cosmos SDK v0.50+
}

// RegisterGRPCServer implements the Application.RegisterGRPCServer method
func (app *AethelredApp) RegisterGRPCServer(grpcServer grpc.Server) {
	// gRPC server registration
}

// ExportAppStateAndValidators exports the application state for genesis export
func (app *AethelredApp) ExportAppStateAndValidators(
	forZeroHeight bool,
	jailAllowedAddrs []string,
	modulesToExport []string,
) (servertypes.ExportedApp, error) {
	// Export genesis state from all modules
	ctx := app.NewContext(true)

	// Get the genesis state
	genState, err := app.ModuleManager.ExportGenesis(ctx, app.appCodec)
	if err != nil {
		return servertypes.ExportedApp{}, err
	}

	appState, err := json.MarshalIndent(genState, "", "  ")
	if err != nil {
		return servertypes.ExportedApp{}, err
	}

	return servertypes.ExportedApp{
		AppState:        appState,
		Height:          app.LastBlockHeight(),
		ConsensusParams: app.GetConsensusParams(ctx),
	}, nil
}
