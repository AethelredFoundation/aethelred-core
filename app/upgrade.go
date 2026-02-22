package app

import (
	"context"
	"os"

	storetypes "cosmossdk.io/store/types"
	upgradekeeper "cosmossdk.io/x/upgrade/keeper"
	upgradetypes "cosmossdk.io/x/upgrade/types"

	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/server"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	"github.com/spf13/cast"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

const (
	UpgradeNameV020 = "v0.2.0"
)

func (app *AethelredApp) initUpgradeKeeper(
	keys map[string]*storetypes.KVStoreKey,
	appCodec codec.Codec,
	appOpts servertypes.AppOptions,
) {
	skipUpgradeHeights := getSkipUpgradeHeights(appOpts)
	homePath := cast.ToString(appOpts.Get(flags.FlagHome))
	if homePath == "" {
		homePath = DefaultNodeHome
	}

	app.UpgradeKeeper = upgradekeeper.NewKeeper(
		skipUpgradeHeights,
		runtime.NewKVStoreService(keys[upgradetypes.StoreKey]),
		appCodec,
		homePath,
		app.BaseApp,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)
}

func (app *AethelredApp) RegisterUpgradeHandlers() {
	app.UpgradeKeeper.SetUpgradeHandler(UpgradeNameV020, func(ctx context.Context, plan upgradetypes.Plan, vm module.VersionMap) (module.VersionMap, error) {
		sdkCtx := sdk.UnwrapSDKContext(ctx)
		sdkCtx.Logger().Info("running upgrade handler", "name", plan.Name, "height", plan.Height)

		warnings := keeper.PreUpgradeValidation(sdkCtx, app.PouwKeeper)
		for _, w := range warnings {
			sdkCtx.Logger().Warn("pre-upgrade warning", "warning", w)
		}

		newVM, err := app.ModuleManager.RunMigrations(sdkCtx, app.configurator, vm)
		if err != nil {
			return nil, err
		}

		if err := keeper.PostUpgradeValidation(sdkCtx, app.PouwKeeper); err != nil {
			return nil, err
		}

		return newVM, nil
	})
}

func (app *AethelredApp) SetupUpgradeStoreLoader() {
	upgradeInfo, err := app.UpgradeKeeper.ReadUpgradeInfoFromDisk()
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		app.Logger().Error("failed to read upgrade info", "error", err)
		return
	}

	if app.UpgradeKeeper.IsSkipHeight(upgradeInfo.Height) {
		app.Logger().Info("skipping upgrade at height", "height", upgradeInfo.Height, "name", upgradeInfo.Name)
		return
	}

	switch upgradeInfo.Name {
	case UpgradeNameV020:
		storeUpgrades := storetypes.StoreUpgrades{}
		app.SetStoreLoader(upgradetypes.UpgradeStoreLoader(upgradeInfo.Height, &storeUpgrades))
	}
}

func getSkipUpgradeHeights(appOpts servertypes.AppOptions) map[int64]bool {
	skipUpgradeHeights := make(map[int64]bool)
	skipHeights := cast.ToIntSlice(appOpts.Get(server.FlagUnsafeSkipUpgrades))
	for _, h := range skipHeights {
		skipUpgradeHeights[int64(h)] = true
	}
	return skipUpgradeHeights
}
