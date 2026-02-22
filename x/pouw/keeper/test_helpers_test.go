package keeper_test

import (
	"context"
	"time"

	"cosmossdk.io/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func sdkTestContext() context.Context {
	header := tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  100,
		Time:    time.Now().UTC(),
	}
	sdkCtx := sdk.NewContext(nil, header, false, log.NewNopLogger())
	return sdk.WrapSDKContext(sdkCtx)
}
