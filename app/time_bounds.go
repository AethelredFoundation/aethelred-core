package app

import (
	"encoding/binary"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
)

func (app *AethelredApp) persistLastBlockTime(ctx sdk.Context) {
	if ctx.BlockTime().IsZero() {
		return
	}

	store := ctx.KVStore(app.keys[pouwtypes.StoreKey])
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(ctx.BlockTime().UnixNano()))
	store.Set(pouwtypes.LastBlockTimeKey, buf)
}

func (app *AethelredApp) lastBlockTime(ctx sdk.Context) (time.Time, bool) {
	store := ctx.KVStore(app.keys[pouwtypes.StoreKey])
	bz := store.Get(pouwtypes.LastBlockTimeKey)
	if len(bz) != 8 {
		return time.Time{}, false
	}

	nanos := int64(binary.BigEndian.Uint64(bz))
	if nanos <= 0 {
		return time.Time{}, false
	}

	return time.Unix(0, nanos).UTC(), true
}

func (app *AethelredApp) voteExtensionTimeBounds(ctx sdk.Context) (time.Duration, time.Duration) {
	params, err := app.PouwKeeper.GetParams(ctx)
	if err != nil || params == nil {
		return voteExtensionDefaultMaxPastSkew, voteExtensionDefaultMaxFutureSkew
	}

	pastSecs := params.VoteExtensionMaxPastSkewSecs
	futureSecs := params.VoteExtensionMaxFutureSkewSecs
	if pastSecs <= 0 || futureSecs <= 0 || futureSecs > pastSecs {
		return voteExtensionDefaultMaxPastSkew, voteExtensionDefaultMaxFutureSkew
	}

	return time.Duration(pastSecs) * time.Second, time.Duration(futureSecs) * time.Second
}
