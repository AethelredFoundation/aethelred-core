package app

import (
	"encoding/base64"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (app *AethelredApp) recordLivenessFromLastCommit(ctx sdk.Context, commit abci.CommitInfo) {
	if app.evidenceProcessor == nil {
		return
	}

	for _, vote := range commit.Votes {
		if len(vote.Validator.Address) == 0 {
			continue
		}
		validatorAddr := base64.StdEncoding.EncodeToString(vote.Validator.Address)

		if vote.BlockIdFlag == cmtproto.BlockIDFlagAbsent {
			app.evidenceProcessor.RecordValidatorMiss(ctx, validatorAddr)
			continue
		}

		app.evidenceProcessor.RecordValidatorParticipation(ctx, validatorAddr, [32]byte{}, map[string][32]byte{})
	}
}
