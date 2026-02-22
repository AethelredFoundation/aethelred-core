package app

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"cosmossdk.io/core/store"
	"cosmossdk.io/log"
	storetypes "cosmossdk.io/store/types"
	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/stretchr/testify/require"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
	sealkeeper "github.com/aethelred/aethelred/x/seal/keeper"
	verifykeeper "github.com/aethelred/aethelred/x/verify/keeper"
)

type mockStakingKeeper struct{}

func (mockStakingKeeper) GetAllValidators(_ context.Context) ([]stakingtypes.Validator, error) {
	return nil, nil
}
func (mockStakingKeeper) GetValidator(_ context.Context, _ sdk.ValAddress) (stakingtypes.Validator, error) {
	return stakingtypes.Validator{}, nil
}

type mockBankKeeper struct{}

func (mockBankKeeper) SendCoinsFromModuleToAccount(_ context.Context, _ string, _ sdk.AccAddress, _ sdk.Coins) error {
	return nil
}
func (mockBankKeeper) SendCoinsFromAccountToModule(_ context.Context, _ sdk.AccAddress, _ string, _ sdk.Coins) error {
	return nil
}
func (mockBankKeeper) SendCoinsFromModuleToModule(_ context.Context, _ string, _ string, _ sdk.Coins) error {
	return nil
}
func (mockBankKeeper) BurnCoins(_ context.Context, _ string, _ sdk.Coins) error { return nil }
func (mockBankKeeper) SpendableCoins(_ context.Context, _ sdk.AccAddress) sdk.Coins {
	return sdk.NewCoins()
}

func newTestApp(t *testing.T) *AethelredApp {
	t.Helper()

	logger := log.NewNopLogger()
	db := dbm.NewMemDB()
	txDecoder := func(_ []byte) (sdk.Tx, error) { return nil, nil }

	bapp := baseapp.NewBaseApp(Name, logger, db, txDecoder)
	storeKey := storetypes.NewKVStoreKey(pouwtypes.StoreKey)

	app := &AethelredApp{
		BaseApp:            bapp,
		voteExtensionCache: NewVoteExtensionCache(4),
	}

	app.MountKVStores(map[string]*storetypes.KVStoreKey{
		pouwtypes.StoreKey: storeKey,
	})
	require.NoError(t, app.LoadLatestVersion())

	reg := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(reg)
	var storeService store.KVStoreService = runtime.NewKVStoreService(storeKey)

	app.PouwKeeper = pouwkeeper.NewKeeper(
		cdc,
		storeService,
		mockStakingKeeper{},
		mockBankKeeper{},
		sealkeeper.Keeper{},
		verifykeeper.Keeper{},
		"authority",
	)
	app.consensusHandler = pouwkeeper.NewConsensusHandler(logger, &app.PouwKeeper, nil)

	return app
}

func TestProcessProposal_FinalityAcceptsValidInjectedTx(t *testing.T) {
	app := newTestApp(t)
	ctx := app.BaseApp.NewContext(true).WithBlockHeight(2).WithBlockTime(time.Now().UTC())

	require.NoError(t, app.PouwKeeper.SetParams(ctx, pouwtypes.DefaultParams()))

	modelHash := make32Bytes()
	inputHash := make32Bytes()
	outputHash := make32Bytes()

	job := pouwtypes.ComputeJob{
		Id:          "job-finality-ok",
		ModelHash:   modelHash,
		InputHash:   inputHash,
		RequestedBy: "requester",
		ProofType:   pouwtypes.ProofTypeTEE,
		Status:      pouwtypes.JobStatusPending,
		BlockHeight: ctx.BlockHeight(),
	}
	require.NoError(t, app.PouwKeeper.Jobs.Set(ctx, job.Id, job))

	addr1 := []byte("validator-addr-1")
	addr2 := []byte("validator-addr-2")

	ext1 := makeVoteExtensionForJob(t, 1, addr1, job, outputHash)
	ext2 := makeVoteExtensionForJob(t, 1, addr2, job, outputHash)

	app.voteExtensionCache.Store(1, addr1, ext1)
	app.voteExtensionCache.Store(1, addr2, ext2)

	commit := abci.CommitInfo{
		Round: 0,
		Votes: []abci.VoteInfo{
			{Validator: abci.Validator{Address: addr1, Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
			{Validator: abci.Validator{Address: addr2, Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
		},
	}

	extendedVotes, _ := app.voteExtensionCache.BuildExtendedVotes(1, commit.Votes)
	results := app.consensusHandler.AggregateVoteExtensions(ctx, extendedVotes)
	sealTxs := app.consensusHandler.CreateSealTransactions(ctx, results)
	require.Len(t, sealTxs, 1)

	handler := app.ProcessProposalHandler()
	resp, err := handler(ctx, &abci.RequestProcessProposal{
		Height:             2,
		Txs:                sealTxs,
		ProposedLastCommit: commit,
	})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_ACCEPT, resp.Status)
}

func TestProcessProposal_FinalityRejectsMissingInjectedTx(t *testing.T) {
	app := newTestApp(t)
	ctx := app.BaseApp.NewContext(true).WithBlockHeight(2).WithBlockTime(time.Now().UTC())

	require.NoError(t, app.PouwKeeper.SetParams(ctx, pouwtypes.DefaultParams()))

	modelHash := make32Bytes()
	inputHash := make32Bytes()
	outputHash := make32Bytes()

	job := pouwtypes.ComputeJob{
		Id:          "job-finality-missing",
		ModelHash:   modelHash,
		InputHash:   inputHash,
		RequestedBy: "requester",
		ProofType:   pouwtypes.ProofTypeTEE,
		Status:      pouwtypes.JobStatusPending,
		BlockHeight: ctx.BlockHeight(),
	}
	require.NoError(t, app.PouwKeeper.Jobs.Set(ctx, job.Id, job))

	addr1 := []byte("validator-addr-1")
	addr2 := []byte("validator-addr-2")

	ext1 := makeVoteExtensionForJob(t, 1, addr1, job, outputHash)
	ext2 := makeVoteExtensionForJob(t, 1, addr2, job, outputHash)

	app.voteExtensionCache.Store(1, addr1, ext1)
	app.voteExtensionCache.Store(1, addr2, ext2)

	commit := abci.CommitInfo{
		Round: 0,
		Votes: []abci.VoteInfo{
			{Validator: abci.Validator{Address: addr1, Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
			{Validator: abci.Validator{Address: addr2, Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
		},
	}

	handler := app.ProcessProposalHandler()
	resp, err := handler(ctx, &abci.RequestProcessProposal{
		Height:             2,
		Txs:                nil,
		ProposedLastCommit: commit,
	})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_REJECT, resp.Status)
}

func TestProcessProposal_FinalityRejectsTamperedConsensusPower(t *testing.T) {
	app := newTestApp(t)
	ctx := app.BaseApp.NewContext(true).WithBlockHeight(2).WithBlockTime(time.Now().UTC())

	require.NoError(t, app.PouwKeeper.SetParams(ctx, pouwtypes.DefaultParams()))

	modelHash := make32Bytes()
	inputHash := make32Bytes()
	outputHash := make32Bytes()

	job := pouwtypes.ComputeJob{
		Id:          "job-finality-tampered-power",
		ModelHash:   modelHash,
		InputHash:   inputHash,
		RequestedBy: "requester",
		ProofType:   pouwtypes.ProofTypeTEE,
		Status:      pouwtypes.JobStatusPending,
		BlockHeight: ctx.BlockHeight(),
	}
	require.NoError(t, app.PouwKeeper.Jobs.Set(ctx, job.Id, job))

	addr1 := []byte("validator-addr-1")
	addr2 := []byte("validator-addr-2")

	ext1 := makeVoteExtensionForJob(t, 1, addr1, job, outputHash)
	ext2 := makeVoteExtensionForJob(t, 1, addr2, job, outputHash)

	app.voteExtensionCache.Store(1, addr1, ext1)
	app.voteExtensionCache.Store(1, addr2, ext2)

	commit := abci.CommitInfo{
		Round: 0,
		Votes: []abci.VoteInfo{
			{Validator: abci.Validator{Address: addr1, Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
			{Validator: abci.Validator{Address: addr2, Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
		},
	}

	extendedVotes, _ := app.voteExtensionCache.BuildExtendedVotes(1, commit.Votes)
	results := app.consensusHandler.AggregateVoteExtensions(ctx, extendedVotes)
	sealTxs := app.consensusHandler.CreateSealTransactions(ctx, results)
	require.Len(t, sealTxs, 1)

	// Tamper tx consensus-power fields so tx-level validation still passes
	// while app-level recomputation should reject it.
	var txMap map[string]interface{}
	require.NoError(t, json.Unmarshal(sealTxs[0], &txMap))
	txMap["total_power"] = float64(1)
	txMap["agreement_power"] = float64(1)
	txMap["total_votes"] = float64(1)
	txMap["validator_count"] = float64(1)
	tampered, err := json.Marshal(txMap)
	require.NoError(t, err)

	handler := app.ProcessProposalHandler()
	resp, err := handler(ctx, &abci.RequestProcessProposal{
		Height:             2,
		Txs:                [][]byte{tampered},
		ProposedLastCommit: commit,
	})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_REJECT, resp.Status)
}

func TestProcessProposal_FinalityAcceptsNoInjectedTxWithEmptyCachedExtensions(t *testing.T) {
	app := newTestApp(t)
	ctx := app.BaseApp.NewContext(true).WithBlockHeight(2).WithBlockTime(time.Now().UTC())

	require.NoError(t, app.PouwKeeper.SetParams(ctx, pouwtypes.DefaultParams()))

	addr1 := []byte("validator-addr-1")
	addr2 := []byte("validator-addr-2")
	app.voteExtensionCache.Store(1, addr1, []byte{})
	app.voteExtensionCache.Store(1, addr2, []byte{})

	commit := abci.CommitInfo{
		Round: 0,
		Votes: []abci.VoteInfo{
			{Validator: abci.Validator{Address: addr1, Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
			{Validator: abci.Validator{Address: addr2, Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
		},
	}

	handler := app.ProcessProposalHandler()
	resp, err := handler(ctx, &abci.RequestProcessProposal{
		Height:             2,
		Txs:                nil,
		ProposedLastCommit: commit,
	})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_ACCEPT, resp.Status)
}

func TestProcessProposal_FinalityRejectsInjectedTxWhenCacheMissing(t *testing.T) {
	app := newTestApp(t)
	ctx := app.BaseApp.NewContext(true).WithBlockHeight(2).WithBlockTime(time.Now().UTC())

	require.NoError(t, app.PouwKeeper.SetParams(ctx, pouwtypes.DefaultParams()))

	modelHash := make32Bytes()
	inputHash := make32Bytes()
	outputHash := make32Bytes()

	job := pouwtypes.ComputeJob{
		Id:          "job-cache-miss",
		ModelHash:   modelHash,
		InputHash:   inputHash,
		RequestedBy: "requester",
		ProofType:   pouwtypes.ProofTypeTEE,
		Status:      pouwtypes.JobStatusPending,
		BlockHeight: ctx.BlockHeight(),
	}
	require.NoError(t, app.PouwKeeper.Jobs.Set(ctx, job.Id, job))

	results := map[string]*pouwkeeper.AggregatedResult{
		job.Id: {
			JobID:          job.Id,
			ModelHash:      modelHash,
			InputHash:      inputHash,
			OutputHash:     outputHash,
			TotalVotes:     2,
			TotalPower:     2,
			AgreementCount: 2,
			AgreementPower: 2,
			HasConsensus:   true,
		},
	}
	sealTxs := app.consensusHandler.CreateSealTransactions(ctx, results)
	require.Len(t, sealTxs, 1)

	addr1 := []byte("validator-addr-1")
	addr2 := []byte("validator-addr-2")
	commit := abci.CommitInfo{
		Round: 0,
		Votes: []abci.VoteInfo{
			{Validator: abci.Validator{Address: addr1, Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
			{Validator: abci.Validator{Address: addr2, Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
		},
	}

	handler := app.ProcessProposalHandler()
	resp, err := handler(ctx, &abci.RequestProcessProposal{
		Height:             2,
		Txs:                sealTxs,
		ProposedLastCommit: commit,
	})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_REJECT, resp.Status)
}

func TestProcessProposal_RejectsDuplicateInjectedConsensusTxForJob(t *testing.T) {
	app := newTestApp(t)
	ctx := app.BaseApp.NewContext(true).WithBlockHeight(2).WithBlockTime(time.Now().UTC())

	params := pouwtypes.DefaultParams()
	params.AllowSimulated = true // disable production finality path for this wiring test
	require.NoError(t, app.PouwKeeper.SetParams(ctx, params))

	modelHash := make32Bytes()
	inputHash := make32Bytes()
	outputHash := make32Bytes()

	job := pouwtypes.ComputeJob{
		Id:          "job-duplicate-injected",
		ModelHash:   modelHash,
		InputHash:   inputHash,
		RequestedBy: "requester",
		ProofType:   pouwtypes.ProofTypeTEE,
		Status:      pouwtypes.JobStatusPending,
		BlockHeight: ctx.BlockHeight(),
	}
	require.NoError(t, app.PouwKeeper.Jobs.Set(ctx, job.Id, job))

	commit := abci.CommitInfo{
		Round: 0,
		Votes: []abci.VoteInfo{
			{Validator: abci.Validator{Address: []byte("validator-addr-1"), Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
			{Validator: abci.Validator{Address: []byte("validator-addr-2"), Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
		},
	}

	tx1 := mustMarshalInjected(t, job.Id, outputHash, 2, 2, 2, 2)
	tx2 := mustMarshalInjected(t, job.Id, outputHash, 2, 2, 2, 2)

	handler := app.ProcessProposalHandler()
	resp, err := handler(ctx, &abci.RequestProcessProposal{
		Height:             2,
		Txs:                [][]byte{tx1, tx2},
		ProposedLastCommit: commit,
	})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_REJECT, resp.Status)
}

func makeVoteExtensionForJob(t *testing.T, height int64, validatorAddr []byte, job pouwtypes.ComputeJob, output []byte) []byte {
	t.Helper()

	ve := NewVoteExtension(height, validatorAddr)
	ve.Timestamp = time.Unix(1_700_000_000+height, 0).UTC()
	ve.AddVerification(ComputeVerification{
		JobID:           job.Id,
		ModelHash:       job.ModelHash,
		InputHash:       job.InputHash,
		OutputHash:      output,
		AttestationType: AttestationTypeTEE,
		ExecutionTimeMs: 1,
		Success:         true,
		Nonce:           make([]byte, 32),
	})

	data, err := ve.Marshal()
	require.NoError(t, err)
	return data
}
