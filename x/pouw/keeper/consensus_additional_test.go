package keeper

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"cosmossdk.io/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/types"
)

type noopJobVerifier struct{}

func (noopJobVerifier) VerifyJob(_ sdk.Context, _ *types.ComputeJob, _ *types.RegisteredModel, _ string) (types.VerificationResult, error) {
	return types.VerificationResult{Success: true}, nil
}

func newConsensusSDKContext(height int64, blockTime time.Time) sdk.Context {
	return sdk.NewContext(nil, tmproto.Header{
		Height:  height,
		Time:    blockTime.UTC(),
		ChainID: "aethelred-test-1",
	}, false, log.NewNopLogger())
}

func TestConsensusHandlerHelpersAndPrepareVoteExtension(t *testing.T) {
	scheduler := NewJobScheduler(log.NewNopLogger(), nil, DefaultSchedulerConfig())
	ch := NewConsensusHandler(log.NewNopLogger(), nil, scheduler)
	require.NotNil(t, ch)
	require.Equal(t, scheduler, ch.Scheduler())
	require.NotNil(t, ch.GetEvidenceCollector())

	ctx := newConsensusSDKContext(100, time.Unix(1_700_000_000, 0))
	require.Equal(t, 67, ch.getConsensusThreshold(ctx))

	ch.SetConsensusThresholdForTesting(75)
	require.Equal(t, 75, ch.getConsensusThreshold(ctx))

	ch.SetVerifier(noopJobVerifier{})
	require.NotNil(t, ch.verifier)

	res, err := ch.PrepareVoteExtension(ctx, "validator-1")
	require.NoError(t, err)
	require.Nil(t, res)
}

func TestConsensusSimulationVerificationHelpers(t *testing.T) {
	ch := NewConsensusHandler(log.NewNopLogger(), nil, nil)
	ctx := newConsensusSDKContext(101, time.Unix(1_700_000_010, 0))

	job := &types.ComputeJob{
		Id:        "job-1",
		ModelHash: bytes.Repeat([]byte{0x01}, 32),
		InputHash: bytes.Repeat([]byte{0x02}, 32),
		ProofType: types.ProofTypeTEE,
	}
	model := &types.RegisteredModel{
		TeeMeasurement: bytes.Repeat([]byte{0x03}, 32),
		CircuitHash:    bytes.Repeat([]byte{0x04}, 32),
	}

	outputA := computeDeterministicOutput(job.ModelHash, job.InputHash)
	outputB := computeDeterministicOutput(job.ModelHash, job.InputHash)
	require.Equal(t, outputA, outputB)
	require.Len(t, outputA, 32)

	quoteA := generateAttestationQuote(outputA, model.TeeMeasurement)
	quoteB := generateAttestationQuote(outputA, model.TeeMeasurement)
	require.Equal(t, quoteA, quoteB)
	require.Len(t, quoteA, 32)

	proofA := generateZKProof(job.ModelHash, job.InputHash, outputA, model.CircuitHash)
	proofNoCircuit := generateZKProof(job.ModelHash, job.InputHash, outputA, nil)
	require.NotEqual(t, proofA, proofNoCircuit)
	require.Len(t, proofA, 32)
	require.Len(t, sha256Hash([]byte("abc")), 32)

	teeResult := &types.VerificationResult{}
	ch.executeTEEVerification(ctx, job, model, teeResult)
	require.True(t, teeResult.Success)
	require.Equal(t, "aws-nitro", teeResult.TeePlatform)
	require.Len(t, teeResult.OutputHash, 32)
	require.Len(t, teeResult.AttestationData, 32)

	zkResult := &types.VerificationResult{}
	ch.executeZKMLVerification(ctx, job, model, zkResult)
	require.True(t, zkResult.Success)
	require.Len(t, zkResult.OutputHash, 32)
	require.Len(t, zkResult.AttestationData, 32)

	hybridResult := &types.VerificationResult{}
	ch.executeHybridVerification(ctx, job, model, hybridResult)
	require.True(t, hybridResult.Success)
	require.Contains(t, string(hybridResult.AttestationData), "|ZKML|")
}

func TestRequiredThresholdCount_UsesCeilingDivisionAndCapsAtTotal(t *testing.T) {
	require.Equal(t, int64(3), requiredThresholdCount(int64(3), 67), "ceil(2.01)=3")
	require.Equal(t, int64(67), requiredThresholdCount(int64(100), 67), "exact percentages should not over-require")
	require.Equal(t, int64(5), requiredThresholdCount(int64(5), 100), "100%% threshold must be reachable")
	require.Equal(t, int64(0), requiredThresholdCount(int64(0), 67), "zero total should require zero")
	require.Equal(t, int64(0), requiredThresholdCount(int64(10), 0), "zero threshold should require zero")
}

func TestConsensusSealTransactionBranches(t *testing.T) {
	ctx := newConsensusSDKContext(222, time.Unix(1_700_000_123, 0))
	ch := NewConsensusHandler(log.NewNopLogger(), nil, nil)

	resultWithConsensus := &AggregatedResult{
		JobID:            "job-seal-1",
		ModelHash:        bytes.Repeat([]byte{0x11}, 32),
		InputHash:        bytes.Repeat([]byte{0x12}, 32),
		OutputHash:       bytes.Repeat([]byte{0x13}, 32),
		AgreementCount:   3,
		AgreementPower:   70,
		TotalVotes:       4,
		TotalPower:       100,
		HasConsensus:     true,
		ValidatorResults: []ValidatorResult{{ValidatorAddress: "val1"}},
	}
	resultWithoutConsensus := &AggregatedResult{
		JobID:        "job-seal-2",
		HasConsensus: false,
	}

	txs := ch.CreateSealTransactions(ctx, map[string]*AggregatedResult{
		resultWithConsensus.JobID:    resultWithConsensus,
		resultWithoutConsensus.JobID: resultWithoutConsensus,
	})
	require.Len(t, txs, 1)

	var parsed SealCreationTx
	require.NoError(t, json.Unmarshal(txs[0], &parsed))
	require.Equal(t, resultWithConsensus.JobID, parsed.JobID)
	require.EqualValues(t, ctx.BlockHeight(), parsed.BlockHeight)
	require.Equal(t, ctx.BlockTime().UTC(), parsed.Timestamp)

	require.ErrorContains(t, ch.ValidateSealTransaction(ctx, []byte("{bad-json")), "unmarshal")

	badType, err := json.Marshal(SealCreationTx{Type: "wrong", JobID: "job-x", OutputHash: bytes.Repeat([]byte{0x01}, 32)})
	require.NoError(t, err)
	require.ErrorContains(t, ch.ValidateSealTransaction(ctx, badType), "invalid seal transaction type")

	missingJobID, err := json.Marshal(SealCreationTx{Type: "create_seal_from_consensus", OutputHash: bytes.Repeat([]byte{0x01}, 32)})
	require.NoError(t, err)
	require.ErrorContains(t, ch.ValidateSealTransaction(ctx, missingJobID), "missing job ID")

	badOutputHash, err := json.Marshal(SealCreationTx{Type: "create_seal_from_consensus", JobID: "job-x", OutputHash: []byte{0x01}})
	require.NoError(t, err)
	require.ErrorContains(t, ch.ValidateSealTransaction(ctx, badOutputHash), "invalid output hash length")

	require.ErrorContains(t, ch.ProcessSealTransaction(sdk.WrapSDKContext(ctx), []byte("{bad-json")), "unmarshal")

	require.True(t, IsSealTransaction(txs[0]))
	require.False(t, IsSealTransaction([]byte("{bad-json")))
	require.False(t, IsSealTransaction([]byte(`{"type":"not-seal"}`)))

	require.True(t, isNullOrEmpty(nil))
	require.True(t, isNullOrEmpty(json.RawMessage("null")))
	require.True(t, isNullOrEmpty(json.RawMessage(`""`)))
	require.False(t, isNullOrEmpty(json.RawMessage(`"value"`)))
}
