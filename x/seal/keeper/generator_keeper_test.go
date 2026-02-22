package keeper

import (
	"bytes"
	"testing"
	"time"

	"cosmossdk.io/log"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/seal/types"
)

func validConsensusResult(requester string, ts time.Time) *ConsensusResult {
	return &ConsensusResult{
		JobID:                   "job-generator-1",
		ModelHash:               bytes.Repeat([]byte{0x11}, 32),
		InputHash:               bytes.Repeat([]byte{0x22}, 32),
		OutputHash:              bytes.Repeat([]byte{0x33}, 32),
		Height:                  100,
		Round:                   1,
		TotalValidators:         5,
		ParticipatingValidators: 5,
		AgreementCount:          4,
		TEEResults: []TEEResult{
			{
				ValidatorAddress:    "validator-1",
				ValidatorPubKey:     []byte("pubkey"),
				Platform:            "aws-nitro",
				EnclaveID:           "enclave-1",
				Measurement:         bytes.Repeat([]byte{0x44}, 32),
				AttestationDocument: []byte("attestation"),
				OutputHash:          bytes.Repeat([]byte{0x33}, 32),
				ExecutionTimeMs:     42,
				Timestamp:           ts,
				Signature:           []byte("sig"),
				Nonce:               []byte("nonce"),
			},
		},
		ZKMLResult: &ZKMLResult{
			ProofSystem:        "ezkl",
			Proof:              []byte("proof"),
			PublicInputs:       []byte("public-inputs"),
			VerifyingKeyHash:   bytes.Repeat([]byte{0x55}, 32),
			CircuitHash:        bytes.Repeat([]byte{0x66}, 32),
			ProofSizeBytes:     1234,
			GenerationTimeMs:   100,
			VerificationTimeMs: 7,
			Verified:           true,
			GeneratedBy:        "validator-1",
			Timestamp:          ts,
		},
		RequestedBy: requester,
		Purpose:     "fraud_detection",
		BlockHash:   []byte("block-hash"),
		Timestamp:   ts,
	}
}

func TestSealGeneratorGenerateSealSuccess(t *testing.T) {
	k, ctx := createSealKeeperWithStore(t)
	cfg := DefaultGeneratorConfig()
	sg := NewSealGenerator(log.NewNopLogger(), &k, "aethelred-test", cfg)

	requester := sdk.AccAddress(bytes.Repeat([]byte{0x99}, 20)).String()
	res := validConsensusResult(requester, ctx.BlockTime())

	seal, err := sg.GenerateSeal(ctx, res)
	require.NoError(t, err)
	require.Equal(t, "hybrid", seal.VerificationBundle.VerificationType)
	require.Equal(t, requester, seal.RequestedBy)
	require.Equal(t, types.SealStatusActive, seal.Status)
	require.NotNil(t, seal.RegulatoryInfo)
	require.Contains(t, seal.RegulatoryInfo.ComplianceFrameworks, "GDPR")

	stored, err := k.GetSeal(ctx, seal.Id)
	require.NoError(t, err)
	require.Equal(t, seal.Id, stored.Id)
}

func TestSealGeneratorValidationAndBundleBranches(t *testing.T) {
	k, ctx := createSealKeeperWithStore(t)
	cfg := DefaultGeneratorConfig()
	sg := NewSealGenerator(log.NewNopLogger(), &k, "aethelred-test", cfg)
	requester := sdk.AccAddress(bytes.Repeat([]byte{0x88}, 20)).String()
	base := validConsensusResult(requester, ctx.BlockTime())

	t.Run("invalid result branches", func(t *testing.T) {
		cases := []struct {
			name string
			mut  func(*ConsensusResult)
		}{
			{name: "missing job id", mut: func(r *ConsensusResult) { r.JobID = "" }},
			{name: "bad model hash", mut: func(r *ConsensusResult) { r.ModelHash = []byte{0x01} }},
			{name: "bad input hash", mut: func(r *ConsensusResult) { r.InputHash = []byte{0x02} }},
			{name: "bad output hash", mut: func(r *ConsensusResult) { r.OutputHash = []byte{0x03} }},
			{name: "insufficient consensus", mut: func(r *ConsensusResult) { r.AgreementCount = 1 }},
			{name: "missing tee", mut: func(r *ConsensusResult) { r.TEEResults = nil }},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				copyRes := *base
				tc.mut(&copyRes)
				require.Error(t, sg.validateConsensusResult(&copyRes))
			})
		}
	})

	t.Run("require zkml branch", func(t *testing.T) {
		zkCfg := cfg
		zkCfg.RequireZKML = true
		sgZK := NewSealGenerator(log.NewNopLogger(), &k, "aethelred-test", zkCfg)
		copyRes := *base
		copyRes.ZKMLResult = nil
		require.Error(t, sgZK.validateConsensusResult(&copyRes))
	})

	t.Run("build bundle branches", func(t *testing.T) {
		copyRes := *base
		copyRes.ZKMLResult = nil
		bundle, err := sg.buildVerificationBundle(&copyRes)
		require.NoError(t, err)
		require.Equal(t, "tee", bundle.VerificationType)
		require.NotEmpty(t, bundle.BundleHash)
		require.NotNil(t, bundle.ModelVerification)

		// No verification evidence should fail.
		copyRes.TEEResults = nil
		bundle, err = sg.buildVerificationBundle(&copyRes)
		require.Nil(t, bundle)
		require.Error(t, err)
	})

	t.Run("helper branches", func(t *testing.T) {
		info := sg.buildConsensusInfo(base)
		require.Len(t, info.VoteExtensionHashes, len(base.TEEResults))

		hash1 := sg.computeBundleHash(&types.VerificationBundle{
			VerificationType:     "tee",
			AggregatedOutputHash: bytes.Repeat([]byte{0x01}, 32),
			TEEVerifications: []types.TEEVerification{
				{OutputHash: bytes.Repeat([]byte{0x02}, 32), AttestationDocument: []byte("doc")},
			},
		})
		hash2 := sg.computeBundleHash(&types.VerificationBundle{
			VerificationType:     "tee",
			AggregatedOutputHash: bytes.Repeat([]byte{0x01}, 32),
			TEEVerifications: []types.TEEVerification{
				{OutputHash: bytes.Repeat([]byte{0x02}, 32), AttestationDocument: []byte("doc")},
			},
		})
		require.Equal(t, hash1, hash2)

		require.Contains(t, sg.determineComplianceFrameworks("credit_scoring"), "FCRA")
		require.Contains(t, sg.determineComplianceFrameworks("unknown"), "SOC2")
		require.Equal(t, "confidential_phi", sg.classifyData("medical_diagnosis"))
		require.Equal(t, "internal", sg.classifyData("other"))
	})
}

func TestSealGeneratorBatchAndFromJob(t *testing.T) {
	k, ctx := createSealKeeperWithStore(t)
	cfg := DefaultGeneratorConfig()
	sg := NewSealGenerator(log.NewNopLogger(), &k, "aethelred-test", cfg)

	requester := sdk.AccAddress(bytes.Repeat([]byte{0x77}, 20)).String()
	valid := validConsensusResult(requester, ctx.BlockTime())
	invalid := &ConsensusResult{JobID: "bad"}

	seals, err := sg.BatchGenerateSeals(ctx, []*ConsensusResult{valid, invalid})
	require.NoError(t, err)
	require.Len(t, seals, 1)

	// GenerateSealFromJob currently constructs a minimal result and should fail validation.
	_, err = sg.GenerateSealFromJob(ctx, "job-1", bytes.Repeat([]byte{0x03}, 32), []VerificationResult{
		{
			ValidatorAddress: "validator-1",
			OutputHash:       bytes.Repeat([]byte{0x03}, 32),
			AttestationType:  "tee",
			TEEPlatform:      "aws-nitro",
			AttestationData:  []byte("attestation"),
			ExecutionTimeMs:  5,
			Timestamp:        time.Now().UTC(),
			Success:          true,
		},
	})
	require.Error(t, err)
}

func TestSealKeeperAdditionalProductionPaths(t *testing.T) {
	k, ctx := createSealKeeperWithStore(t)

	seal := makeTestSeal(3, "credit_scoring")
	require.NoError(t, k.CreateSeal(ctx, seal))

	foundByJob, err := k.GetSealByJob(ctx, seal.Id)
	require.NoError(t, err)
	require.Equal(t, seal.Id, foundByJob.Id)

	_, err = k.GetSealByJob(ctx, "missing-job")
	require.Error(t, err)

	seal.Status = types.SealStatusRevoked
	require.NoError(t, k.UpdateSeal(ctx, seal))
	updated, err := k.GetSeal(ctx, seal.Id)
	require.NoError(t, err)
	require.Equal(t, types.SealStatusRevoked, updated.Status)

	err = k.UpdateSeal(ctx, &types.DigitalSeal{Id: "unknown"})
	require.Error(t, err)

	streamCount := 0
	require.NoError(t, k.ExportGenesisStream(ctx, func(seal *types.DigitalSeal) error {
		streamCount++
		return nil
	}))
	require.GreaterOrEqual(t, streamCount, 1)

	err = k.InitGenesis(ctx, &types.GenesisState{
		Params: types.DefaultParams(),
		Seals:  []*types.DigitalSeal{nil},
	})
	require.ErrorContains(t, err, "nil seal in genesis")

	withLogger := NewKeeperWithLogger(log.NewNopLogger(), nil, nil, "authority")
	require.Equal(t, "authority", withLogger.GetAuthority())
}

func TestSDKHelperProofExportAndReference(t *testing.T) {
	k, ctx := createSealKeeperWithStore(t)
	seal := makeTestSeal(4, "fraud_detection")
	require.NoError(t, k.CreateSeal(ctx, seal))

	verifier := NewSealVerifier(log.NewNopLogger(), &k, DefaultVerifierConfig())
	exporter := NewSealExporter(log.NewNopLogger(), &k, verifier)
	helper := NewSDKHelper(log.NewNopLogger(), &k, verifier, exporter)

	proof, err := helper.GenerateVerificationProof(ctx, seal.Id)
	require.NoError(t, err)
	require.Equal(t, seal.Id, proof.SealID)
	require.NotEmpty(t, proof.ProofHash)
	require.Equal(t, ctx.ChainID(), proof.ChainID)

	pkg, err := helper.ExportForExternalVerification(ctx, seal.Id)
	require.NoError(t, err)
	require.Equal(t, seal.Id, pkg.SealID)
	require.NotEmpty(t, pkg.PackageHash)
	require.Equal(t, ctx.ChainID(), pkg.ChainID)
	require.NotNil(t, pkg.ZKProof)

	ref, err := helper.CreateSealReference(ctx, seal.Id)
	require.NoError(t, err)
	require.Equal(t, seal.Id, ref.SealID)
	require.NotEmpty(t, ref.ReferenceHash)
	require.Equal(t, ctx.ChainID(), ref.ChainID)
}
