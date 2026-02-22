package keeper_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// =============================================================================
// WEEK 29-30: Remediation Sprint 1 — Critical Findings Tests
//
// These tests verify:
//   1. Vote extension signature verification (AS-17) — 10 tests
//   2. Liveness tracker (AS-16) — 10 tests
//   3. Remediation tracker — 6 tests
//   4. Hardened ValidateParams — 5 tests
//   5. Integration verification — 4 tests
//
// Total: 35 tests
// =============================================================================

// =============================================================================
// Section 1: Vote Extension Signature Verification (AS-17)
// =============================================================================

func TestVoteExtensionVerifier_NewVerifier(t *testing.T) {
	v := keeper.NewVoteExtensionVerifier()
	require.NotNil(t, v)
	require.Equal(t, 0, v.RegisteredCount())
}

func TestVoteExtensionVerifier_RegisterKey(t *testing.T) {
	v := keeper.NewVoteExtensionVerifier()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	err = v.RegisterKey("validator-1", pub)
	require.NoError(t, err)
	require.Equal(t, 1, v.RegisteredCount())
	require.True(t, v.HasKey("validator-1"))
	require.False(t, v.HasKey("validator-2"))
}

func TestVoteExtensionVerifier_RegisterKey_InvalidSize(t *testing.T) {
	v := keeper.NewVoteExtensionVerifier()

	err := v.RegisterKey("validator-1", []byte("short"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid public key size")
}

func TestVoteExtensionVerifier_RegisterKey_EmptyAddr(t *testing.T) {
	v := keeper.NewVoteExtensionVerifier()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	err = v.RegisterKey("", pub)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty")
}

func TestVoteExtensionVerifier_UnregisterKey(t *testing.T) {
	v := keeper.NewVoteExtensionVerifier()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_ = v.RegisterKey("validator-1", pub)
	require.True(t, v.HasKey("validator-1"))

	v.UnregisterKey("validator-1")
	require.False(t, v.HasKey("validator-1"))
	require.Equal(t, 0, v.RegisteredCount())
}

func TestSignedVoteExtension_SignAndVerify(t *testing.T) {
	v := keeper.NewVoteExtensionVerifier()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	err = v.RegisterKey("validator-1", pub)
	require.NoError(t, err)

	// Create a mock signer
	signer := &mockSigner{privKey: priv, pubKey: pub}

	// Create signed extension
	payload := []byte(`{"job_id":"job-1","output_hash":"abc123"}`)
	signedExt, err := keeper.CreateSignedExtension(payload, "validator-1", signer)
	require.NoError(t, err)
	require.NotNil(t, signedExt)
	require.NotEmpty(t, signedExt.Signature)
	require.NotEmpty(t, signedExt.PayloadHash)

	// Verify
	err = v.VerifySignature(signedExt)
	require.NoError(t, err)
}

func TestSignedVoteExtension_VerifyFailsWithWrongKey(t *testing.T) {
	v := keeper.NewVoteExtensionVerifier()

	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	// Register pub2 but sign with priv1
	_ = v.RegisterKey("validator-1", pub2)
	signer := &mockSigner{privKey: priv1, pubKey: pub1}

	payload := []byte(`{"job_id":"job-1"}`)
	signedExt, err := keeper.CreateSignedExtension(payload, "validator-1", signer)
	require.NoError(t, err)

	err = v.VerifySignature(signedExt)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid signature")
}

func TestSignedVoteExtension_VerifyFailsWithTamperedPayload(t *testing.T) {
	v := keeper.NewVoteExtensionVerifier()

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_ = v.RegisterKey("validator-1", pub)
	signer := &mockSigner{privKey: priv, pubKey: pub}

	payload := []byte(`{"job_id":"job-1"}`)
	signedExt, err := keeper.CreateSignedExtension(payload, "validator-1", signer)
	require.NoError(t, err)

	// Tamper with payload
	signedExt.ExtensionPayload = []byte(`{"job_id":"job-EVIL"}`)

	err = v.VerifySignature(signedExt)
	require.Error(t, err)
	require.Contains(t, err.Error(), "tampered")
}

func TestSignedVoteExtension_VerifyFailsNoKey(t *testing.T) {
	v := keeper.NewVoteExtensionVerifier()

	payload := []byte(`{"job_id":"job-1"}`)
	ext := &keeper.SignedVoteExtension{
		ExtensionPayload: payload,
		ValidatorAddr:    "validator-unknown",
		Signature:        []byte("fake"),
		PayloadHash:      keeper.ComputePayloadHash(payload),
	}

	err := v.VerifySignature(ext)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no public key")
}

func TestSignedVoteExtension_VerifyNilExtension(t *testing.T) {
	v := keeper.NewVoteExtensionVerifier()
	err := v.VerifySignature(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil")
}

// mockSigner implements VoteExtensionSigner for testing
type mockSigner struct {
	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey
}

func (m *mockSigner) Sign(payload []byte) ([]byte, error) {
	return ed25519.Sign(m.privKey, payload), nil
}

func (m *mockSigner) PublicKey() []byte {
	return m.pubKey
}

// =============================================================================
// Section 2: Liveness Tracker (AS-16)
// =============================================================================

func TestLivenessTracker_NewTracker(t *testing.T) {
	lt := keeper.NewLivenessTracker(100, 500)
	require.NotNil(t, lt)
	require.Equal(t, 0, lt.TrackedCount())
}

func TestLivenessTracker_RecordActivity(t *testing.T) {
	lt := keeper.NewLivenessTracker(5, 50)

	lt.RecordActivity("val-1", 100)
	require.True(t, lt.IsResponsive("val-1"))
	require.Equal(t, 1, lt.TrackedCount())

	record, ok := lt.GetRecord("val-1")
	require.True(t, ok)
	require.Equal(t, int64(100), record.LastActiveBlock)
	require.Equal(t, int64(0), record.ConsecutiveMisses)
}

func TestLivenessTracker_RecordMiss(t *testing.T) {
	lt := keeper.NewLivenessTracker(5, 50)

	lt.RecordActivity("val-1", 100)

	// Miss 3 blocks — still responsive (threshold is 5)
	for i := 0; i < 3; i++ {
		lt.RecordMiss("val-1", int64(101+i))
	}

	require.True(t, lt.IsResponsive("val-1"))

	record, _ := lt.GetRecord("val-1")
	require.Equal(t, int64(3), record.ConsecutiveMisses)
	require.Equal(t, int64(3), record.TotalMisses)
}

func TestLivenessTracker_DowntimeThreshold(t *testing.T) {
	lt := keeper.NewLivenessTracker(5, 50)

	lt.RecordActivity("val-1", 100)

	// Miss 5 blocks — triggers downtime
	for i := 0; i < 5; i++ {
		lt.RecordMiss("val-1", int64(101+i))
	}

	require.False(t, lt.IsResponsive("val-1"))

	// Activity resets
	lt.RecordActivity("val-1", 200)
	require.True(t, lt.IsResponsive("val-1"))
}

func TestLivenessTracker_UnknownValidator(t *testing.T) {
	lt := keeper.NewLivenessTracker(5, 50)
	require.False(t, lt.IsResponsive("unknown"))

	_, ok := lt.GetRecord("unknown")
	require.False(t, ok)
}

func TestLivenessTracker_GetResponsiveValidators(t *testing.T) {
	lt := keeper.NewLivenessTracker(3, 50)

	lt.RecordActivity("val-1", 100)
	lt.RecordActivity("val-2", 100)
	lt.RecordActivity("val-3", 100)

	// Take val-2 offline
	for i := 0; i < 3; i++ {
		lt.RecordMiss("val-2", int64(101+i))
	}

	responsive := lt.GetResponsiveValidators()
	require.Len(t, responsive, 2)
	require.NotContains(t, responsive, "val-2")

	unresponsive := lt.GetUnresponsiveValidators()
	require.Len(t, unresponsive, 1)
	require.Contains(t, unresponsive, "val-2")
}

func TestLivenessTracker_NeedsEscalation(t *testing.T) {
	lt := keeper.NewLivenessTracker(5, 10)

	lt.RecordActivity("val-1", 100)

	// Accumulate 10 total misses (escalation threshold)
	for i := 0; i < 10; i++ {
		lt.RecordMiss("val-1", int64(101+i))
	}

	escalations := lt.NeedsEscalation()
	require.Len(t, escalations, 1)
	require.Equal(t, "val-1", escalations[0].ValidatorAddr)
	require.Equal(t, int64(10), escalations[0].TotalMisses)
}

func TestLivenessTracker_Reset(t *testing.T) {
	lt := keeper.NewLivenessTracker(3, 50)

	lt.RecordActivity("val-1", 100)
	for i := 0; i < 5; i++ {
		lt.RecordMiss("val-1", int64(101+i))
	}
	require.False(t, lt.IsResponsive("val-1"))

	lt.Reset("val-1")
	require.True(t, lt.IsResponsive("val-1"))
}

func TestLivenessTracker_DefaultThresholds(t *testing.T) {
	// Zero thresholds should use defaults
	lt := keeper.NewLivenessTracker(0, 0)
	require.NotNil(t, lt)

	// With default threshold of 100, 99 misses should be fine
	lt.RecordActivity("val-1", 1)
	for i := 0; i < 99; i++ {
		lt.RecordMiss("val-1", int64(2+i))
	}
	require.True(t, lt.IsResponsive("val-1"))

	// 100th miss triggers downtime
	lt.RecordMiss("val-1", 101)
	require.False(t, lt.IsResponsive("val-1"))
}

func TestFilterResponsiveValidators(t *testing.T) {
	lt := keeper.NewLivenessTracker(3, 50)

	lt.RecordActivity("val-1", 100)
	lt.RecordActivity("val-2", 100)
	lt.RecordActivity("val-3", 100)

	// Take val-2 offline
	for i := 0; i < 3; i++ {
		lt.RecordMiss("val-2", int64(101+i))
	}

	all := []string{"val-1", "val-2", "val-3"}
	filtered := keeper.FilterResponsiveValidators(all, lt)
	require.Len(t, filtered, 2)
	require.Contains(t, filtered, "val-1")
	require.Contains(t, filtered, "val-3")
	require.NotContains(t, filtered, "val-2")

	// Nil tracker returns all
	noFilter := keeper.FilterResponsiveValidators(all, nil)
	require.Len(t, noFilter, 3)
}

// =============================================================================
// Section 3: Remediation Tracker
// =============================================================================

func TestRemediationTracker_New(t *testing.T) {
	rt := keeper.NewRemediationTracker()
	require.NotNil(t, rt)
	require.Empty(t, rt.All())
}

func TestRemediationTracker_Add(t *testing.T) {
	rt := keeper.NewRemediationTracker()
	rt.Add(keeper.RemediationEntry{
		FindingID:     "TEST-01",
		AttackSurface: "AS-01",
		Status:        keeper.RemediationFixed,
		Description:   "Test fix",
	})

	require.Len(t, rt.All(), 1)
}

func TestRemediationTracker_GetByStatus(t *testing.T) {
	rt := keeper.NewRemediationTracker()
	rt.Add(keeper.RemediationEntry{FindingID: "F-1", Status: keeper.RemediationOpen})
	rt.Add(keeper.RemediationEntry{FindingID: "F-2", Status: keeper.RemediationFixed})
	rt.Add(keeper.RemediationEntry{FindingID: "F-3", Status: keeper.RemediationVerified})
	rt.Add(keeper.RemediationEntry{FindingID: "F-4", Status: keeper.RemediationFixed})

	fixed := rt.GetByStatus(keeper.RemediationFixed)
	require.Len(t, fixed, 2)

	open := rt.GetByStatus(keeper.RemediationOpen)
	require.Len(t, open, 1)

	verified := rt.GetByStatus(keeper.RemediationVerified)
	require.Len(t, verified, 1)
}

func TestRemediationTracker_GetByAttackSurface(t *testing.T) {
	rt := keeper.NewRemediationTracker()
	rt.Add(keeper.RemediationEntry{FindingID: "F-1", AttackSurface: "AS-17", Status: keeper.RemediationFixed})
	rt.Add(keeper.RemediationEntry{FindingID: "F-2", AttackSurface: "AS-16", Status: keeper.RemediationFixed})
	rt.Add(keeper.RemediationEntry{FindingID: "F-3", AttackSurface: "AS-17", Status: keeper.RemediationVerified})

	as17 := rt.GetByAttackSurface("AS-17")
	require.Len(t, as17, 2)
}

func TestRemediationTracker_IsComplete(t *testing.T) {
	rt := keeper.NewRemediationTracker()
	rt.Add(keeper.RemediationEntry{FindingID: "F-1", Status: keeper.RemediationVerified})
	rt.Add(keeper.RemediationEntry{FindingID: "F-2", Status: keeper.RemediationWontFix})
	require.True(t, rt.IsComplete())

	rt.Add(keeper.RemediationEntry{FindingID: "F-3", Status: keeper.RemediationOpen})
	require.False(t, rt.IsComplete())
}

func TestRemediationTracker_Summary(t *testing.T) {
	rt := keeper.NewRemediationTracker()
	rt.Add(keeper.RemediationEntry{FindingID: "F-1", Status: keeper.RemediationOpen})
	rt.Add(keeper.RemediationEntry{FindingID: "F-2", Status: keeper.RemediationFixed})
	rt.Add(keeper.RemediationEntry{FindingID: "F-3", Status: keeper.RemediationVerified})

	summary := rt.Summary()
	require.Contains(t, summary, "3 total")
	require.Contains(t, summary, "1 open")
	require.Contains(t, summary, "1 fixed")
	require.Contains(t, summary, "1 verified")
}

// =============================================================================
// Section 4: Hardened ValidateParams
// =============================================================================

func TestHardenedValidateParams_Threshold50Rejected(t *testing.T) {
	p := types.DefaultParams()
	p.ConsensusThreshold = 50
	err := keeper.ValidateParams(p)
	require.Error(t, err, "threshold 50 should be rejected (below BFT minimum)")
	require.Contains(t, err.Error(), "67", "error should mention BFT-safe minimum of 67")
}

func TestHardenedValidateParams_Threshold51Rejected(t *testing.T) {
	// SECURITY FIX: 51% is no longer accepted - BFT requires >= 67%
	p := types.DefaultParams()
	p.ConsensusThreshold = 51
	err := keeper.ValidateParams(p)
	require.Error(t, err, "threshold 51 should be rejected (below BFT minimum of 67)")
	require.Contains(t, err.Error(), "67")
}

func TestHardenedValidateParams_Threshold66Rejected(t *testing.T) {
	// 66% is still below the BFT threshold
	p := types.DefaultParams()
	p.ConsensusThreshold = 66
	err := keeper.ValidateParams(p)
	require.Error(t, err, "threshold 66 should be rejected (below BFT minimum)")
}

func TestHardenedValidateParams_Threshold67Accepted(t *testing.T) {
	p := types.DefaultParams()
	p.ConsensusThreshold = 67
	require.NoError(t, keeper.ValidateParams(p), "BFT-safe value must pass")
}

func TestHardenedValidateParams_Threshold100Accepted(t *testing.T) {
	p := types.DefaultParams()
	p.ConsensusThreshold = 100
	require.NoError(t, keeper.ValidateParams(p))
}

func TestHardenedValidateParams_Threshold101Rejected(t *testing.T) {
	p := types.DefaultParams()
	p.ConsensusThreshold = 101
	require.Error(t, keeper.ValidateParams(p))
}

// =============================================================================
// Section 5: Integration Verification
// =============================================================================

func TestWeek29_30Remediations_NonEmpty(t *testing.T) {
	remediations := keeper.Week29_30Remediations()
	require.NotEmpty(t, remediations)
	require.GreaterOrEqual(t, len(remediations), 3,
		"must have at least 3 remediations for Week 29-30")
}

func TestWeek29_30Remediations_AllHaveRequiredFields(t *testing.T) {
	for _, r := range keeper.Week29_30Remediations() {
		require.NotEmpty(t, r.FindingID, "remediation must have finding ID")
		require.NotEmpty(t, r.AttackSurface, "remediation %s must have attack surface", r.FindingID)
		require.NotEmpty(t, r.Description, "remediation %s must have description", r.FindingID)
		require.NotEmpty(t, r.ImplementedIn, "remediation %s must reference implementation file", r.FindingID)
		require.NotEmpty(t, r.TestCoverage, "remediation %s must reference test coverage", r.FindingID)
	}
}

func TestVerifyRemediations_Integration(t *testing.T) {
	k, ctx := newTestKeeper(t)

	tracker := keeper.VerifyRemediations(ctx, k)
	require.NotNil(t, tracker)

	all := tracker.All()
	require.NotEmpty(t, all)

	t.Log(tracker.Summary())

	// PARAM-03 should be verified (ValidateParams now rejects 50)
	for _, e := range all {
		if e.FindingID == "PARAM-03" {
			require.Equal(t, keeper.RemediationVerified, e.Status,
				"PARAM-03 should be verified after hardening")
		}
	}
}

func TestVerifyRemediations_GateVerified(t *testing.T) {
	k, ctx := newTestKeeper(t)

	tracker := keeper.VerifyRemediations(ctx, k)

	for _, e := range tracker.All() {
		if e.FindingID == "GATE-01-VERIFY" {
			require.Equal(t, keeper.RemediationVerified, e.Status,
				"GATE-01-VERIFY should be verified (AllowSimulated=false by default)")
		}
	}
}
