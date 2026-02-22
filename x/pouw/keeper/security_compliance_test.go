package keeper_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// =============================================================================
// SECURITY & COMPLIANCE FRAMEWORK TESTS
//
// These tests verify:
//   1. Verification policy (7 tests)
//   2. Audit checklist (6 tests)
//   3. Compliance jurisdictions (2 tests)
//   4. Security invariant spec (4 tests)
//   5. Audit artifacts (2 tests)
//   6. Compliance summary + report (4 tests)
//   7. Integration (2 tests)
//
// Total: 27 tests
// =============================================================================

// =============================================================================
// Section 1: Verification Policy
// =============================================================================

func TestDefaultVerificationPolicy(t *testing.T) {
	policy := keeper.DefaultVerificationPolicy()
	require.NoError(t, keeper.ValidateVerificationPolicy(policy))
	require.Equal(t, keeper.VerificationModeStrict, policy.Mode)
	require.True(t, policy.FailClosed)
	require.True(t, policy.RequireTEEAttestation)
}

func TestVerificationPolicy_StrictRequiresFailClosed(t *testing.T) {
	policy := keeper.DefaultVerificationPolicy()
	policy.FailClosed = false
	require.Error(t, keeper.ValidateVerificationPolicy(policy))
}

func TestVerificationPolicy_StrictRequiresTEE(t *testing.T) {
	policy := keeper.DefaultVerificationPolicy()
	policy.RequireTEEAttestation = false
	require.Error(t, keeper.ValidateVerificationPolicy(policy))
}

func TestVerificationPolicy_MultiPartyRequiresMinVerifiers(t *testing.T) {
	policy := keeper.DefaultVerificationPolicy()
	policy.RequireMultiPartyVerification = true
	policy.MinVerifiers = 1
	require.Error(t, keeper.ValidateVerificationPolicy(policy))
}

func TestVerificationPolicy_InvalidMode(t *testing.T) {
	policy := keeper.DefaultVerificationPolicy()
	policy.Mode = "unknown"
	require.Error(t, keeper.ValidateVerificationPolicy(policy))
}

func TestEvaluateVerificationPolicy_CleanState(t *testing.T) {
	k, ctx := newTestKeeper(t)

	assessment := keeper.EvaluateVerificationPolicy(ctx, k)
	require.NotNil(t, assessment)
	require.True(t, assessment.Passed,
		"clean state with default params should pass policy")
	require.GreaterOrEqual(t, len(assessment.Criteria), 10,
		"should have at least 10 policy criteria")
}

func TestEvaluateVerificationPolicy_CriticalFailures(t *testing.T) {
	k, ctx := newTestKeeper(t)

	assessment := keeper.EvaluateVerificationPolicy(ctx, k)
	failures := assessment.CriticalFailures()
	require.Empty(t, failures,
		"clean state should have no critical failures")
}

// =============================================================================
// Section 2: Audit Checklist
// =============================================================================

func TestBuildAuditChecklist_CleanState(t *testing.T) {
	k, ctx := newTestKeeper(t)

	checklist := keeper.BuildAuditChecklist(ctx, k)
	require.NotNil(t, checklist)
	require.NotEmpty(t, checklist.Items)
	require.GreaterOrEqual(t, len(checklist.Items), 14,
		"should have at least 14 audit checklist items")
}

func TestAuditChecklist_PassedCount(t *testing.T) {
	k, ctx := newTestKeeper(t)

	checklist := keeper.BuildAuditChecklist(ctx, k)
	passed := checklist.PassedCount()
	require.Greater(t, passed, 0, "at least some items should pass")
	require.LessOrEqual(t, passed, len(checklist.Items))
}

func TestAuditChecklist_BlockingFailures(t *testing.T) {
	k, ctx := newTestKeeper(t)

	checklist := keeper.BuildAuditChecklist(ctx, k)
	failures := checklist.BlockingFailures()
	// With default params, all blocking items should pass
	require.Empty(t, failures,
		"default params should have no blocking failures")
}

func TestAuditChecklist_ReadyForAudit(t *testing.T) {
	k, ctx := newTestKeeper(t)

	checklist := keeper.BuildAuditChecklist(ctx, k)
	require.True(t, checklist.IsReadyForAudit(),
		"clean state with default params should be audit-ready")
}

func TestAuditChecklist_HasPhases(t *testing.T) {
	k, ctx := newTestKeeper(t)

	checklist := keeper.BuildAuditChecklist(ctx, k)

	phase1Count, phase2Count := 0, 0
	for _, item := range checklist.Items {
		switch item.Phase {
		case keeper.ChecklistPhase1:
			phase1Count++
		case keeper.ChecklistPhase2:
			phase2Count++
		}
	}
	require.Greater(t, phase1Count, 0, "should have Phase 1 items")
	require.Greater(t, phase2Count, 0, "should have Phase 2 items")
}

func TestAuditChecklist_AllItemsHaveFields(t *testing.T) {
	k, ctx := newTestKeeper(t)

	checklist := keeper.BuildAuditChecklist(ctx, k)

	for _, item := range checklist.Items {
		require.NotEmpty(t, item.ID, "item must have ID")
		require.NotEmpty(t, item.Description, "item %s must have description", item.ID)
		require.NotEmpty(t, item.Category, "item %s must have category", item.ID)
		require.NotEmpty(t, item.Owner, "item %s must have owner", item.ID)
	}
}

// =============================================================================
// Section 3: Compliance Jurisdictions
// =============================================================================

func TestDefaultJurisdictions(t *testing.T) {
	jurisdictions := keeper.DefaultJurisdictions()
	require.Len(t, jurisdictions, 3)

	codes := make(map[string]bool)
	for _, j := range jurisdictions {
		codes[j.Code] = true
		require.NotEmpty(t, j.Name)
		require.NotEmpty(t, j.TokenStatus)
	}

	require.True(t, codes["CH"], "should include Switzerland")
	require.True(t, codes["NL"], "should include Netherlands")
	require.True(t, codes["ADGM"], "should include Abu Dhabi")
}

func TestDefaultJurisdictions_AllCompliant(t *testing.T) {
	for _, j := range keeper.DefaultJurisdictions() {
		require.True(t, j.Compliant,
			"jurisdiction %s should be compliant", j.Code)
	}
}

// =============================================================================
// Section 4: Security Invariant Spec
// =============================================================================

func TestSecurityInvariantSpec_HasInvariants(t *testing.T) {
	spec := keeper.SecurityInvariantSpec()
	require.GreaterOrEqual(t, len(spec), 10,
		"should have at least 10 security invariants")
}

func TestSecurityInvariantSpec_AllHaveFields(t *testing.T) {
	for _, inv := range keeper.SecurityInvariantSpec() {
		require.NotEmpty(t, inv.ID, "invariant must have ID")
		require.NotEmpty(t, inv.Name, "invariant %s must have name", inv.ID)
		require.NotEmpty(t, inv.Category, "invariant %s must have category", inv.ID)
		require.NotEmpty(t, inv.Specification, "invariant %s must have specification", inv.ID)
	}
}

func TestEvaluateSecurityInvariants_CleanState(t *testing.T) {
	k, ctx := newTestKeeper(t)

	results := keeper.EvaluateSecurityInvariants(ctx, k)
	require.GreaterOrEqual(t, len(results), 10)

	for _, r := range results {
		require.True(t, r.Holds,
			"invariant %s should hold in clean state: %s", r.Invariant.ID, r.Evidence)
	}
}

func TestSecurityInvariantSpec_UniqueIDs(t *testing.T) {
	spec := keeper.SecurityInvariantSpec()
	ids := make(map[string]bool)
	for _, inv := range spec {
		require.False(t, ids[inv.ID], "duplicate invariant ID: %s", inv.ID)
		ids[inv.ID] = true
	}
}

// =============================================================================
// Section 5: Audit Artifacts
// =============================================================================

func TestRequiredAuditArtifacts(t *testing.T) {
	artifacts := keeper.RequiredAuditArtifacts()
	require.GreaterOrEqual(t, len(artifacts), 7,
		"should have at least 7 audit artifacts")
}

func TestRequiredAuditArtifacts_AllGenerated(t *testing.T) {
	for _, a := range keeper.RequiredAuditArtifacts() {
		require.True(t, a.Generated,
			"artifact %s should be generated", a.ID)
		require.NotEmpty(t, a.Location,
			"artifact %s should have location", a.ID)
	}
}

// =============================================================================
// Section 6: Compliance Summary + Report
// =============================================================================

func TestRunComplianceSummary(t *testing.T) {
	k, ctx := newTestKeeper(t)

	summary := keeper.RunComplianceSummary(ctx, k)
	require.NotNil(t, summary)
	require.NotNil(t, summary.PolicyAssessment)
	require.NotNil(t, summary.AuditChecklist)
	require.NotEmpty(t, summary.Jurisdictions)
	require.NotEmpty(t, summary.InvariantResults)
	require.NotEmpty(t, summary.AuditArtifacts)
}

func TestRunComplianceSummary_OverallCompliant(t *testing.T) {
	k, ctx := newTestKeeper(t)

	summary := keeper.RunComplianceSummary(ctx, k)
	require.True(t, summary.OverallCompliant,
		"clean state should be overall compliant")
	require.True(t, summary.ReadyForAudit,
		"clean state should be audit-ready")
}

func TestRenderComplianceSummary(t *testing.T) {
	k, ctx := newTestKeeper(t)

	summary := keeper.RunComplianceSummary(ctx, k)
	report := keeper.RenderComplianceSummary(summary)

	require.Contains(t, report, "SECURITY & COMPLIANCE REPORT")
	require.Contains(t, report, "VERIFICATION POLICY")
	require.Contains(t, report, "SECURITY INVARIANTS")
	require.Contains(t, report, "AUDIT PREPARATION CHECKLIST")
	require.Contains(t, report, "COMPLIANCE JURISDICTIONS")
	require.Contains(t, report, "AUDIT ARTIFACTS")

	t.Log(report)
}

func TestRenderComplianceSummary_ContainsCriteria(t *testing.T) {
	k, ctx := newTestKeeper(t)

	summary := keeper.RunComplianceSummary(ctx, k)
	report := keeper.RenderComplianceSummary(summary)

	// Should contain specific criterion IDs
	require.True(t, strings.Contains(report, "VP-01") || strings.Contains(report, "SI-01"),
		"report should contain criterion IDs")
}

// =============================================================================
// Section 7: Integration
// =============================================================================

func TestFullSecurityComplianceFlow(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Evaluate verification policy
	policy := keeper.EvaluateVerificationPolicy(ctx, k)
	require.True(t, policy.Passed)

	// Build audit checklist
	checklist := keeper.BuildAuditChecklist(ctx, k)
	require.True(t, checklist.IsReadyForAudit())

	// Evaluate security invariants
	invariants := keeper.EvaluateSecurityInvariants(ctx, k)
	allHold := true
	for _, r := range invariants {
		if !r.Holds {
			allHold = false
		}
	}
	require.True(t, allHold, "all security invariants should hold")

	// Full compliance summary
	summary := keeper.RunComplianceSummary(ctx, k)
	require.True(t, summary.OverallCompliant)

	// Render report
	report := keeper.RenderComplianceSummary(summary)
	require.NotEmpty(t, report)

	t.Logf("Policy criteria: %d", len(policy.Criteria))
	t.Logf("Checklist items: %d passed/%d total", checklist.PassedCount(), len(checklist.Items))
	t.Logf("Invariants: %d evaluated", len(invariants))
}

func TestSecurityComplianceWithCorruptedState(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Corrupt params to trigger failures
	params, _ := k.GetParams(ctx)
	params.ConsensusThreshold = 40 // below BFT safety
	_ = k.Params.Set(ctx, *params)

	// Policy should fail
	policy := keeper.EvaluateVerificationPolicy(ctx, k)
	require.False(t, policy.Passed, "corrupted params should fail policy")

	// Should have critical failures
	failures := policy.CriticalFailures()
	require.NotEmpty(t, failures, "should have critical failures")

	// Compliance summary should reflect failure
	summary := keeper.RunComplianceSummary(ctx, k)
	require.False(t, summary.OverallCompliant)
}
