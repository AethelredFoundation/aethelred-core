package keeper_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// =============================================================================
// WEEK 28: Audit Scope & Engagement Framework Tests
//
// These tests verify:
//   1. Module component inventory completeness (7 tests)
//   2. Engagement phase structure (5 tests)
//   3. Scope boundary correctness (4 tests)
//   4. Threat coverage matrix (5 tests)
//   5. Auditor finding validation (6 tests)
//   6. Engagement checklist (5 tests)
//   7. Scope builder integration (4 tests)
//
// Total: 36 tests
// =============================================================================

// =============================================================================
// Section 1: Module Component Inventory
// =============================================================================

func TestModuleComponents_NonEmpty(t *testing.T) {
	components := keeper.ModuleComponents()
	require.NotEmpty(t, components, "must define at least one component")
	require.GreaterOrEqual(t, len(components), 10,
		"must have at least 10 auditable components")
}

func TestModuleComponents_AllHaveRequiredFields(t *testing.T) {
	for _, c := range keeper.ModuleComponents() {
		require.NotEmpty(t, c.ID, "component must have ID")
		require.NotEmpty(t, c.Module, "component %s must have module", c.ID)
		require.NotEmpty(t, c.File, "component %s must have file", c.ID)
		require.NotEmpty(t, c.Description, "component %s must have description", c.ID)
		require.NotEmpty(t, c.Criticality, "component %s must have criticality", c.ID)
		require.Greater(t, c.LOCEstimate, 0, "component %s must have LOC estimate", c.ID)
	}
}

func TestModuleComponents_UniqueIDs(t *testing.T) {
	seen := make(map[string]bool)
	for _, c := range keeper.ModuleComponents() {
		require.False(t, seen[c.ID], "duplicate component ID: %s", c.ID)
		seen[c.ID] = true
	}
}

func TestModuleComponents_CriticalComponentsIdentified(t *testing.T) {
	highCount := 0
	for _, c := range keeper.ModuleComponents() {
		if c.Criticality == keeper.CriticalityHigh {
			highCount++
		}
	}
	require.GreaterOrEqual(t, highCount, 5,
		"must identify at least 5 high-criticality components")
}

func TestModuleComponents_AllModulesCovered(t *testing.T) {
	// Verify we cover all four main modules
	modules := make(map[string]bool)
	for _, c := range keeper.ModuleComponents() {
		modules[c.Module] = true
	}

	required := []string{"x/pouw", "x/seal", "x/validator", "x/verify"}
	for _, m := range required {
		require.True(t, modules[m], "module %s must be covered in component inventory", m)
	}
}

func TestModuleComponents_HighCriticalityHaveTests(t *testing.T) {
	for _, c := range keeper.ModuleComponents() {
		if c.Criticality == keeper.CriticalityHigh {
			require.True(t, c.HasTests,
				"high-criticality component %s must have test coverage", c.ID)
			require.NotEmpty(t, c.TestFile,
				"high-criticality component %s must reference a test file", c.ID)
		}
	}
}

func TestModuleComponents_HighCriticalityHaveThreatRefs(t *testing.T) {
	for _, c := range keeper.ModuleComponents() {
		if c.Criticality == keeper.CriticalityHigh {
			require.NotEmpty(t, c.ThreatModelRefs,
				"high-criticality component %s must reference at least one threat model entry", c.ID)
		}
	}
}

// =============================================================================
// Section 2: Engagement Phase Structure
// =============================================================================

func TestEngagementPhases_NonEmpty(t *testing.T) {
	phases := keeper.EngagementPhases()
	require.NotEmpty(t, phases, "must define engagement phases")
	require.GreaterOrEqual(t, len(phases), 6,
		"must have at least 6 engagement phases")
}

func TestEngagementPhases_AllHaveRequiredFields(t *testing.T) {
	for _, p := range keeper.EngagementPhases() {
		require.NotEmpty(t, p.ID, "phase must have ID")
		require.NotEmpty(t, p.Name, "phase %s must have name", p.ID)
		require.NotEmpty(t, p.Description, "phase %s must have description", p.ID)
		require.NotEmpty(t, p.Duration, "phase %s must have duration", p.ID)
		require.NotEmpty(t, p.Deliverable, "phase %s must have deliverable", p.ID)
	}
}

func TestEngagementPhases_IncludesCodeReview(t *testing.T) {
	hasCodeReview := false
	for _, p := range keeper.EngagementPhases() {
		if strings.Contains(strings.ToLower(p.Name), "code review") {
			hasCodeReview = true
			break
		}
	}
	require.True(t, hasCodeReview, "must include a code review phase")
}

func TestEngagementPhases_IncludesRemediationReview(t *testing.T) {
	hasRemediation := false
	for _, p := range keeper.EngagementPhases() {
		if strings.Contains(strings.ToLower(p.Name), "remediation") {
			hasRemediation = true
			break
		}
	}
	require.True(t, hasRemediation, "must include a remediation review phase")
}

func TestEngagementPhases_UniqueIDs(t *testing.T) {
	seen := make(map[string]bool)
	for _, p := range keeper.EngagementPhases() {
		require.False(t, seen[p.ID], "duplicate phase ID: %s", p.ID)
		seen[p.ID] = true
	}
}

// =============================================================================
// Section 3: Scope Boundary Correctness
// =============================================================================

func TestScopeBoundaries_NonEmpty(t *testing.T) {
	boundaries := keeper.ScopeBoundaries()
	require.NotEmpty(t, boundaries)
}

func TestScopeBoundaries_HasInScope(t *testing.T) {
	inScopeCount := 0
	for _, b := range keeper.ScopeBoundaries() {
		if b.InScope {
			inScopeCount++
		}
	}
	require.GreaterOrEqual(t, inScopeCount, 5,
		"must have at least 5 in-scope items")
}

func TestScopeBoundaries_HasOutOfScope(t *testing.T) {
	outScopeCount := 0
	for _, b := range keeper.ScopeBoundaries() {
		if !b.InScope {
			outScopeCount++
		}
	}
	require.GreaterOrEqual(t, outScopeCount, 3,
		"must have at least 3 out-of-scope items")
}

func TestScopeBoundaries_AllHaveRationale(t *testing.T) {
	for _, b := range keeper.ScopeBoundaries() {
		require.NotEmpty(t, b.Rationale,
			"scope boundary '%s' must have rationale", b.Item)
	}
}

// =============================================================================
// Section 4: Threat Coverage Matrix
// =============================================================================

func TestThreatCoverageMatrix_NonEmpty(t *testing.T) {
	components := keeper.ModuleComponents()
	matrix := keeper.BuildThreatCoverageMatrix(components)
	require.NotEmpty(t, matrix, "threat coverage matrix must not be empty")
}

func TestThreatCoverageMatrix_CoversHighImpact(t *testing.T) {
	components := keeper.ModuleComponents()
	matrix := keeper.BuildThreatCoverageMatrix(components)

	// All attack surfaces with critical/high impact must be covered
	for _, as := range keeper.AttackSurfaces {
		if as.Impact == "critical" || as.Impact == "high" {
			covered := matrix[as.ID]
			require.NotEmpty(t, covered,
				"attack surface %s (%s) with %s impact must be covered by at least one component",
				as.ID, as.Name, as.Impact)
		}
	}
}

func TestThreatCoverageMatrix_ConsensusCovered(t *testing.T) {
	components := keeper.ModuleComponents()
	matrix := keeper.BuildThreatCoverageMatrix(components)

	// AS-01 (Rogue Validator False Result) must be covered
	require.NotEmpty(t, matrix["AS-01"],
		"AS-01 (consensus safety) must be covered")

	// AS-02 (Validator Coalition) must be covered
	require.NotEmpty(t, matrix["AS-02"],
		"AS-02 (coalition attack) must be covered")
}

func TestThreatCoverageMatrix_EconomicsCovered(t *testing.T) {
	components := keeper.ModuleComponents()
	matrix := keeper.BuildThreatCoverageMatrix(components)

	// AS-09 and AS-10 (economic attacks) must be covered
	require.NotEmpty(t, matrix["AS-09"],
		"AS-09 (economic attack) must be covered")
	require.NotEmpty(t, matrix["AS-10"],
		"AS-10 (fee manipulation) must be covered")
}

func TestUncoveredAttackSurfaces_Documented(t *testing.T) {
	components := keeper.ModuleComponents()
	matrix := keeper.BuildThreatCoverageMatrix(components)
	uncovered := keeper.UncoveredAttackSurfaces(matrix)

	for _, as := range uncovered {
		t.Logf("UNCOVERED: [%s] %s — impact: %s, status: %s",
			as.ID, as.Name, as.Impact, as.Status)
	}

	// No critical-impact attack surface should be uncovered
	for _, as := range uncovered {
		require.NotEqual(t, "critical", as.Impact,
			"critical attack surface %s (%s) must not be uncovered", as.ID, as.Name)
	}
}

// =============================================================================
// Section 5: Auditor Finding Validation
// =============================================================================

func TestValidateAuditorFinding_Valid(t *testing.T) {
	f := &keeper.AuditorFinding{
		AuditFinding: keeper.AuditFinding{
			ID:          "EXT-001",
			CheckName:   "consensus_threshold_manipulation",
			Severity:    keeper.FindingHigh,
			Description: "Governance proposal can lower consensus threshold below BFT safety",
		},
		AuditorName:    "Test Auditor",
		ComponentID:    "pouw/keeper/governance",
		CVSSScore:      7.5,
		CWEReference:   "CWE-284",
	}
	require.NoError(t, keeper.ValidateAuditorFinding(f))
}

func TestValidateAuditorFinding_MissingID(t *testing.T) {
	f := &keeper.AuditorFinding{
		AuditFinding: keeper.AuditFinding{
			CheckName:   "test",
			Severity:    keeper.FindingHigh,
			Description: "test",
		},
		AuditorName: "Test",
		ComponentID: "pouw/keeper/governance",
	}
	err := keeper.ValidateAuditorFinding(f)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ID")
}

func TestValidateAuditorFinding_InvalidSeverity(t *testing.T) {
	f := &keeper.AuditorFinding{
		AuditFinding: keeper.AuditFinding{
			ID:          "EXT-001",
			CheckName:   "test",
			Severity:    "INVALID",
			Description: "test",
		},
		AuditorName: "Test",
		ComponentID: "pouw/keeper/governance",
	}
	err := keeper.ValidateAuditorFinding(f)
	require.Error(t, err)
	require.Contains(t, err.Error(), "severity")
}

func TestValidateAuditorFinding_InvalidCVSS(t *testing.T) {
	f := &keeper.AuditorFinding{
		AuditFinding: keeper.AuditFinding{
			ID:          "EXT-001",
			CheckName:   "test",
			Severity:    keeper.FindingHigh,
			Description: "test",
		},
		AuditorName: "Test",
		ComponentID: "pouw/keeper/governance",
		CVSSScore:   11.0, // Out of range
	}
	err := keeper.ValidateAuditorFinding(f)
	require.Error(t, err)
	require.Contains(t, err.Error(), "CVSS")
}

func TestValidateAuditorFinding_InvalidComponent(t *testing.T) {
	f := &keeper.AuditorFinding{
		AuditFinding: keeper.AuditFinding{
			ID:          "EXT-001",
			CheckName:   "test",
			Severity:    keeper.FindingHigh,
			Description: "test",
		},
		AuditorName: "Test",
		ComponentID: "nonexistent/module",
	}
	err := keeper.ValidateAuditorFinding(f)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown component")
}

func TestValidateAuditorFinding_AllSeverityLevels(t *testing.T) {
	severities := []keeper.FindingSeverity{
		keeper.FindingCritical,
		keeper.FindingHigh,
		keeper.FindingMedium,
		keeper.FindingLow,
		keeper.FindingInfo,
	}

	for _, sev := range severities {
		f := &keeper.AuditorFinding{
			AuditFinding: keeper.AuditFinding{
				ID:          "EXT-001",
				CheckName:   "test",
				Severity:    sev,
				Description: "test",
			},
			AuditorName: "Test",
			ComponentID: "pouw/keeper/governance",
		}
		require.NoError(t, keeper.ValidateAuditorFinding(f),
			"severity %s should be valid", sev)
	}
}

// =============================================================================
// Section 6: Engagement Checklist
// =============================================================================

func TestEngagementChecklist_NonEmpty(t *testing.T) {
	items := keeper.EngagementChecklist(nil)
	require.NotEmpty(t, items)
	require.GreaterOrEqual(t, len(items), 10,
		"must have at least 10 checklist items")
}

func TestEngagementChecklist_AllHaveRequiredFields(t *testing.T) {
	for _, item := range keeper.EngagementChecklist(nil) {
		require.NotEmpty(t, item.ID, "checklist item must have ID")
		require.NotEmpty(t, item.Category, "checklist item %s must have category", item.ID)
		require.NotEmpty(t, item.Description, "checklist item %s must have description", item.ID)
	}
}

func TestEngagementChecklist_HasRequiredItems(t *testing.T) {
	requiredCount := 0
	for _, item := range keeper.EngagementChecklist(nil) {
		if item.Required {
			requiredCount++
		}
	}
	require.GreaterOrEqual(t, requiredCount, 10,
		"must have at least 10 required checklist items")
}

func TestEngagementChecklist_AutoCompletesFromScope(t *testing.T) {
	k, ctx := newTestKeeper(t)

	scope := keeper.BuildAuditScope(ctx, k)
	items := keeper.EngagementChecklist(scope)

	// CL-14 (module version confirmed) should be auto-completed
	for _, item := range items {
		if item.ID == "CL-14" {
			require.True(t, item.Completed,
				"CL-14 should be auto-completed when module version > 0")
		}
	}
}

func TestChecklistComplete_NotComplete(t *testing.T) {
	items := keeper.EngagementChecklist(nil)
	// Without scope, most items won't be completed
	require.False(t, keeper.ChecklistComplete(items),
		"checklist should not be complete without scope")
}

// =============================================================================
// Section 7: Scope Builder Integration
// =============================================================================

func TestBuildAuditScope_Integration(t *testing.T) {
	k, ctx := newTestKeeper(t)

	scope := keeper.BuildAuditScope(ctx, k)

	require.NotNil(t, scope)
	require.Equal(t, "Aethelred Sovereign L1", scope.ProjectName)
	require.NotEmpty(t, scope.ChainID)
	require.NotEmpty(t, scope.EngagementDate)
	require.Greater(t, scope.ModuleVersion, uint64(0))
	require.NotEmpty(t, scope.Components)
	require.NotEmpty(t, scope.Phases)
	require.NotEmpty(t, scope.Boundaries)
	require.NotNil(t, scope.ThreatCoverage)
	require.NotNil(t, scope.AuditReport)
}

func TestBuildAuditScope_HasPreAuditReport(t *testing.T) {
	k, ctx := newTestKeeper(t)

	scope := keeper.BuildAuditScope(ctx, k)

	require.NotNil(t, scope.AuditReport)
	require.Greater(t, scope.AuditReport.TotalChecks, 0,
		"pre-audit report must run checks")
}

func TestBuildAuditScope_Stats(t *testing.T) {
	k, ctx := newTestKeeper(t)

	scope := keeper.BuildAuditScope(ctx, k)
	stats := scope.Stats()

	require.Greater(t, stats.TotalComponents, 0)
	require.Greater(t, stats.HighCriticality, 0)
	require.Greater(t, stats.TotalLOC, 0)
	require.Greater(t, stats.UniqueModules, 0)
	require.Greater(t, stats.CoveragePercent, 0.0)

	t.Logf("Stats: %d components, %d high-crit, %d LoC, %d modules, %.1f%% tested",
		stats.TotalComponents, stats.HighCriticality, stats.TotalLOC,
		stats.UniqueModules, stats.CoveragePercent)
}

func TestBuildAuditScope_RenderDocument(t *testing.T) {
	k, ctx := newTestKeeper(t)

	scope := keeper.BuildAuditScope(ctx, k)
	doc := scope.RenderScopeDocument()

	require.Contains(t, doc, "SECURITY AUDIT SCOPE DOCUMENT")
	require.Contains(t, doc, "Aethelred Sovereign L1")
	require.Contains(t, doc, "AUDITABLE COMPONENTS")
	require.Contains(t, doc, "SCOPE BOUNDARIES")
	require.Contains(t, doc, "THREAT COVERAGE MATRIX")
	require.Contains(t, doc, "ENGAGEMENT PHASES")
	require.Contains(t, doc, "PRE-AUDIT HEALTH CHECK")

	// Log first 2000 chars for visual inspection
	if len(doc) > 2000 {
		t.Logf("Scope document (truncated):\n%s...", doc[:2000])
	} else {
		t.Log(doc)
	}
}
