package keeper

import (
	"fmt"
	"strings"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// ---------------------------------------------------------------------------
// Week 28: Audit Scope & Engagement Framework
// ---------------------------------------------------------------------------
//
// This file provides a programmatic audit scope definition that external
// auditors use as their engagement guide. It includes:
//
//   1. Module inventory with criticality ratings
//   2. Code surface area metrics (files, LoC, test counts)
//   3. Coverage matrices mapping modules to threat model entries
//   4. Engagement checklist with phase definitions
//   5. Scope boundary definitions (in-scope vs out-of-scope)
//   6. Auditor deliverable templates
//
// Usage:
//   scope := BuildAuditScope(ctx, k)
//   fmt.Println(scope.RenderScopeDocument())
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Audit scope data types
// ---------------------------------------------------------------------------

// ModuleCriticality rates the security importance of a module component.
type ModuleCriticality string

const (
	CriticalityHigh   ModuleCriticality = "HIGH"
	CriticalityMedium ModuleCriticality = "MEDIUM"
	CriticalityLow    ModuleCriticality = "LOW"
)

// ModuleComponent describes a single auditable component in the codebase.
type ModuleComponent struct {
	ID           string            // Unique identifier (e.g., "pouw/keeper/consensus")
	Module       string            // Parent module (e.g., "x/pouw")
	File         string            // Relative file path
	Description  string            // What this component does
	Criticality  ModuleCriticality // Security criticality rating
	LOCEstimate  int               // Estimated lines of code
	HasTests     bool              // Whether test coverage exists
	TestFile     string            // Corresponding test file (if any)
	ThreatModelRefs []string       // Related attack surface IDs (e.g., "AS-01")
	AuditNotes   string            // Special notes for auditors
}

// AuditPhase describes one phase of the external audit engagement.
type AuditPhase struct {
	ID          string
	Name        string
	Description string
	Duration    string // e.g., "3 days"
	Deliverable string // What the auditor produces
}

// ScopeBoundary defines an explicit in-scope or out-of-scope item.
type ScopeBoundary struct {
	Item       string
	InScope    bool
	Rationale  string
}

// AuditScope is the complete audit engagement scope document.
type AuditScope struct {
	// Header
	ProjectName    string
	ChainID        string
	EngagementDate string
	ModuleVersion  uint64
	BlockHeight    int64

	// Components
	Components     []ModuleComponent

	// Engagement plan
	Phases         []AuditPhase

	// Scope boundaries
	Boundaries     []ScopeBoundary

	// Coverage matrix
	ThreatCoverage map[string][]string // attack surface ID → component IDs

	// Runtime state summary
	ParamSnapshot  *types.Params
	JobCount       uint64
	ValidatorCount int
	PendingCount   int

	// Pre-audit health
	AuditReport    *AuditReport
}

// ---------------------------------------------------------------------------
// Module component registry
// ---------------------------------------------------------------------------

// ModuleComponents returns the complete inventory of auditable components.
func ModuleComponents() []ModuleComponent {
	return []ModuleComponent{
		// x/pouw/keeper — core consensus and job management
		{
			ID: "pouw/keeper/keeper", Module: "x/pouw", File: "keeper/keeper.go",
			Description:    "Core keeper struct, state collections, initialization",
			Criticality:    CriticalityHigh,
			LOCEstimate:    200,
			HasTests:       true,
			TestFile:       "keeper/test_helpers_test.go",
			ThreatModelRefs: []string{"AS-06", "AS-07"},
			AuditNotes:     "Review collections initialization and access control on exported fields",
		},
		{
			ID: "pouw/keeper/consensus", Module: "x/pouw", File: "keeper/consensus.go",
			Description:    "Proof-of-Useful-Work consensus handler, vote extension aggregation",
			Criticality:    CriticalityHigh,
			LOCEstimate:    500,
			HasTests:       true,
			TestFile:       "keeper/consensus_test.go",
			ThreatModelRefs: []string{"AS-01", "AS-02", "AS-03", "AS-04", "AS-05"},
			AuditNotes:     "CRITICAL: Core consensus logic. Verify BFT threshold enforcement, vote tallying, result aggregation",
		},
		{
			ID: "pouw/keeper/governance", Module: "x/pouw", File: "keeper/governance.go",
			Description:    "Parameter governance, MergeParams, UpdateParams handler, one-way gate",
			Criticality:    CriticalityHigh,
			LOCEstimate:    300,
			HasTests:       true,
			TestFile:       "keeper/production_mode_test.go",
			ThreatModelRefs: []string{"AS-07", "AS-08"},
			AuditNotes:     "Verify AllowSimulated one-way gate in UpdateParams handler. MergeParams is a pure merge — gate is at handler level",
		},
		{
			ID: "pouw/keeper/evidence", Module: "x/pouw", File: "keeper/evidence.go",
			Description:    "Byzantine evidence detection and collection",
			Criticality:    CriticalityHigh,
			LOCEstimate:    350,
			HasTests:       true,
			TestFile:       "keeper/byzantine_test.go",
			ThreatModelRefs: []string{"AS-01", "AS-02", "AS-05"},
			AuditNotes:     "Verify evidence validation, double-sign detection, collusion detection thresholds",
		},
		{
			ID: "pouw/keeper/fee_distribution", Module: "x/pouw", File: "keeper/fee_distribution.go",
			Description:    "Fee distribution with BPS-based splits, conservation enforcement",
			Criticality:    CriticalityHigh,
			LOCEstimate:    300,
			HasTests:       true,
			TestFile:       "keeper/tokenomics_test.go",
			ThreatModelRefs: []string{"AS-09", "AS-10"},
			AuditNotes:     "Verify BPS sum = 10000, integer rounding, conservation across all edge cases",
		},
		{
			ID: "pouw/keeper/staking", Module: "x/pouw", File: "keeper/staking.go",
			Description:    "Validator staking, reputation scaling, reward distribution",
			Criticality:    CriticalityMedium,
			LOCEstimate:    250,
			HasTests:       true,
			TestFile:       "keeper/tokenomics_test.go",
			ThreatModelRefs: []string{"AS-09", "AS-10", "AS-11"},
			AuditNotes:     "Verify reputation scaling formula, reward bounds, staking amount validation",
		},
		{
			ID: "pouw/keeper/scheduler", Module: "x/pouw", File: "keeper/scheduler.go",
			Description:    "Job scheduling, priority queue, load balancing",
			Criticality:    CriticalityMedium,
			LOCEstimate:    300,
			HasTests:       true,
			TestFile:       "keeper/scheduler_test.go",
			ThreatModelRefs: []string{"AS-12"},
			AuditNotes:     "Verify job ordering fairness, DoS resistance, timeout enforcement",
		},
		{
			ID: "pouw/keeper/msg_server", Module: "x/pouw", File: "keeper/msg_server.go",
			Description:    "Message handler entry points (SubmitJob, SubmitProof, etc.)",
			Criticality:    CriticalityHigh,
			LOCEstimate:    400,
			HasTests:       true,
			TestFile:       "keeper/e2e_test.go",
			ThreatModelRefs: []string{"AS-06", "AS-07", "AS-12"},
			AuditNotes:     "Verify input validation, authorization checks, state transition correctness",
		},
		{
			ID: "pouw/keeper/invariants", Module: "x/pouw", File: "keeper/invariants.go",
			Description:    "Module invariant checks (7 invariants)",
			Criticality:    CriticalityMedium,
			LOCEstimate:    250,
			HasTests:       true,
			TestFile:       "keeper/e2e_test.go",
			ThreatModelRefs: []string{"AS-13"},
			AuditNotes:     "Verify all 7 invariants are complete and can detect all known corruption patterns",
		},
		{
			ID: "pouw/keeper/audit", Module: "x/pouw", File: "keeper/audit.go",
			Description:    "Structured audit logging with SHA-256 hash chain",
			Criticality:    CriticalityMedium,
			LOCEstimate:    500,
			HasTests:       true,
			TestFile:       "keeper/security_audit_test.go",
			ThreatModelRefs: []string{"AS-14", "AS-15"},
			AuditNotes:     "Verify hash chain integrity, tamper resistance, event emission completeness",
		},
		{
			ID: "pouw/keeper/metrics", Module: "x/pouw", File: "keeper/metrics.go",
			Description:    "Prometheus metrics and observability",
			Criticality:    CriticalityLow,
			LOCEstimate:    200,
			HasTests:       true,
			TestFile:       "keeper/observability_test.go",
			ThreatModelRefs: []string{},
			AuditNotes:     "Low security impact. Verify no sensitive data leaks through metrics labels",
		},
		{
			ID: "pouw/keeper/upgrade", Module: "x/pouw", File: "keeper/upgrade.go",
			Description:    "Module upgrade/migration infrastructure (v1→v2)",
			Criticality:    CriticalityMedium,
			LOCEstimate:    310,
			HasTests:       true,
			TestFile:       "keeper/devex_test.go",
			ThreatModelRefs: []string{"AS-13"},
			AuditNotes:     "Verify migration determinism, orphan cleanup, job count reconciliation",
		},

		// x/seal — digital seal module
		{
			ID: "seal/keeper/keeper", Module: "x/seal", File: "keeper/keeper.go",
			Description:    "Digital seal creation, storage, and retrieval",
			Criticality:    CriticalityHigh,
			LOCEstimate:    300,
			HasTests:       true,
			TestFile:       "keeper/seal_test.go",
			ThreatModelRefs: []string{"AS-14", "AS-15"},
			AuditNotes:     "Verify seal immutability, hash commitments, attestation storage",
		},
		{
			ID: "seal/keeper/verifier", Module: "x/seal", File: "keeper/verifier.go",
			Description:    "Seal verification and integrity checking",
			Criticality:    CriticalityHigh,
			LOCEstimate:    200,
			HasTests:       true,
			TestFile:       "keeper/seal_test.go",
			ThreatModelRefs: []string{"AS-14"},
			AuditNotes:     "Verify seal verification logic, commitment matching, revocation checks",
		},
		{
			ID: "seal/keeper/revocation", Module: "x/seal", File: "keeper/revocation.go",
			Description:    "Seal revocation with evidence requirement",
			Criticality:    CriticalityMedium,
			LOCEstimate:    150,
			HasTests:       true,
			TestFile:       "keeper/seal_test.go",
			ThreatModelRefs: []string{"AS-15"},
			AuditNotes:     "Verify revocation authorization, evidence validation",
		},

		// x/validator — validator management
		{
			ID: "validator/keeper/slashing", Module: "x/validator", File: "keeper/slashing.go",
			Description:    "Validator slashing conditions and penalty enforcement",
			Criticality:    CriticalityHigh,
			LOCEstimate:    250,
			HasTests:       true,
			TestFile:       "keeper/slashing_test.go",
			ThreatModelRefs: []string{"AS-01", "AS-02", "AS-05", "AS-16"},
			AuditNotes:     "Verify escalation ladder, penalty calculations, jailing conditions",
		},

		// x/verify — verification engines
		{
			ID: "verify/keeper/keeper", Module: "x/verify", File: "keeper/keeper.go",
			Description:    "Verification orchestration (TEE + zkML)",
			Criticality:    CriticalityHigh,
			LOCEstimate:    350,
			HasTests:       true,
			TestFile:       "keeper/remote_verifier_test.go",
			ThreatModelRefs: []string{"AS-03", "AS-04", "AS-17"},
			AuditNotes:     "Verify attestation validation, proof verification, fallback logic",
		},
	}
}

// ---------------------------------------------------------------------------
// Audit engagement phases
// ---------------------------------------------------------------------------

// EngagementPhases returns the standard audit engagement phases.
func EngagementPhases() []AuditPhase {
	return []AuditPhase{
		{
			ID: "PHASE-01", Name: "Kickoff & Scope Confirmation",
			Description: "Review scope document, confirm component inventory, align on threat model coverage. Auditor receives access to private repository, CI artifacts, and documentation.",
			Duration:    "1 day",
			Deliverable: "Signed scope confirmation document",
		},
		{
			ID: "PHASE-02", Name: "Architecture Review",
			Description: "Review system architecture, module dependencies, consensus flow, state machine transitions. Identify architectural risks not covered by existing threat model.",
			Duration:    "2 days",
			Deliverable: "Architecture risk assessment memo",
		},
		{
			ID: "PHASE-03", Name: "Code Review — Consensus & Governance",
			Description: "Deep review of consensus.go, governance.go, evidence.go, and msg_server.go. Focus on BFT safety, vote extension handling, parameter governance gates, and state transition correctness.",
			Duration:    "3 days",
			Deliverable: "Findings report for consensus/governance components",
		},
		{
			ID: "PHASE-04", Name: "Code Review — Economics & State",
			Description: "Deep review of fee_distribution.go, staking.go, scheduler.go, invariants.go. Focus on fee conservation, rounding safety, reward distribution correctness, and invariant completeness.",
			Duration:    "2 days",
			Deliverable: "Findings report for economics/state components",
		},
		{
			ID: "PHASE-05", Name: "Code Review — Seal & Verification",
			Description: "Review x/seal and x/verify modules. Focus on seal immutability, attestation verification, zkML proof validation, and cross-module trust boundaries.",
			Duration:    "2 days",
			Deliverable: "Findings report for seal/verification components",
		},
		{
			ID: "PHASE-06", Name: "Attack Simulation",
			Description: "Execute attack scenarios from the threat model against a local testnet. Attempt to: forge proofs, manipulate governance, break fee conservation, corrupt state, and bypass the one-way gate.",
			Duration:    "3 days",
			Deliverable: "Attack simulation results with PoUW exploits (if any)",
		},
		{
			ID: "PHASE-07", Name: "Findings Consolidation & Report",
			Description: "Consolidate all findings into a structured report. Classify by severity (Critical/High/Medium/Low/Info). Provide remediation recommendations and verification criteria.",
			Duration:    "2 days",
			Deliverable: "Final audit report (PDF + structured JSON)",
		},
		{
			ID: "PHASE-08", Name: "Remediation Review",
			Description: "Review fixes applied by the development team for all Critical and High findings. Verify that remediations address root causes and do not introduce new issues.",
			Duration:    "2 days",
			Deliverable: "Remediation verification report + sign-off",
		},
	}
}

// ---------------------------------------------------------------------------
// Scope boundaries
// ---------------------------------------------------------------------------

// ScopeBoundaries returns the explicit in-scope and out-of-scope items.
func ScopeBoundaries() []ScopeBoundary {
	return []ScopeBoundary{
		// In-scope
		{Item: "x/pouw module (all keeper files)", InScope: true, Rationale: "Core consensus, governance, and economic logic"},
		{Item: "x/seal module (all keeper files)", InScope: true, Rationale: "Digital seal creation, verification, and revocation"},
		{Item: "x/validator module (slashing)", InScope: true, Rationale: "Validator penalty enforcement"},
		{Item: "x/verify module (verification engines)", InScope: true, Rationale: "TEE and zkML proof verification"},
		{Item: "Proto/types definitions (x/*/types)", InScope: true, Rationale: "State schema and message definitions"},
		{Item: "Module upgrade/migration logic", InScope: true, Rationale: "State migration correctness"},
		{Item: "ABCI++ vote extension handlers (app/abci.go)", InScope: true, Rationale: "Consensus integration point"},
		{Item: "Genesis import/export", InScope: true, Rationale: "State initialization and snapshot correctness"},
		{Item: "Parameter validation and governance", InScope: true, Rationale: "Critical governance safety gates"},

		// Out-of-scope
		{Item: "Frontend applications (apps/)", InScope: false, Rationale: "UI layer, no consensus/state impact"},
		{Item: "TypeScript/Python SDKs (sdk/)", InScope: false, Rationale: "Client-side, no on-chain impact"},
		{Item: "Infrastructure/Terraform (infrastructure/)", InScope: false, Rationale: "Deployment tooling, separate audit"},
		{Item: "CometBFT/Cosmos SDK framework code", InScope: false, Rationale: "Audited separately by upstream"},
		{Item: "Third-party dependencies (go.mod)", InScope: false, Rationale: "Dependency audit is separate engagement"},
		{Item: "CI/CD pipeline configuration", InScope: false, Rationale: "Build tooling, separate audit"},
		{Item: "Documentation and README files", InScope: false, Rationale: "Non-executable content"},
	}
}

// ---------------------------------------------------------------------------
// Coverage matrix builder
// ---------------------------------------------------------------------------

// BuildThreatCoverageMatrix maps each attack surface to the components that
// address it, enabling auditors to verify coverage completeness.
func BuildThreatCoverageMatrix(components []ModuleComponent) map[string][]string {
	matrix := make(map[string][]string)

	for _, c := range components {
		for _, asRef := range c.ThreatModelRefs {
			matrix[asRef] = append(matrix[asRef], c.ID)
		}
	}

	return matrix
}

// UncoveredAttackSurfaces returns attack surfaces that have no component
// coverage in the audit scope. These represent gaps that need attention.
func UncoveredAttackSurfaces(matrix map[string][]string) []AttackSurface {
	var uncovered []AttackSurface
	for _, as := range AttackSurfaces {
		if _, ok := matrix[as.ID]; !ok {
			uncovered = append(uncovered, as)
		}
	}
	return uncovered
}

// ---------------------------------------------------------------------------
// Scope builder
// ---------------------------------------------------------------------------

// BuildAuditScope constructs the complete audit scope document from live
// chain state and the static module registry. This is the primary entry
// point for generating the engagement scope.
func BuildAuditScope(ctx sdk.Context, k Keeper) *AuditScope {
	components := ModuleComponents()
	matrix := BuildThreatCoverageMatrix(components)

	// Gather runtime state
	params, _ := k.GetParams(ctx)
	jobCount, _ := k.JobCount.Get(ctx)

	validatorCount := 0
	_ = k.ValidatorStats.Walk(ctx, nil, func(_ string, _ types.ValidatorStats) (bool, error) {
		validatorCount++
		return false, nil
	})

	pendingCount := 0
	_ = k.PendingJobs.Walk(ctx, nil, func(_ string, _ types.ComputeJob) (bool, error) {
		pendingCount++
		return false, nil
	})

	// Run pre-audit health check
	report := RunSecurityAudit(ctx, k)

	return &AuditScope{
		ProjectName:    "Aethelred Sovereign L1",
		ChainID:        ctx.ChainID(),
		EngagementDate: time.Now().UTC().Format("2006-01-02"),
		ModuleVersion:  ModuleConsensusVersion,
		BlockHeight:    ctx.BlockHeight(),

		Components:     components,
		Phases:         EngagementPhases(),
		Boundaries:     ScopeBoundaries(),
		ThreatCoverage: matrix,

		ParamSnapshot:  params,
		JobCount:       jobCount,
		ValidatorCount: validatorCount,
		PendingCount:   pendingCount,

		AuditReport: report,
	}
}

// ---------------------------------------------------------------------------
// Scope document renderer
// ---------------------------------------------------------------------------

// RenderScopeDocument produces a human-readable scope document suitable
// for sharing with external auditors.
func (s *AuditScope) RenderScopeDocument() string {
	var sb strings.Builder

	// Header
	sb.WriteString("===========================================================\n")
	sb.WriteString("  SECURITY AUDIT SCOPE DOCUMENT\n")
	sb.WriteString("  " + s.ProjectName + "\n")
	sb.WriteString("===========================================================\n\n")
	sb.WriteString(fmt.Sprintf("Chain ID:         %s\n", s.ChainID))
	sb.WriteString(fmt.Sprintf("Engagement Date:  %s\n", s.EngagementDate))
	sb.WriteString(fmt.Sprintf("Module Version:   %d\n", s.ModuleVersion))
	sb.WriteString(fmt.Sprintf("Block Height:     %d\n\n", s.BlockHeight))

	// Runtime state
	sb.WriteString("--- RUNTIME STATE SUMMARY ---\n")
	sb.WriteString(fmt.Sprintf("Total Jobs:       %d\n", s.JobCount))
	sb.WriteString(fmt.Sprintf("Validators:       %d\n", s.ValidatorCount))
	sb.WriteString(fmt.Sprintf("Pending Jobs:     %d\n\n", s.PendingCount))

	// Module components
	sb.WriteString("--- AUDITABLE COMPONENTS ---\n")
	sb.WriteString(fmt.Sprintf("Total components: %d\n\n", len(s.Components)))

	critCount, highCount, medCount := 0, 0, 0
	totalLOC := 0
	testedCount := 0
	for _, c := range s.Components {
		switch c.Criticality {
		case CriticalityHigh:
			highCount++
		case CriticalityMedium:
			medCount++
		case CriticalityLow:
			critCount++ // "low" criticality count
		}
		totalLOC += c.LOCEstimate
		if c.HasTests {
			testedCount++
		}
	}
	sb.WriteString(fmt.Sprintf("HIGH criticality:   %d components\n", highCount))
	sb.WriteString(fmt.Sprintf("MEDIUM criticality: %d components\n", medCount))
	sb.WriteString(fmt.Sprintf("Estimated total LoC: %d\n", totalLOC))
	sb.WriteString(fmt.Sprintf("Components with tests: %d/%d\n\n", testedCount, len(s.Components)))

	for _, c := range s.Components {
		sb.WriteString(fmt.Sprintf("  [%s] %s (%s)\n", c.Criticality, c.ID, c.File))
		sb.WriteString(fmt.Sprintf("    %s\n", c.Description))
		if len(c.ThreatModelRefs) > 0 {
			sb.WriteString(fmt.Sprintf("    Threat refs: %s\n", strings.Join(c.ThreatModelRefs, ", ")))
		}
		if c.AuditNotes != "" {
			sb.WriteString(fmt.Sprintf("    Auditor note: %s\n", c.AuditNotes))
		}
		sb.WriteString("\n")
	}

	// Scope boundaries
	sb.WriteString("--- SCOPE BOUNDARIES ---\n\n")
	sb.WriteString("IN-SCOPE:\n")
	for _, b := range s.Boundaries {
		if b.InScope {
			sb.WriteString(fmt.Sprintf("  ✓ %s — %s\n", b.Item, b.Rationale))
		}
	}
	sb.WriteString("\nOUT-OF-SCOPE:\n")
	for _, b := range s.Boundaries {
		if !b.InScope {
			sb.WriteString(fmt.Sprintf("  ✗ %s — %s\n", b.Item, b.Rationale))
		}
	}
	sb.WriteString("\n")

	// Threat coverage matrix
	sb.WriteString("--- THREAT COVERAGE MATRIX ---\n\n")
	for _, as := range AttackSurfaces {
		components := s.ThreatCoverage[as.ID]
		status := "COVERED"
		if len(components) == 0 {
			status = "GAP"
		}
		sb.WriteString(fmt.Sprintf("  [%s] %s (%s) — %s\n", as.ID, as.Name, as.Impact, status))
		if len(components) > 0 {
			sb.WriteString(fmt.Sprintf("    Components: %s\n", strings.Join(components, ", ")))
		}
	}
	sb.WriteString("\n")

	// Engagement phases
	sb.WriteString("--- ENGAGEMENT PHASES ---\n\n")
	totalDuration := 0
	for _, p := range s.Phases {
		sb.WriteString(fmt.Sprintf("  %s: %s (%s)\n", p.ID, p.Name, p.Duration))
		sb.WriteString(fmt.Sprintf("    %s\n", p.Description))
		sb.WriteString(fmt.Sprintf("    Deliverable: %s\n\n", p.Deliverable))
		// Parse duration for total estimate
		if strings.HasSuffix(p.Duration, " days") || strings.HasSuffix(p.Duration, " day") {
			var d int
			fmt.Sscanf(p.Duration, "%d", &d)
			totalDuration += d
		}
	}
	sb.WriteString(fmt.Sprintf("Estimated total duration: %d business days\n\n", totalDuration))

	// Pre-audit health
	if s.AuditReport != nil {
		sb.WriteString("--- PRE-AUDIT HEALTH CHECK ---\n\n")
		sb.WriteString(s.AuditReport.Summary())
	}

	sb.WriteString("\n--- END OF SCOPE DOCUMENT ---\n")
	return sb.String()
}

// ---------------------------------------------------------------------------
// Component statistics
// ---------------------------------------------------------------------------

// ComponentStats returns aggregate statistics about the audit scope.
type ComponentStats struct {
	TotalComponents     int
	HighCriticality     int
	MediumCriticality   int
	LowCriticality      int
	TotalLOC            int
	WithTests           int
	WithoutTests        int
	CoveragePercent     float64
	UniqueModules       int
	TotalThreatModelRefs int
}

// Stats computes aggregate statistics from the scope.
func (s *AuditScope) Stats() ComponentStats {
	stats := ComponentStats{
		TotalComponents: len(s.Components),
	}

	modules := make(map[string]bool)
	threatRefs := make(map[string]bool)

	for _, c := range s.Components {
		modules[c.Module] = true
		switch c.Criticality {
		case CriticalityHigh:
			stats.HighCriticality++
		case CriticalityMedium:
			stats.MediumCriticality++
		case CriticalityLow:
			stats.LowCriticality++
		}
		stats.TotalLOC += c.LOCEstimate
		if c.HasTests {
			stats.WithTests++
		} else {
			stats.WithoutTests++
		}
		for _, ref := range c.ThreatModelRefs {
			threatRefs[ref] = true
		}
	}

	stats.UniqueModules = len(modules)
	stats.TotalThreatModelRefs = len(threatRefs)

	if stats.TotalComponents > 0 {
		stats.CoveragePercent = float64(stats.WithTests) / float64(stats.TotalComponents) * 100.0
	}

	return stats
}

// ---------------------------------------------------------------------------
// Auditor interface: finding submission
// ---------------------------------------------------------------------------

// AuditorFinding is a structured finding submitted by an external auditor.
// It extends AuditFinding with auditor-specific metadata.
type AuditorFinding struct {
	AuditFinding

	// Auditor metadata
	AuditorName    string // Name of the auditor or firm
	AuditorID      string // Auditor engagement identifier
	SubmittedAt    string // RFC3339 timestamp
	ComponentID    string // Which component this finding relates to
	ThreatModelRef string // Which attack surface this relates to (if any)

	// Verification
	ReproduciblePOC string // Steps to reproduce (if applicable)
	CVSSScore       float64 // CVSS v3.1 score (0-10)
	CWEReference    string  // CWE identifier (e.g., "CWE-190")
}

// ValidateAuditorFinding checks that an auditor finding has all required fields.
func ValidateAuditorFinding(f *AuditorFinding) error {
	if f.ID == "" {
		return fmt.Errorf("finding ID is required")
	}
	if f.CheckName == "" {
		return fmt.Errorf("finding check name is required")
	}
	if f.Severity == "" {
		return fmt.Errorf("finding severity is required")
	}
	if f.Description == "" {
		return fmt.Errorf("finding description is required")
	}
	if f.AuditorName == "" {
		return fmt.Errorf("auditor name is required")
	}
	if f.ComponentID == "" {
		return fmt.Errorf("component ID is required")
	}

	// Validate severity
	switch f.Severity {
	case FindingCritical, FindingHigh, FindingMedium, FindingLow, FindingInfo:
		// valid
	default:
		return fmt.Errorf("invalid severity: %s", f.Severity)
	}

	// Validate CVSS range
	if f.CVSSScore < 0 || f.CVSSScore > 10 {
		return fmt.Errorf("CVSS score must be 0-10, got %f", f.CVSSScore)
	}

	// Validate component reference exists
	found := false
	for _, c := range ModuleComponents() {
		if c.ID == f.ComponentID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("unknown component ID: %s", f.ComponentID)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Engagement checklist
// ---------------------------------------------------------------------------

// EngagementChecklistItem is a single item in the pre-audit checklist.
type EngagementChecklistItem struct {
	ID          string
	Category    string
	Description string
	Required    bool
	Completed   bool
}

// EngagementChecklist returns the pre-audit preparation checklist.
// Each item must be completed (or explicitly waived) before the audit begins.
func EngagementChecklist(scope *AuditScope) []EngagementChecklistItem {
	items := []EngagementChecklistItem{
		{ID: "CL-01", Category: "access", Description: "Auditor has read access to private repository", Required: true},
		{ID: "CL-02", Category: "access", Description: "Auditor has access to CI/CD artifacts and test results", Required: true},
		{ID: "CL-03", Category: "access", Description: "Auditor has access to local testnet setup scripts", Required: true},
		{ID: "CL-04", Category: "documentation", Description: "Architecture documentation provided", Required: true},
		{ID: "CL-05", Category: "documentation", Description: "Threat model document provided", Required: true},
		{ID: "CL-06", Category: "documentation", Description: "Scope document signed by both parties", Required: true},
		{ID: "CL-07", Category: "documentation", Description: "Previous audit reports provided (if any)", Required: false},
		{ID: "CL-08", Category: "environment", Description: "Local testnet can be spun up by auditor", Required: true},
		{ID: "CL-09", Category: "environment", Description: "All tests pass on auditor's environment", Required: true},
		{ID: "CL-10", Category: "environment", Description: "Go toolchain and dependencies installed", Required: true},
		{ID: "CL-11", Category: "state", Description: "Pre-audit security audit runner passes", Required: true},
		{ID: "CL-12", Category: "state", Description: "All module invariants pass", Required: true},
		{ID: "CL-13", Category: "state", Description: "No critical findings in pre-audit health check", Required: true},
		{ID: "CL-14", Category: "state", Description: "Module consensus version confirmed", Required: true},
		{ID: "CL-15", Category: "contact", Description: "Primary technical contact identified", Required: true},
		{ID: "CL-16", Category: "contact", Description: "Secure communication channel established", Required: true},
		{ID: "CL-17", Category: "contact", Description: "Responsible disclosure policy agreed upon", Required: true},
	}

	// Auto-complete state checks based on scope data
	if scope != nil && scope.AuditReport != nil {
		for i := range items {
			switch items[i].ID {
			case "CL-11":
				items[i].Completed = scope.AuditReport.CriticalCount == 0
			case "CL-12":
				// Check if invariant finding passed
				for _, f := range scope.AuditReport.Findings {
					if f.ID == "INV-01" && f.Passed {
						items[i].Completed = true
					}
				}
			case "CL-13":
				items[i].Completed = scope.AuditReport.CriticalCount == 0
			case "CL-14":
				items[i].Completed = scope.ModuleVersion > 0
			}
		}
	}

	return items
}

// ChecklistComplete returns true if all required checklist items are completed.
func ChecklistComplete(items []EngagementChecklistItem) bool {
	for _, item := range items {
		if item.Required && !item.Completed {
			return false
		}
	}
	return true
}

// RenderChecklist produces a human-readable checklist summary.
func RenderChecklist(items []EngagementChecklistItem) string {
	var sb strings.Builder
	sb.WriteString("--- PRE-AUDIT ENGAGEMENT CHECKLIST ---\n\n")

	categories := []string{"access", "documentation", "environment", "state", "contact"}
	for _, cat := range categories {
		sb.WriteString(fmt.Sprintf("[%s]\n", strings.ToUpper(cat)))
		for _, item := range items {
			if item.Category != cat {
				continue
			}
			status := "[ ]"
			if item.Completed {
				status = "[x]"
			}
			req := ""
			if item.Required {
				req = " (required)"
			}
			sb.WriteString(fmt.Sprintf("  %s %s: %s%s\n", status, item.ID, item.Description, req))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
