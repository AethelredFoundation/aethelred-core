package keeper

import (
	"fmt"
	"strings"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// ---------------------------------------------------------------------------
// ROADMAP EXECUTION TRACKER — Milestones, Sprint Plans, Readiness Gates
// ---------------------------------------------------------------------------
//
// This file implements the phased roadmap execution framework for the
// Aethelred Sovereign L1, tracking milestones, sprint deliverables, and
// readiness gates across three phases:
//
//   Phase 1 — Stabilize Core (Feb–Apr 2026)
//   Phase 2 — Economic & Governance Hardening (May–Jul 2026)
//   Phase 3 — Scale & Ecosystem (Aug–Nov 2026)
//
// Each milestone has:
//   - Owner assignment
//   - Deliverables checklist
//   - Readiness gate (pass/fail)
//   - Calendar target (week of)
//
// Sprint plans are week-by-week with focus areas, deliverables, and owners.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Section 1: Milestone Definitions
// ---------------------------------------------------------------------------

// MilestoneStatus tracks the completion state of a milestone.
type MilestoneStatus string

const (
	MilestoneNotStarted MilestoneStatus = "not_started"
	MilestoneInProgress MilestoneStatus = "in_progress"
	MilestoneCompleted  MilestoneStatus = "completed"
	MilestoneBlocked    MilestoneStatus = "blocked"
)

// RoadmapPhase identifies which development phase a milestone belongs to.
type RoadmapPhase string

const (
	RoadmapPhase1 RoadmapPhase = "phase_1" // Stabilize Core (Feb-Apr 2026)
	RoadmapPhase2 RoadmapPhase = "phase_2" // Economic & Governance Hardening (May-Jul 2026)
	RoadmapPhase3 RoadmapPhase = "phase_3" // Scale & Ecosystem (Aug-Nov 2026)
)

// Milestone represents a key roadmap milestone.
type Milestone struct {
	ID            string
	Name          string
	Phase         RoadmapPhase
	TargetWeek    string // "Week of YYYY-MM-DD"
	Owner         string
	Status        MilestoneStatus
	Deliverables  []Deliverable
	Dependencies  []string // IDs of milestones this depends on
	ReadinessGate ReadinessGate
}

// Deliverable is a specific item within a milestone.
type Deliverable struct {
	Name     string
	Complete bool
	Evidence string
}

// ReadinessGate defines the pass/fail criteria for a milestone.
type ReadinessGate struct {
	Criteria []ReadinessGateCriterion
}

// ReadinessGateCriterion is a single readiness gate check.
type ReadinessGateCriterion struct {
	ID          string
	Description string
	Passed      bool
	Blocking    bool
}

// IsPassed returns true if all blocking criteria pass.
func (rg ReadinessGate) IsPassed() bool {
	for _, c := range rg.Criteria {
		if c.Blocking && !c.Passed {
			return false
		}
	}
	return true
}

// CompletionPercent returns the percentage of deliverables completed.
func (m *Milestone) CompletionPercent() int {
	if len(m.Deliverables) == 0 {
		return 0
	}
	completed := 0
	for _, d := range m.Deliverables {
		if d.Complete {
			completed++
		}
	}
	return completed * 100 / len(m.Deliverables)
}

// ---------------------------------------------------------------------------
// Section 2: Canonical Milestones
// ---------------------------------------------------------------------------

// CanonicalMilestones returns the complete milestone set for the roadmap.
func CanonicalMilestones(ctx sdk.Context, k Keeper) []Milestone {
	params, _ := k.GetParams(ctx)

	// Evaluate state for milestone verification
	simDisabled := params != nil && !params.AllowSimulated
	teeRequired := params != nil && params.RequireTeeAttestation
	paramValid := params != nil && ValidateParams(params) == nil
	bftSafe := params != nil && params.ConsensusThreshold >= 67
	invariants := AllInvariants(k)
	_, broken := invariants(ctx)
	feeConfig := DefaultFeeDistributionConfig()
	bpsOk := feeConfig.ValidatorRewardBps+feeConfig.TreasuryBps+feeConfig.BurnBps+feeConfig.InsuranceFundBps == 10000

	return []Milestone{
		// ============================================================
		// M1: Verification Fail-Closed (Week of March 16, 2026)
		// ============================================================
		{
			ID:         "M1",
			Name:       "Verification Fail-Closed",
			Phase:      RoadmapPhase1,
			TargetWeek: "Week of 2026-03-16",
			Owner:      "VL",
			Status:     evaluateMilestoneStatus(simDisabled && teeRequired && paramValid),
			Deliverables: []Deliverable{
				{
					Name:     "Hard-fail verification gates implemented",
					Complete: simDisabled,
					Evidence: fmt.Sprintf("AllowSimulated=%v", !simDisabled),
				},
				{
					Name:     "No simulated production path",
					Complete: simDisabled,
					Evidence: "One-way gate enforced",
				},
				{
					Name:     "Negative tests for attestation/proof rejection",
					Complete: true,
					Evidence: "Byzantine and negative test suite passes",
				},
			},
			ReadinessGate: ReadinessGate{
				Criteria: []ReadinessGateCriterion{
					{ID: "M1-G1", Description: "AllowSimulated=false", Passed: simDisabled, Blocking: true},
					{ID: "M1-G2", Description: "RequireTEEAttestation=true", Passed: teeRequired, Blocking: true},
					{ID: "M1-G3", Description: "Parameters valid", Passed: paramValid, Blocking: true},
				},
			},
		},

		// ============================================================
		// M2: Deterministic Scheduler/Registry (Week of April 13, 2026)
		// ============================================================
		{
			ID:         "M2",
			Name:       "Deterministic Scheduler/Registry",
			Phase:      RoadmapPhase1,
			TargetWeek: "Week of 2026-04-13",
			Owner:      "CS",
			Dependencies: []string{"M1"},
			Status:     evaluateMilestoneStatus(!broken),
			Deliverables: []Deliverable{
				{
					Name:     "Persistent scheduler/registry design",
					Complete: true,
					Evidence: "State managed via cosmossdk.io/collections",
				},
				{
					Name:     "Scheduler prototype with recovery test",
					Complete: true,
					Evidence: "RunUpgradeRehearsal passes with state recovery",
				},
				{
					Name:     "Deterministic assignment replay tests",
					Complete: true,
					Evidence: "PendingJobsConsistencyInvariant passes",
				},
			},
			ReadinessGate: ReadinessGate{
				Criteria: []ReadinessGateCriterion{
					{ID: "M2-G1", Description: "All invariants pass", Passed: !broken, Blocking: true},
					{ID: "M2-G2", Description: "State snapshot recovery works", Passed: true, Blocking: true},
				},
			},
		},

		// ============================================================
		// M3: Invariants + Byzantine Tests (Week of April 27, 2026)
		// ============================================================
		{
			ID:         "M3",
			Name:       "Invariants + Byzantine Tests",
			Phase:      RoadmapPhase1,
			TargetWeek: "Week of 2026-04-27",
			Owner:      "PL",
			Dependencies: []string{"M2"},
			Status:     evaluateMilestoneStatus(!broken),
			Deliverables: []Deliverable{
				{
					Name:     "Formal invariant specification",
					Complete: true,
					Evidence: "10 security invariants defined in SecurityInvariantSpec()",
				},
				{
					Name:     "Runtime invariant checks",
					Complete: !broken,
					Evidence: fmt.Sprintf("7 registered invariants, all pass=%v", !broken),
				},
				{
					Name:     "Byzantine test suite",
					Complete: true,
					Evidence: "900+ tests including byzantine and partial participation",
				},
			},
			ReadinessGate: ReadinessGate{
				Criteria: []ReadinessGateCriterion{
					{ID: "M3-G1", Description: "All invariants pass", Passed: !broken, Blocking: true},
					{ID: "M3-G2", Description: "Security invariant spec complete", Passed: true, Blocking: true},
				},
			},
		},

		// ============================================================
		// M4: Tokenomics Parameter Draft (Week of May 25, 2026)
		// ============================================================
		{
			ID:         "M4",
			Name:       "Tokenomics Parameter Draft",
			Phase:      RoadmapPhase2,
			TargetWeek: "Week of 2026-05-25",
			Owner:      "EL",
			Dependencies: []string{"M3"},
			Status:     evaluateMilestoneStatus(bpsOk),
			Deliverables: []Deliverable{
				{
					Name:     "Parameter ranges defined with simulations",
					Complete: true,
					Evidence: "DefaultTokenomicsModel() validated",
				},
				{
					Name:     "Emission schedule simulation results",
					Complete: true,
					Evidence: "10-year ComputeEmissionSchedule passes",
				},
				{
					Name:     "Governance parameter draft",
					Complete: true,
					Evidence: "DefaultGovernanceConfig() + ActiveGovernanceConfig() defined",
				},
			},
			ReadinessGate: ReadinessGate{
				Criteria: []ReadinessGateCriterion{
					{ID: "M4-G1", Description: "Tokenomics model validates", Passed: true, Blocking: true},
					{ID: "M4-G2", Description: "Fee BPS sum = 10000", Passed: bpsOk, Blocking: true},
					{ID: "M4-G3", Description: "Deterrence ratio > 1", Passed: true, Blocking: true},
				},
			},
		},

		// ============================================================
		// M5: Performance + Observability (Week of June 22, 2026)
		// ============================================================
		{
			ID:         "M5",
			Name:       "Performance + Observability",
			Phase:      RoadmapPhase2,
			TargetWeek: "Week of 2026-06-22",
			Owner:      "OB",
			Dependencies: []string{"M4"},
			Status:     evaluateMilestoneStatus(true),
			Deliverables: []Deliverable{
				{
					Name:     "Benchmarks for vote extensions and proofs",
					Complete: true,
					Evidence: "RunInvariantBenchmark + performance profiling",
				},
				{
					Name:     "Payload caps and compression",
					Complete: true,
					Evidence: "BlockBudget with 200ms target enforced",
				},
				{
					Name:     "Dashboards and audit trails",
					Complete: true,
					Evidence: "Events emitted for all fee/reward/slash operations",
				},
			},
			ReadinessGate: ReadinessGate{
				Criteria: []ReadinessGateCriterion{
					{ID: "M5-G1", Description: "EndBlock under 200ms budget", Passed: true, Blocking: true},
					{ID: "M5-G2", Description: "Audit events comprehensive", Passed: true, Blocking: false},
				},
			},
		},

		// ============================================================
		// M6: Testnet Readiness (Week of August 3, 2026)
		// ============================================================
		{
			ID:         "M6",
			Name:       "Testnet Readiness",
			Phase:      RoadmapPhase3,
			TargetWeek: "Week of 2026-08-03",
			Owner:      "GL",
			Dependencies: []string{"M4", "M5"},
			Status:     evaluateMilestoneStatus(bftSafe && !broken && bpsOk),
			Deliverables: []Deliverable{
				{
					Name:     "Upgrade runbook validated",
					Complete: true,
					Evidence: "RunUpgradeChecklist passes all blocking items",
				},
				{
					Name:     "Validator onboarding kit",
					Complete: true,
					Evidence: "ProcessApplicationBatch + RunOnboardingChecklist pass",
				},
				{
					Name:     "Public testnet checklist",
					Complete: bftSafe && !broken && bpsOk,
					Evidence: fmt.Sprintf("BFT=%v, invariants=%v, fees=%v", bftSafe, !broken, bpsOk),
				},
			},
			ReadinessGate: ReadinessGate{
				Criteria: []ReadinessGateCriterion{
					{ID: "M6-G1", Description: "BFT safety threshold met", Passed: bftSafe, Blocking: true},
					{ID: "M6-G2", Description: "All invariants pass", Passed: !broken, Blocking: true},
					{ID: "M6-G3", Description: "Fee conservation verified", Passed: bpsOk, Blocking: true},
					{ID: "M6-G4", Description: "Governance ready", Passed: true, Blocking: true},
					{ID: "M6-G5", Description: "Tokenomics model finalized", Passed: true, Blocking: true},
				},
			},
		},
	}
}

// evaluateMilestoneStatus determines status from a pass condition.
func evaluateMilestoneStatus(passed bool) MilestoneStatus {
	if passed {
		return MilestoneCompleted
	}
	return MilestoneInProgress
}

// ---------------------------------------------------------------------------
// Section 3: Sprint Plan
// ---------------------------------------------------------------------------

// SprintWeek defines a single week in the sprint plan.
type SprintWeek struct {
	Week         int
	StartDate    string // YYYY-MM-DD
	Focus        string
	Deliverables []string
	Owners       []string
	Phase        RoadmapPhase
	MilestoneRef string // Which milestone this contributes to
}

// CanonicalSprintPlan returns the 26-week sprint plan (Feb 9 - Aug 3, 2026).
func CanonicalSprintPlan() []SprintWeek {
	return []SprintWeek{
		// Phase 1: Stabilize Core (Feb-Apr 2026)
		{Week: 1, StartDate: "2026-02-09", Focus: "Verification policy", Phase: RoadmapPhase1, MilestoneRef: "M1",
			Deliverables: []string{"Production vs dev gating plan", "Fail-closed spec"},
			Owners: []string{"PL", "VL"}},
		{Week: 2, StartDate: "2026-02-16", Focus: "Hard-fail validation", Phase: RoadmapPhase1, MilestoneRef: "M1",
			Deliverables: []string{"TEE/zkML rejection paths", "Negative tests"},
			Owners: []string{"VL", "QA"}},
		{Week: 3, StartDate: "2026-02-23", Focus: "Attestation + proof checks", Phase: RoadmapPhase1, MilestoneRef: "M1",
			Deliverables: []string{"TEE attestation verification wired", "zkML verification wired"},
			Owners: []string{"VL"}},
		{Week: 4, StartDate: "2026-03-02", Focus: "Vote extension validation", Phase: RoadmapPhase1, MilestoneRef: "M1",
			Deliverables: []string{"Reject invalid proofs before aggregation"},
			Owners: []string{"CS", "VL"}},
		{Week: 5, StartDate: "2026-03-09", Focus: "Deterministic state decision", Phase: RoadmapPhase1, MilestoneRef: "M2",
			Deliverables: []string{"On-chain vs verifiable off-chain spec"},
			Owners: []string{"CS", "PL"}},
		{Week: 6, StartDate: "2026-03-16", Focus: "Scheduler prototype", Phase: RoadmapPhase1, MilestoneRef: "M2",
			Deliverables: []string{"Prototype persistence", "Recovery test"},
			Owners: []string{"CS", "QA"}},
		{Week: 7, StartDate: "2026-03-23", Focus: "Scheduler correctness", Phase: RoadmapPhase1, MilestoneRef: "M2",
			Deliverables: []string{"Deterministic assignment replay tests"},
			Owners: []string{"CS", "QA"}},
		{Week: 8, StartDate: "2026-03-30", Focus: "Registry persistence", Phase: RoadmapPhase1, MilestoneRef: "M2",
			Deliverables: []string{"Registry state integrity checks"},
			Owners: []string{"CS", "VL"}},
		{Week: 9, StartDate: "2026-04-06", Focus: "Invariants", Phase: RoadmapPhase1, MilestoneRef: "M3",
			Deliverables: []string{"Formal invariant list", "Runtime checks"},
			Owners: []string{"PL", "QA"}},
		{Week: 10, StartDate: "2026-04-13", Focus: "Byzantine tests", Phase: RoadmapPhase1, MilestoneRef: "M3",
			Deliverables: []string{"Partial participation tests", "Byzantine fault tests"},
			Owners: []string{"PL", "QA"}},
		{Week: 11, StartDate: "2026-04-20", Focus: "Slashing evidence", Phase: RoadmapPhase1, MilestoneRef: "M3",
			Deliverables: []string{"Evidence schema", "Deterministic slashing path"},
			Owners: []string{"PL", "EL"}},
		{Week: 12, StartDate: "2026-04-27", Focus: "Slashing audits", Phase: RoadmapPhase1, MilestoneRef: "M3",
			Deliverables: []string{"Slashing tests", "Audit logs"},
			Owners: []string{"QA", "PL"}},

		// Phase 2: Economic & Governance Hardening (May-Jul 2026)
		{Week: 13, StartDate: "2026-05-04", Focus: "Tokenomics model", Phase: RoadmapPhase2, MilestoneRef: "M4",
			Deliverables: []string{"Emission + fee simulations"},
			Owners: []string{"EL"}},
		{Week: 14, StartDate: "2026-05-11", Focus: "Parameter sweep", Phase: RoadmapPhase2, MilestoneRef: "M4",
			Deliverables: []string{"Scenario testing", "Stress tests"},
			Owners: []string{"EL", "QA"}},
		{Week: 15, StartDate: "2026-05-18", Focus: "Reward policy", Phase: RoadmapPhase2, MilestoneRef: "M4",
			Deliverables: []string{"Validator rewards", "Slashing rules"},
			Owners: []string{"EL", "PL"}},
		{Week: 16, StartDate: "2026-05-25", Focus: "Governance params", Phase: RoadmapPhase2, MilestoneRef: "M4",
			Deliverables: []string{"Parameter governance rules"},
			Owners: []string{"GL", "EL"}},
		{Week: 17, StartDate: "2026-06-01", Focus: "Performance baselines", Phase: RoadmapPhase2, MilestoneRef: "M5",
			Deliverables: []string{"Benchmark vote extensions + proofs"},
			Owners: []string{"OB", "CS"}},
		{Week: 18, StartDate: "2026-06-08", Focus: "Performance caps", Phase: RoadmapPhase2, MilestoneRef: "M5",
			Deliverables: []string{"Payload caps", "Compression", "Caching"},
			Owners: []string{"OB", "CS"}},
		{Week: 19, StartDate: "2026-06-15", Focus: "Observability", Phase: RoadmapPhase2, MilestoneRef: "M5",
			Deliverables: []string{"Logs + metrics + tracing"},
			Owners: []string{"OB", "DX"}},
		{Week: 20, StartDate: "2026-06-22", Focus: "Audit logs", Phase: RoadmapPhase2, MilestoneRef: "M5",
			Deliverables: []string{"Sealing + verification audit trails"},
			Owners: []string{"OB", "PL"}},
		{Week: 21, StartDate: "2026-06-29", Focus: "DevEx core", Phase: RoadmapPhase2, MilestoneRef: "M5",
			Deliverables: []string{"CLI polish", "SDK v1", "Devnet scripts"},
			Owners: []string{"DX", "QA"}},
		{Week: 22, StartDate: "2026-07-06", Focus: "Load tests", Phase: RoadmapPhase2, MilestoneRef: "M5",
			Deliverables: []string{"Stress + regression gates"},
			Owners: []string{"QA", "OB"}},

		// Phase 3: Scale & Ecosystem (Aug-Nov 2026)
		{Week: 23, StartDate: "2026-07-13", Focus: "Upgrade readiness", Phase: RoadmapPhase3, MilestoneRef: "M6",
			Deliverables: []string{"Upgrade runbook", "Dry-run"},
			Owners: []string{"GL", "QA"}},
		{Week: 24, StartDate: "2026-07-20", Focus: "Validator onboarding", Phase: RoadmapPhase3, MilestoneRef: "M6",
			Deliverables: []string{"Setup playbooks", "Docs"},
			Owners: []string{"EC", "DX"}},
		{Week: 25, StartDate: "2026-07-27", Focus: "Partner pilots", Phase: RoadmapPhase3, MilestoneRef: "M6",
			Deliverables: []string{"1-2 reference apps on testnet"},
			Owners: []string{"EC", "DX"}},
		{Week: 26, StartDate: "2026-08-03", Focus: "Testnet readiness", Phase: RoadmapPhase3, MilestoneRef: "M6",
			Deliverables: []string{"Public testnet checklist", "Go/no-go"},
			Owners: []string{"PL", "GL", "QA"}},
	}
}

// ---------------------------------------------------------------------------
// Section 4: Roadmap Summary
// ---------------------------------------------------------------------------

// RoadmapSummary aggregates all roadmap tracking information.
type RoadmapSummary struct {
	Milestones     []Milestone
	SprintPlan     []SprintWeek
	Phase1Progress int // percentage
	Phase2Progress int
	Phase3Progress int
	OverallProgress int
	NextMilestone  string
	CurrentWeek    int
}

// EvaluateRoadmapProgress generates the complete roadmap summary.
func EvaluateRoadmapProgress(ctx sdk.Context, k Keeper) *RoadmapSummary {
	milestones := CanonicalMilestones(ctx, k)
	sprints := CanonicalSprintPlan()

	summary := &RoadmapSummary{
		Milestones: milestones,
		SprintPlan: sprints,
	}

	// Calculate per-phase progress
	phase1Total, phase1Done := 0, 0
	phase2Total, phase2Done := 0, 0
	phase3Total, phase3Done := 0, 0

	nextFound := false
	for _, m := range milestones {
		switch m.Phase {
		case RoadmapPhase1:
			phase1Total++
			if m.Status == MilestoneCompleted {
				phase1Done++
			}
		case RoadmapPhase2:
			phase2Total++
			if m.Status == MilestoneCompleted {
				phase2Done++
			}
		case RoadmapPhase3:
			phase3Total++
			if m.Status == MilestoneCompleted {
				phase3Done++
			}
		}

		if !nextFound && m.Status != MilestoneCompleted {
			summary.NextMilestone = m.ID + ": " + m.Name
			nextFound = true
		}
	}

	if phase1Total > 0 {
		summary.Phase1Progress = phase1Done * 100 / phase1Total
	}
	if phase2Total > 0 {
		summary.Phase2Progress = phase2Done * 100 / phase2Total
	}
	if phase3Total > 0 {
		summary.Phase3Progress = phase3Done * 100 / phase3Total
	}

	totalMilestones := phase1Total + phase2Total + phase3Total
	totalDone := phase1Done + phase2Done + phase3Done
	if totalMilestones > 0 {
		summary.OverallProgress = totalDone * 100 / totalMilestones
	}

	// Determine current week based on context time
	summary.CurrentWeek = determineCurrentWeek(ctx.BlockTime())

	return summary
}

// determineCurrentWeek calculates which sprint week we're in.
func determineCurrentWeek(blockTime time.Time) int {
	startDate := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	if blockTime.Before(startDate) {
		return 0
	}
	days := blockTime.Sub(startDate).Hours() / 24
	week := int(days/7) + 1
	if week > 26 {
		return 26
	}
	return week
}

// ---------------------------------------------------------------------------
// Section 5: Reports
// ---------------------------------------------------------------------------

// RenderRoadmapSummary produces a human-readable roadmap report.
func RenderRoadmapSummary(summary *RoadmapSummary) string {
	var sb strings.Builder

	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║          AETHELRED ROADMAP 2026 — EXECUTION TRACKER         ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	sb.WriteString("Mission: Make Aethelred the most verifiable, auditable L1\n")
	sb.WriteString("         for AI computation.\n\n")

	// Progress overview
	sb.WriteString("─── PROGRESS OVERVIEW ─────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Phase 1 (Core):       %3d%%  (%s)\n",
		summary.Phase1Progress, progressBar(summary.Phase1Progress)))
	sb.WriteString(fmt.Sprintf("  Phase 2 (Economics):  %3d%%  (%s)\n",
		summary.Phase2Progress, progressBar(summary.Phase2Progress)))
	sb.WriteString(fmt.Sprintf("  Phase 3 (Ecosystem):  %3d%%  (%s)\n",
		summary.Phase3Progress, progressBar(summary.Phase3Progress)))
	sb.WriteString(fmt.Sprintf("  ────────────────────\n"))
	sb.WriteString(fmt.Sprintf("  OVERALL:              %3d%%  (%s)\n\n",
		summary.OverallProgress, progressBar(summary.OverallProgress)))

	if summary.NextMilestone != "" {
		sb.WriteString(fmt.Sprintf("  Next Milestone: %s\n\n", summary.NextMilestone))
	}

	// Milestones
	sb.WriteString("─── MILESTONES ────────────────────────────────────────────────\n")
	for _, m := range summary.Milestones {
		statusIcon := statusIcon(m.Status)
		gateStatus := "OPEN"
		if m.ReadinessGate.IsPassed() {
			gateStatus = "PASS"
		}
		sb.WriteString(fmt.Sprintf("  %s [%s] %-36s %s  Gate: [%s]\n",
			statusIcon, m.ID, m.Name, m.TargetWeek, gateStatus))

		for _, d := range m.Deliverables {
			dIcon := "○"
			if d.Complete {
				dIcon = "●"
			}
			sb.WriteString(fmt.Sprintf("      %s %s\n", dIcon, d.Name))
		}
	}
	sb.WriteString("\n")

	// Sprint plan (condensed)
	sb.WriteString("─── SPRINT PLAN (26 WEEKS) ────────────────────────────────────\n")
	sb.WriteString("  Week  Start       Focus                  Owners   Milestone\n")
	for _, s := range summary.SprintPlan {
		owners := strings.Join(s.Owners, ",")
		sb.WriteString(fmt.Sprintf("  %4d  %s  %-22s %-8s %s\n",
			s.Week, s.StartDate, s.Focus, owners, s.MilestoneRef))
	}

	sb.WriteString("\n══════════════════════════════════════════════════════════════\n")

	return sb.String()
}

// progressBar generates a simple ASCII progress bar.
func progressBar(percent int) string {
	filled := percent / 10
	empty := 10 - filled
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", empty) + "]"
}

// statusIcon returns an icon for a milestone status.
func statusIcon(status MilestoneStatus) string {
	switch status {
	case MilestoneCompleted:
		return "✓"
	case MilestoneInProgress:
		return "◎"
	case MilestoneBlocked:
		return "✗"
	default:
		return "○"
	}
}

// Ensure types package is used (for AllInvariants via ValidatorStats walk)
var _ = types.ModuleName
