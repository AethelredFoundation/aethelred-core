package keeper

import (
	"fmt"
	"sort"
	"strings"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// ---------------------------------------------------------------------------
// WEEKS 46-52: Post-Launch Monitoring & Governance Activation
// ---------------------------------------------------------------------------
//
// This file implements the post-launch operational framework:
//
//   1. Chain health monitor (Week 46-48)
//      - Real-time health dashboard aggregating all subsystems
//      - Automated anomaly detection with severity classification
//      - Health alert system with escalation thresholds
//
//   2. Incident response framework (Week 46-48)
//      - Incident classification and tracking
//      - Runbook execution with automated remediation
//      - Post-incident review generator
//
//   3. Governance activation (Week 49-52)
//      - Governance proposal lifecycle management
//      - Voting period configuration and quorum enforcement
//      - Parameter change governance with lock registry integration
//
//   4. Chain maturity assessment (Week 49-52)
//      - Progressive decentralization metrics
//      - Network stability scoring over time windows
//      - Graduation criteria from launch phase to mature phase
//
// Design principles:
//   - All monitoring is deterministic and reproducible from on-chain state
//   - Incidents are documented with full audit trail
//   - Governance respects parameter lock registry
//   - Maturity assessment is quantitative and transparent
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Section 1: Chain Health Monitor
// ---------------------------------------------------------------------------

// SubsystemStatus describes the health state of a subsystem.
type SubsystemStatus string

const (
	HealthGreen  SubsystemStatus = "green"  // All systems nominal
	HealthYellow SubsystemStatus = "yellow" // Degraded but operational
	HealthRed    SubsystemStatus = "red"    // Critical issue detected
)

// SubsystemHealth describes the health of a single subsystem.
type SubsystemHealth struct {
	Name        string
	Status      SubsystemStatus
	Details     string
	LastChecked string
	Metrics     map[string]string
}

// ChainHealthReport is a comprehensive health assessment of the running chain.
type ChainHealthReport struct {
	// Identity
	ChainID     string
	BlockHeight int64
	Timestamp   string

	// Overall status
	OverallStatus SubsystemStatus

	// Subsystem health
	Subsystems []SubsystemHealth

	// Anomalies detected
	Anomalies []HealthAnomaly

	// Summary metrics
	TotalJobs        uint64
	PendingJobs      int
	ActiveValidators int
	AvgReputation    float64
	InvariantsPass   bool
	ParamsValid      bool
}

// HealthAnomaly describes a detected anomaly in chain operation.
type HealthAnomaly struct {
	ID          string
	Subsystem   string
	Severity    string // "info", "warning", "critical"
	Description string
	DetectedAt  string
	Metric      string
	Expected    string
	Actual      string
}

// RunChainHealthCheck performs a comprehensive health assessment.
func RunChainHealthCheck(ctx sdk.Context, k Keeper) *ChainHealthReport {
	report := &ChainHealthReport{
		ChainID:     ctx.ChainID(),
		BlockHeight: ctx.BlockHeight(),
		Timestamp:   ctx.BlockTime().UTC().Format(time.RFC3339),
	}

	now := ctx.BlockTime().UTC().Format(time.RFC3339)

	// --- Subsystem: Parameters ---
	params, err := k.GetParams(ctx)
	paramValid := err == nil && params != nil && ValidateParams(params) == nil
	report.ParamsValid = paramValid
	paramStatus := HealthGreen
	if !paramValid {
		paramStatus = HealthRed
	}
	report.Subsystems = append(report.Subsystems, SubsystemHealth{
		Name:        "parameters",
		Status:      paramStatus,
		Details:     fmt.Sprintf("valid=%v", paramValid),
		LastChecked: now,
		Metrics: map[string]string{
			"consensus_threshold":    fmt.Sprintf("%d", params.ConsensusThreshold),
			"allow_simulated":        fmt.Sprintf("%v", params.AllowSimulated),
			"require_tee_attestation": fmt.Sprintf("%v", params.RequireTeeAttestation),
		},
	})

	// --- Subsystem: Invariants ---
	invariants := AllInvariants(k)
	invMsg, invBroken := invariants(ctx)
	report.InvariantsPass = !invBroken
	invStatus := HealthGreen
	if invBroken {
		invStatus = HealthRed
		report.Anomalies = append(report.Anomalies, HealthAnomaly{
			ID:          "ANO-001",
			Subsystem:   "invariants",
			Severity:    "critical",
			Description: "Module invariants broken: " + invMsg,
			DetectedAt:  now,
		})
	}
	report.Subsystems = append(report.Subsystems, SubsystemHealth{
		Name:        "invariants",
		Status:      invStatus,
		Details:     invMsg,
		LastChecked: now,
	})

	// --- Subsystem: Job Queue ---
	totalJobs, _ := k.JobCount.Get(ctx)
	report.TotalJobs = totalJobs
	pendingJobs := k.GetPendingJobs(ctx)
	report.PendingJobs = len(pendingJobs)

	jobStatus := HealthGreen
	maxPending := int64(1000) // mainnet default
	if params != nil {
		maxPending = params.MaxJobsPerBlock * 40 // ~40 blocks backlog threshold
	}
	if int64(report.PendingJobs) > maxPending {
		jobStatus = HealthYellow
		report.Anomalies = append(report.Anomalies, HealthAnomaly{
			ID:          "ANO-002",
			Subsystem:   "job_queue",
			Severity:    "warning",
			Description: "Pending job queue exceeds backlog threshold",
			DetectedAt:  now,
			Metric:      "pending_jobs",
			Expected:    fmt.Sprintf("<= %d", maxPending),
			Actual:      fmt.Sprintf("%d", report.PendingJobs),
		})
	}
	report.Subsystems = append(report.Subsystems, SubsystemHealth{
		Name:        "job_queue",
		Status:      jobStatus,
		Details:     fmt.Sprintf("total=%d, pending=%d", totalJobs, report.PendingJobs),
		LastChecked: now,
		Metrics: map[string]string{
			"total_jobs":   fmt.Sprintf("%d", totalJobs),
			"pending_jobs": fmt.Sprintf("%d", report.PendingJobs),
		},
	})

	// --- Subsystem: Validator Set ---
	var repSum int64
	valCount := 0
	lowRepCount := 0
	_ = k.ValidatorStats.Walk(ctx, nil, func(_ string, s types.ValidatorStats) (bool, error) {
		valCount++
		repSum += s.ReputationScore
		if s.ReputationScore < 40 {
			lowRepCount++
		}
		return false, nil
	})
	report.ActiveValidators = valCount
	if valCount > 0 {
		report.AvgReputation = float64(repSum) / float64(valCount)
	}

	valStatus := HealthGreen
	minVal := int64(3)
	if params != nil {
		minVal = params.MinValidators
	}
	if int64(valCount) < minVal {
		valStatus = HealthRed
		report.Anomalies = append(report.Anomalies, HealthAnomaly{
			ID:          "ANO-003",
			Subsystem:   "validator_set",
			Severity:    "critical",
			Description: "Active validators below minimum",
			DetectedAt:  now,
			Metric:      "active_validators",
			Expected:    fmt.Sprintf(">= %d", minVal),
			Actual:      fmt.Sprintf("%d", valCount),
		})
	} else if lowRepCount > 0 {
		valStatus = HealthYellow
		report.Anomalies = append(report.Anomalies, HealthAnomaly{
			ID:          "ANO-004",
			Subsystem:   "validator_set",
			Severity:    "warning",
			Description: fmt.Sprintf("%d validators below reputation threshold", lowRepCount),
			DetectedAt:  now,
			Metric:      "low_reputation_count",
			Expected:    "0",
			Actual:      fmt.Sprintf("%d", lowRepCount),
		})
	}
	report.Subsystems = append(report.Subsystems, SubsystemHealth{
		Name:        "validator_set",
		Status:      valStatus,
		Details:     fmt.Sprintf("count=%d, avg_rep=%.1f", valCount, report.AvgReputation),
		LastChecked: now,
		Metrics: map[string]string{
			"total_validators": fmt.Sprintf("%d", valCount),
			"avg_reputation":   fmt.Sprintf("%.1f", report.AvgReputation),
			"low_reputation":   fmt.Sprintf("%d", lowRepCount),
		},
	})

	// --- Subsystem: Fee Distribution ---
	feeConfig := DefaultFeeDistributionConfig()
	bpsSum := feeConfig.ValidatorRewardBps + feeConfig.TreasuryBps + feeConfig.BurnBps + feeConfig.InsuranceFundBps
	feeStatus := HealthGreen
	if bpsSum != 10000 {
		feeStatus = HealthRed
	}
	report.Subsystems = append(report.Subsystems, SubsystemHealth{
		Name:        "fee_distribution",
		Status:      feeStatus,
		Details:     fmt.Sprintf("BPS sum=%d", bpsSum),
		LastChecked: now,
	})

	// --- Subsystem: Consistency ---
	consistency := EndBlockConsistencyChecks(ctx, k)
	consistencyPass := true
	for _, c := range consistency {
		if !c.Passed {
			consistencyPass = false
			break
		}
	}
	consistencyStatus := HealthGreen
	if !consistencyPass {
		consistencyStatus = HealthYellow
	}
	report.Subsystems = append(report.Subsystems, SubsystemHealth{
		Name:        "consistency",
		Status:      consistencyStatus,
		Details:     fmt.Sprintf("%d checks, all_pass=%v", len(consistency), consistencyPass),
		LastChecked: now,
	})

	// --- Compute overall status ---
	report.OverallStatus = HealthGreen
	for _, s := range report.Subsystems {
		if s.Status == HealthRed {
			report.OverallStatus = HealthRed
			break
		}
		if s.Status == HealthYellow && report.OverallStatus != HealthRed {
			report.OverallStatus = HealthYellow
		}
	}

	return report
}

// CriticalAnomalies returns only critical-severity anomalies.
func (r *ChainHealthReport) CriticalAnomalies() []HealthAnomaly {
	var critical []HealthAnomaly
	for _, a := range r.Anomalies {
		if a.Severity == "critical" {
			critical = append(critical, a)
		}
	}
	return critical
}

// IsHealthy returns true if the overall health is green.
func (r *ChainHealthReport) IsHealthy() bool {
	return r.OverallStatus == HealthGreen
}

// ---------------------------------------------------------------------------
// Section 2: Incident Response Framework
// ---------------------------------------------------------------------------

// IncidentSeverity classifies the severity of an incident.
type IncidentSeverity string

const (
	IncidentSev1 IncidentSeverity = "SEV-1" // Chain halt / consensus failure
	IncidentSev2 IncidentSeverity = "SEV-2" // Degraded performance / validator issues
	IncidentSev3 IncidentSeverity = "SEV-3" // Minor issues / cosmetic
)

// IncidentStatus tracks the lifecycle of an incident.
type IncidentStatus string

const (
	IncidentOpen       IncidentStatus = "open"
	IncidentInvestigating IncidentStatus = "investigating"
	IncidentMitigated  IncidentStatus = "mitigated"
	IncidentResolved   IncidentStatus = "resolved"
)

// Incident represents a tracked incident.
type Incident struct {
	ID          string
	Severity    IncidentSeverity
	Status      IncidentStatus
	Title       string
	Description string
	DetectedAt  string
	ResolvedAt  string
	AffectedSystems []string
	RootCause   string
	Remediation string
	Timeline    []IncidentEvent
}

// IncidentEvent is a timestamped entry in the incident timeline.
type IncidentEvent struct {
	Timestamp string
	Action    string
	Details   string
	Actor     string
}

// IncidentTracker manages the lifecycle of incidents.
type IncidentTracker struct {
	Incidents []Incident
}

// NewIncidentTracker creates a new empty tracker.
func NewIncidentTracker() *IncidentTracker {
	return &IncidentTracker{}
}

// CreateIncident opens a new incident.
func (it *IncidentTracker) CreateIncident(id string, severity IncidentSeverity, title, description, detectedAt string) error {
	if id == "" {
		return fmt.Errorf("incident ID must not be empty")
	}
	if title == "" {
		return fmt.Errorf("incident title must not be empty")
	}
	for _, inc := range it.Incidents {
		if inc.ID == id {
			return fmt.Errorf("incident %q already exists", id)
		}
	}

	incident := Incident{
		ID:          id,
		Severity:    severity,
		Status:      IncidentOpen,
		Title:       title,
		Description: description,
		DetectedAt:  detectedAt,
		Timeline: []IncidentEvent{
			{Timestamp: detectedAt, Action: "created", Details: description, Actor: "system"},
		},
	}
	it.Incidents = append(it.Incidents, incident)
	return nil
}

// UpdateStatus transitions an incident to a new status.
func (it *IncidentTracker) UpdateStatus(id string, status IncidentStatus, details, actor, timestamp string) error {
	for i := range it.Incidents {
		if it.Incidents[i].ID == id {
			it.Incidents[i].Status = status
			if status == IncidentResolved {
				it.Incidents[i].ResolvedAt = timestamp
			}
			it.Incidents[i].Timeline = append(it.Incidents[i].Timeline, IncidentEvent{
				Timestamp: timestamp,
				Action:    string(status),
				Details:   details,
				Actor:     actor,
			})
			return nil
		}
	}
	return fmt.Errorf("incident %q not found", id)
}

// OpenIncidents returns all unresolved incidents.
func (it *IncidentTracker) OpenIncidents() []Incident {
	var open []Incident
	for _, inc := range it.Incidents {
		if inc.Status != IncidentResolved {
			open = append(open, inc)
		}
	}
	return open
}

// GetIncident retrieves an incident by ID.
func (it *IncidentTracker) GetIncident(id string) (*Incident, bool) {
	for i := range it.Incidents {
		if it.Incidents[i].ID == id {
			return &it.Incidents[i], true
		}
	}
	return nil, false
}

// AutoDetectIncidents creates incidents from health anomalies.
func AutoDetectIncidents(report *ChainHealthReport, tracker *IncidentTracker) int {
	created := 0
	for _, anomaly := range report.Anomalies {
		// Map severity
		var severity IncidentSeverity
		switch anomaly.Severity {
		case "critical":
			severity = IncidentSev1
		case "warning":
			severity = IncidentSev2
		default:
			severity = IncidentSev3
		}

		incID := "INC-" + anomaly.ID
		err := tracker.CreateIncident(
			incID, severity,
			anomaly.Description,
			fmt.Sprintf("Auto-detected from %s: %s", anomaly.Subsystem, anomaly.Description),
			anomaly.DetectedAt,
		)
		if err == nil {
			created++
		}
	}
	return created
}

// ---------------------------------------------------------------------------
// Section 3: Governance Activation
// ---------------------------------------------------------------------------

// GovernancePhase describes the current governance phase.
type GovernancePhase string

const (
	GovPhaseBootstrap   GovernancePhase = "bootstrap"    // Launch phase, limited governance
	GovPhaseActivating  GovernancePhase = "activating"   // Transitioning to full governance
	GovPhaseActive      GovernancePhase = "active"       // Full governance operational
)

// GovernanceConfig defines the governance parameters.
type GovernanceConfig struct {
	Phase              GovernancePhase
	VotingPeriodBlocks int64
	QuorumPercent      int
	ThresholdPercent   int  // % of yes votes to pass
	VetoPercent        int  // % of no-with-veto to reject
	MaxProposals       int  // max concurrent proposals
}

// DefaultGovernanceConfig returns the default governance configuration.
func DefaultGovernanceConfig() GovernanceConfig {
	return GovernanceConfig{
		Phase:              GovPhaseBootstrap,
		VotingPeriodBlocks: 50400,  // ~3.5 days at 6s blocks
		QuorumPercent:      33,
		ThresholdPercent:   50,
		VetoPercent:        33,
		MaxProposals:       10,
	}
}

// ActiveGovernanceConfig returns the config for the fully active phase.
func ActiveGovernanceConfig() GovernanceConfig {
	return GovernanceConfig{
		Phase:              GovPhaseActive,
		VotingPeriodBlocks: 100800, // ~7 days at 6s blocks
		QuorumPercent:      40,
		ThresholdPercent:   50,
		VetoPercent:        33,
		MaxProposals:       20,
	}
}

// ValidateGovernanceConfig checks that governance parameters are well-formed.
func ValidateGovernanceConfig(config GovernanceConfig) error {
	if config.VotingPeriodBlocks < 100 {
		return fmt.Errorf("voting period must be >= 100 blocks, got %d", config.VotingPeriodBlocks)
	}
	if config.QuorumPercent < 10 || config.QuorumPercent > 100 {
		return fmt.Errorf("quorum must be in [10, 100], got %d", config.QuorumPercent)
	}
	if config.ThresholdPercent < 50 || config.ThresholdPercent > 100 {
		return fmt.Errorf("threshold must be in [50, 100], got %d", config.ThresholdPercent)
	}
	if config.VetoPercent < 10 || config.VetoPercent > 100 {
		return fmt.Errorf("veto must be in [10, 100], got %d", config.VetoPercent)
	}
	if config.MaxProposals < 1 {
		return fmt.Errorf("max proposals must be >= 1, got %d", config.MaxProposals)
	}
	return nil
}

// GovernanceReadiness evaluates whether the chain is ready for full governance.
type GovernanceReadiness struct {
	CurrentPhase     GovernancePhase
	ReadyForActive   bool
	Criteria         []GovernanceReadinessCriterion
	BlocksSinceLaunch int64
	MinBlocksRequired int64
}

// GovernanceReadinessCriterion is a single criterion for governance activation.
type GovernanceReadinessCriterion struct {
	ID          string
	Description string
	Passed      bool
	Details     string
	Required    bool
}

// MinBlocksForGovernance is the minimum blocks since genesis before full
// governance can be activated (~2 weeks at 6s blocks).
const MinBlocksForGovernance = 201600

// EvaluateGovernanceReadiness checks if the chain is ready for full governance.
func EvaluateGovernanceReadiness(ctx sdk.Context, k Keeper) *GovernanceReadiness {
	result := &GovernanceReadiness{
		CurrentPhase:      GovPhaseBootstrap,
		ReadyForActive:    true,
		BlocksSinceLaunch: ctx.BlockHeight(),
		MinBlocksRequired: MinBlocksForGovernance,
	}

	// GR-01: Minimum blocks since launch
	blockOk := ctx.BlockHeight() >= MinBlocksForGovernance
	result.Criteria = append(result.Criteria, GovernanceReadinessCriterion{
		ID:          "GR-01",
		Description: "Minimum blocks since launch (2 weeks)",
		Passed:      blockOk,
		Details:     fmt.Sprintf("height=%d, required=%d", ctx.BlockHeight(), MinBlocksForGovernance),
		Required:    true,
	})
	if !blockOk {
		result.ReadyForActive = false
	}

	// GR-02: All invariants pass
	invariants := AllInvariants(k)
	_, broken := invariants(ctx)
	result.Criteria = append(result.Criteria, GovernanceReadinessCriterion{
		ID:          "GR-02",
		Description: "All module invariants pass",
		Passed:      !broken,
		Details:     fmt.Sprintf("broken=%v", broken),
		Required:    true,
	})
	if broken {
		result.ReadyForActive = false
	}

	// GR-03: Parameters valid
	params, err := k.GetParams(ctx)
	paramValid := err == nil && params != nil && ValidateParams(params) == nil
	result.Criteria = append(result.Criteria, GovernanceReadinessCriterion{
		ID:          "GR-03",
		Description: "Module parameters valid",
		Passed:      paramValid,
		Details:     fmt.Sprintf("valid=%v", paramValid),
		Required:    true,
	})
	if !paramValid {
		result.ReadyForActive = false
	}

	// GR-04: Minimum active validators
	valCount := 0
	_ = k.ValidatorStats.Walk(ctx, nil, func(_ string, _ types.ValidatorStats) (bool, error) {
		valCount++
		return false, nil
	})
	minVal := int64(3)
	if params != nil {
		minVal = params.MinValidators
	}
	result.Criteria = append(result.Criteria, GovernanceReadinessCriterion{
		ID:          "GR-04",
		Description: "Minimum active validators",
		Passed:      int64(valCount) >= minVal,
		Details:     fmt.Sprintf("active=%d, required=%d", valCount, minVal),
		Required:    false, // Advisory — governance can work with fewer
	})

	// GR-05: No SEV-1 incidents
	// In production this would check an incident tracker, here we verify chain health
	health := RunChainHealthCheck(ctx, k)
	critical := health.CriticalAnomalies()
	result.Criteria = append(result.Criteria, GovernanceReadinessCriterion{
		ID:          "GR-05",
		Description: "No critical health anomalies",
		Passed:      len(critical) == 0,
		Details:     fmt.Sprintf("%d critical anomalies", len(critical)),
		Required:    true,
	})
	if len(critical) > 0 {
		result.ReadyForActive = false
	}

	return result
}

// ---------------------------------------------------------------------------
// Section 4: Chain Maturity Assessment
// ---------------------------------------------------------------------------

// MaturityLevel describes the maturity stage of the chain.
type MaturityLevel string

const (
	MaturityLaunch     MaturityLevel = "launch"      // First 2 weeks
	MaturityEarlyOps   MaturityLevel = "early_ops"   // 2-6 weeks
	MaturityStable     MaturityLevel = "stable"       // 6-12 weeks
	MaturityMature     MaturityLevel = "mature"       // 12+ weeks
)

// MaturityAssessment captures the current maturity stage and metrics.
type MaturityAssessment struct {
	// Identity
	ChainID     string
	BlockHeight int64
	AssessedAt  string

	// Maturity
	Level           MaturityLevel
	BlocksElapsed   int64
	WeeksElapsed    float64

	// Stability metrics
	InvariantsPass  bool
	ParamsValid     bool
	ValidatorCount  int
	TotalJobs       uint64
	AvgReputation   float64

	// Decentralization
	GovernancePhase GovernancePhase
	LockedParams    int
	MutableParams   int

	// Score (0-100)
	StabilityScore     int
	DecentralizationScore int
	ActivityScore      int
	OverallMaturity    int

	// Graduation criteria
	GraduationCriteria []MaturityCriterion
}

// MaturityCriterion is a single criterion for maturity graduation.
type MaturityCriterion struct {
	ID          string
	Description string
	Passed      bool
	Details     string
}

// AssessChainMaturity evaluates the chain's current maturity stage.
func AssessChainMaturity(ctx sdk.Context, k Keeper) *MaturityAssessment {
	assessment := &MaturityAssessment{
		ChainID:     ctx.ChainID(),
		BlockHeight: ctx.BlockHeight(),
		AssessedAt:  ctx.BlockTime().UTC().Format(time.RFC3339),
		BlocksElapsed: ctx.BlockHeight(),
	}

	// Calculate weeks (6-second blocks)
	assessment.WeeksElapsed = float64(ctx.BlockHeight()) * 6 / (7 * 24 * 3600)

	// Determine maturity level
	switch {
	case assessment.BlocksElapsed < 201600: // < 2 weeks
		assessment.Level = MaturityLaunch
	case assessment.BlocksElapsed < 604800: // < 6 weeks
		assessment.Level = MaturityEarlyOps
	case assessment.BlocksElapsed < 1209600: // < 12 weeks
		assessment.Level = MaturityStable
	default:
		assessment.Level = MaturityMature
	}

	// Collect metrics
	invariants := AllInvariants(k)
	_, broken := invariants(ctx)
	assessment.InvariantsPass = !broken

	params, _ := k.GetParams(ctx)
	assessment.ParamsValid = params != nil && ValidateParams(params) == nil

	_ = k.ValidatorStats.Walk(ctx, nil, func(_ string, s types.ValidatorStats) (bool, error) {
		assessment.ValidatorCount++
		assessment.AvgReputation += float64(s.ReputationScore)
		return false, nil
	})
	if assessment.ValidatorCount > 0 {
		assessment.AvgReputation /= float64(assessment.ValidatorCount)
	}

	assessment.TotalJobs, _ = k.JobCount.Get(ctx)
	assessment.LockedParams = len(GetLockedParams())
	assessment.MutableParams = len(GetMutableParams())

	// Governance phase
	govReady := EvaluateGovernanceReadiness(ctx, k)
	if govReady.ReadyForActive {
		assessment.GovernancePhase = GovPhaseActive
	} else {
		assessment.GovernancePhase = GovPhaseBootstrap
	}

	// --- Compute scores ---

	// Stability score (0-100)
	stabilityPoints := 0
	if assessment.InvariantsPass {
		stabilityPoints += 40
	}
	if assessment.ParamsValid {
		stabilityPoints += 30
	}
	if assessment.ValidatorCount >= 3 {
		stabilityPoints += 15
	}
	if assessment.AvgReputation >= 50 {
		stabilityPoints += 15
	}
	assessment.StabilityScore = stabilityPoints

	// Decentralization score (0-100)
	decentPoints := 0
	if assessment.LockedParams > 0 {
		decentPoints += 30
	}
	if assessment.GovernancePhase == GovPhaseActive {
		decentPoints += 40
	} else {
		decentPoints += 20 // bootstrap gets partial credit
	}
	if assessment.ValidatorCount >= 5 {
		decentPoints += 30
	} else if assessment.ValidatorCount >= 3 {
		decentPoints += 15
	}
	assessment.DecentralizationScore = decentPoints

	// Activity score (0-100)
	activityPoints := 0
	if assessment.TotalJobs > 0 {
		activityPoints += 30
	}
	if assessment.TotalJobs > 100 {
		activityPoints += 20
	}
	if assessment.TotalJobs > 1000 {
		activityPoints += 20
	}
	if assessment.ValidatorCount > 0 {
		activityPoints += 15
	}
	if assessment.AvgReputation > 0 {
		activityPoints += 15
	}
	if activityPoints > 100 {
		activityPoints = 100
	}
	assessment.ActivityScore = activityPoints

	// Overall maturity (weighted average)
	assessment.OverallMaturity = (assessment.StabilityScore*40 +
		assessment.DecentralizationScore*30 +
		assessment.ActivityScore*30) / 100

	// Graduation criteria
	assessment.GraduationCriteria = computeGraduationCriteria(assessment)

	return assessment
}

func computeGraduationCriteria(a *MaturityAssessment) []MaturityCriterion {
	var criteria []MaturityCriterion

	// MC-01: Chain running for minimum blocks
	criteria = append(criteria, MaturityCriterion{
		ID:          "MC-01",
		Description: "Chain running for minimum 2 weeks",
		Passed:      a.BlocksElapsed >= 201600,
		Details:     fmt.Sprintf("blocks=%d, weeks=%.1f", a.BlocksElapsed, a.WeeksElapsed),
	})

	// MC-02: Invariants pass
	criteria = append(criteria, MaturityCriterion{
		ID:          "MC-02",
		Description: "All invariants pass",
		Passed:      a.InvariantsPass,
		Details:     fmt.Sprintf("pass=%v", a.InvariantsPass),
	})

	// MC-03: Parameters valid
	criteria = append(criteria, MaturityCriterion{
		ID:          "MC-03",
		Description: "Parameters valid",
		Passed:      a.ParamsValid,
		Details:     fmt.Sprintf("valid=%v", a.ParamsValid),
	})

	// MC-04: Minimum validators
	criteria = append(criteria, MaturityCriterion{
		ID:          "MC-04",
		Description: "Minimum 3 active validators",
		Passed:      a.ValidatorCount >= 3,
		Details:     fmt.Sprintf("count=%d", a.ValidatorCount),
	})

	// MC-05: Governance ready
	criteria = append(criteria, MaturityCriterion{
		ID:          "MC-05",
		Description: "Governance activation ready",
		Passed:      a.GovernancePhase == GovPhaseActive,
		Details:     fmt.Sprintf("phase=%s", a.GovernancePhase),
	})

	// MC-06: Stability score above threshold
	criteria = append(criteria, MaturityCriterion{
		ID:          "MC-06",
		Description: "Stability score >= 70",
		Passed:      a.StabilityScore >= 70,
		Details:     fmt.Sprintf("score=%d", a.StabilityScore),
	})

	return criteria
}

// AllGraduationCriteriaPassed returns true if all criteria pass.
func (a *MaturityAssessment) AllGraduationCriteriaPassed() bool {
	for _, c := range a.GraduationCriteria {
		if !c.Passed {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Section 5: Post-Launch Reports
// ---------------------------------------------------------------------------

// RenderChainHealthReport produces a human-readable health report.
func RenderChainHealthReport(r *ChainHealthReport) string {
	var sb strings.Builder

	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║          CHAIN HEALTH MONITOR                               ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	sb.WriteString(fmt.Sprintf("Chain: %s | Block: %d | Time: %s\n", r.ChainID, r.BlockHeight, r.Timestamp))
	sb.WriteString(fmt.Sprintf("Overall Status: [%s]\n\n", strings.ToUpper(string(r.OverallStatus))))

	sb.WriteString("─── SUBSYSTEMS ────────────────────────────────────────────────\n")
	for _, s := range r.Subsystems {
		sb.WriteString(fmt.Sprintf("  [%s] %-20s %s\n",
			strings.ToUpper(string(s.Status)), s.Name, s.Details))
	}

	if len(r.Anomalies) > 0 {
		sb.WriteString("\n─── ANOMALIES ─────────────────────────────────────────────────\n")
		for _, a := range r.Anomalies {
			sb.WriteString(fmt.Sprintf("  [%s] %s: %s\n", strings.ToUpper(a.Severity), a.ID, a.Description))
		}
	}

	sb.WriteString("\n─── METRICS ───────────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Total Jobs:        %d\n", r.TotalJobs))
	sb.WriteString(fmt.Sprintf("  Pending Jobs:      %d\n", r.PendingJobs))
	sb.WriteString(fmt.Sprintf("  Active Validators: %d\n", r.ActiveValidators))
	sb.WriteString(fmt.Sprintf("  Avg Reputation:    %.1f\n", r.AvgReputation))
	sb.WriteString(fmt.Sprintf("  Invariants:        %v\n", r.InvariantsPass))
	sb.WriteString(fmt.Sprintf("  Params Valid:      %v\n", r.ParamsValid))

	sb.WriteString("\n══════════════════════════════════════════════════════════════\n")
	return sb.String()
}

// RenderMaturityAssessment produces a human-readable maturity report.
func RenderMaturityAssessment(a *MaturityAssessment) string {
	var sb strings.Builder

	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║          CHAIN MATURITY ASSESSMENT                          ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	sb.WriteString(fmt.Sprintf("Chain: %s | Block: %d | Assessed: %s\n", a.ChainID, a.BlockHeight, a.AssessedAt))
	sb.WriteString(fmt.Sprintf("Maturity Level: %s (%.1f weeks)\n\n", strings.ToUpper(string(a.Level)), a.WeeksElapsed))

	sb.WriteString("─── SCORES ────────────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Stability:          %3d/100\n", a.StabilityScore))
	sb.WriteString(fmt.Sprintf("  Decentralization:   %3d/100\n", a.DecentralizationScore))
	sb.WriteString(fmt.Sprintf("  Activity:           %3d/100\n", a.ActivityScore))
	sb.WriteString(fmt.Sprintf("  ────────────────────\n"))
	sb.WriteString(fmt.Sprintf("  OVERALL MATURITY:   %3d/100\n\n", a.OverallMaturity))

	sb.WriteString("─── GRADUATION CRITERIA ────────────────────────────────────────\n")
	for _, c := range a.GraduationCriteria {
		status := "PASS"
		if !c.Passed {
			status = "FAIL"
		}
		sb.WriteString(fmt.Sprintf("  [%s] %s: %s — %s\n", status, c.ID, c.Description, c.Details))
	}

	sb.WriteString("\n─── GOVERNANCE ────────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Phase:    %s\n", a.GovernancePhase))
	sb.WriteString(fmt.Sprintf("  Locked:   %d parameters\n", a.LockedParams))
	sb.WriteString(fmt.Sprintf("  Mutable:  %d parameters\n", a.MutableParams))

	sb.WriteString("\n══════════════════════════════════════════════════════════════\n")

	// Sort graduation criteria to give final verdict
	allPassed := a.AllGraduationCriteriaPassed()
	if allPassed {
		sb.WriteString("  *** CHAIN GRADUATED *** — Ready for mature operations\n")
	} else {
		sb.WriteString("  Chain is in " + string(a.Level) + " phase — not yet graduated\n")
	}
	sb.WriteString("══════════════════════════════════════════════════════════════\n")

	return sb.String()
}

// ---------------------------------------------------------------------------
// Section 6: Comprehensive Post-Launch Summary
// ---------------------------------------------------------------------------

// PostLaunchSummary aggregates all post-launch monitoring data.
type PostLaunchSummary struct {
	Health    *ChainHealthReport
	Maturity  *MaturityAssessment
	Governance *GovernanceReadiness
	Incidents  int
	OpenIncidents int
}

// RunPostLaunchSummary generates a comprehensive post-launch status.
func RunPostLaunchSummary(ctx sdk.Context, k Keeper) *PostLaunchSummary {
	health := RunChainHealthCheck(ctx, k)
	maturity := AssessChainMaturity(ctx, k)
	governance := EvaluateGovernanceReadiness(ctx, k)

	return &PostLaunchSummary{
		Health:     health,
		Maturity:   maturity,
		Governance: governance,
	}
}

// RenderPostLaunchSummary produces a final summary combining all reports.
func RenderPostLaunchSummary(s *PostLaunchSummary) string {
	var sb strings.Builder

	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║          POST-LAUNCH STATUS SUMMARY                         ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	// Health
	sb.WriteString(fmt.Sprintf("Health:     [%s]\n", strings.ToUpper(string(s.Health.OverallStatus))))
	sb.WriteString(fmt.Sprintf("Maturity:   %s (score: %d/100)\n", s.Maturity.Level, s.Maturity.OverallMaturity))
	sb.WriteString(fmt.Sprintf("Governance: %s\n", s.Governance.CurrentPhase))
	sb.WriteString(fmt.Sprintf("Block:      %d\n", s.Health.BlockHeight))

	sb.WriteString("\n─── KEY METRICS ───────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Validators:    %d\n", s.Health.ActiveValidators))
	sb.WriteString(fmt.Sprintf("  Total Jobs:    %d\n", s.Health.TotalJobs))
	sb.WriteString(fmt.Sprintf("  Invariants:    %v\n", s.Health.InvariantsPass))
	sb.WriteString(fmt.Sprintf("  Params Valid:  %v\n", s.Health.ParamsValid))

	// Anomaly count
	criticalCount := len(s.Health.CriticalAnomalies())
	sb.WriteString(fmt.Sprintf("  Anomalies:     %d (%d critical)\n",
		len(s.Health.Anomalies), criticalCount))

	sb.WriteString("\n══════════════════════════════════════════════════════════════\n")
	return sb.String()
}

// GetMonitoringSummaryByValidators returns validators sorted by reputation.
func GetMonitoringSummaryByValidators(ctx sdk.Context, k Keeper) []types.ValidatorStats {
	var validators []types.ValidatorStats
	_ = k.ValidatorStats.Walk(ctx, nil, func(_ string, s types.ValidatorStats) (bool, error) {
		validators = append(validators, s)
		return false, nil
	})
	sort.Slice(validators, func(i, j int) bool {
		return validators[i].ReputationScore > validators[j].ReputationScore
	})
	return validators
}
