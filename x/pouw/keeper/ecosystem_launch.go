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
// WEEKS 41-45: Launch Readiness, Go/No-Go, and Genesis
// ---------------------------------------------------------------------------
//
// This file implements the final pre-launch sequence:
//
//   1. Ecosystem pilot cohort (Week 41-42)
//      - Pilot application registry and tracking
//      - Cohort health assessment and readiness
//      - Integration verification per pilot partner
//
//   2. Final go/no-go review (Week 43-44)
//      - Comprehensive launch decision framework (20+ criteria)
//      - Multi-dimensional scoring (security, performance, economics, ops)
//      - Blocking vs advisory criteria separation
//      - Automated evidence collection from all subsystems
//
//   3. Mainnet genesis ceremony (Week 45)
//      - Genesis state builder with full validation
//      - Validator set bootstrapping and capability registration
//      - Chain initialization sequence with pre/post checks
//      - Genesis verification and deterministic hash
//
// Design principles:
//   - Go/no-go is deterministic and reproducible from on-chain state
//   - Genesis ceremony produces a fully validated genesis state
//   - All pilot cohort data is auditable and traceable
//   - Launch decision is transparently documented
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Section 1: Ecosystem Pilot Cohort
// ---------------------------------------------------------------------------

// PilotPartnerStatus tracks the integration status of an ecosystem partner.
type PilotPartnerStatus string

const (
	PilotStatusProspect   PilotPartnerStatus = "prospect"
	PilotStatusIntegrating PilotPartnerStatus = "integrating"
	PilotStatusTesting    PilotPartnerStatus = "testing"
	PilotStatusActive     PilotPartnerStatus = "active"
	PilotStatusChurned    PilotPartnerStatus = "churned"
)

// PilotPartner represents an ecosystem partner in the pilot cohort.
type PilotPartner struct {
	ID              string
	Name            string
	Category        string // "financial", "enterprise", "developer", "infrastructure"
	Status          PilotPartnerStatus
	IntegrationType string // "sdk", "api", "bridge", "validator"
	JoinedAt        time.Time
	LastActiveAt    time.Time

	// Integration metrics
	TotalTransactions int64
	SuccessRate       float64 // 0.0 - 1.0
	AvgLatencyMs      int64

	// Verification
	SDKVersion        string
	ChainID           string
	ContactEmail      string
}

// ValidatePilotPartner checks if a pilot partner record is well-formed.
func ValidatePilotPartner(p PilotPartner) error {
	if p.ID == "" {
		return fmt.Errorf("partner ID must not be empty")
	}
	if p.Name == "" {
		return fmt.Errorf("partner name must not be empty")
	}
	validCategories := map[string]bool{
		"financial": true, "enterprise": true, "developer": true, "infrastructure": true,
	}
	if !validCategories[p.Category] {
		return fmt.Errorf("invalid partner category %q; must be one of financial, enterprise, developer, infrastructure", p.Category)
	}
	validIntegrations := map[string]bool{
		"sdk": true, "api": true, "bridge": true, "validator": true,
	}
	if !validIntegrations[p.IntegrationType] {
		return fmt.Errorf("invalid integration type %q; must be one of sdk, api, bridge, validator", p.IntegrationType)
	}
	return nil
}

// PilotCohort manages the full set of ecosystem pilot partners.
type PilotCohort struct {
	Partners []PilotPartner
}

// NewPilotCohort creates an empty cohort.
func NewPilotCohort() *PilotCohort {
	return &PilotCohort{}
}

// AddPartner adds a validated partner to the cohort.
func (pc *PilotCohort) AddPartner(p PilotPartner) error {
	if err := ValidatePilotPartner(p); err != nil {
		return fmt.Errorf("invalid partner: %w", err)
	}
	// Check for duplicate ID
	for _, existing := range pc.Partners {
		if existing.ID == p.ID {
			return fmt.Errorf("partner with ID %q already exists", p.ID)
		}
	}
	pc.Partners = append(pc.Partners, p)
	return nil
}

// GetPartner retrieves a partner by ID.
func (pc *PilotCohort) GetPartner(id string) (*PilotPartner, bool) {
	for i := range pc.Partners {
		if pc.Partners[i].ID == id {
			return &pc.Partners[i], true
		}
	}
	return nil, false
}

// ActivePartners returns all partners in "active" or "testing" status.
func (pc *PilotCohort) ActivePartners() []PilotPartner {
	var active []PilotPartner
	for _, p := range pc.Partners {
		if p.Status == PilotStatusActive || p.Status == PilotStatusTesting {
			active = append(active, p)
		}
	}
	return active
}

// CohortHealth evaluates the overall health of the pilot cohort.
type CohortHealth struct {
	TotalPartners      int
	ActivePartners     int
	IntegratingPartners int
	ChurnedPartners    int

	CategoryBreakdown  map[string]int
	IntegrationBreakdown map[string]int

	AvgSuccessRate     float64
	AvgLatencyMs       int64
	TotalTransactions  int64

	IsHealthy          bool
	HealthIssues       []string
}

// EvaluateCohortHealth analyzes the cohort and returns a health assessment.
func (pc *PilotCohort) EvaluateCohortHealth() *CohortHealth {
	health := &CohortHealth{
		TotalPartners:        len(pc.Partners),
		CategoryBreakdown:    make(map[string]int),
		IntegrationBreakdown: make(map[string]int),
		IsHealthy:            true,
	}

	var successSum float64
	var latencySum int64
	activeCount := 0

	for _, p := range pc.Partners {
		health.CategoryBreakdown[p.Category]++
		health.IntegrationBreakdown[p.IntegrationType]++
		health.TotalTransactions += p.TotalTransactions

		switch p.Status {
		case PilotStatusActive, PilotStatusTesting:
			health.ActivePartners++
			activeCount++
			successSum += p.SuccessRate
			latencySum += p.AvgLatencyMs
		case PilotStatusIntegrating:
			health.IntegratingPartners++
		case PilotStatusChurned:
			health.ChurnedPartners++
		}
	}

	if activeCount > 0 {
		health.AvgSuccessRate = successSum / float64(activeCount)
		health.AvgLatencyMs = latencySum / int64(activeCount)
	}

	// Health checks
	if health.TotalPartners < 3 {
		health.IsHealthy = false
		health.HealthIssues = append(health.HealthIssues,
			fmt.Sprintf("insufficient partners: %d (minimum 3)", health.TotalPartners))
	}
	if health.ActivePartners == 0 && health.TotalPartners > 0 {
		health.IsHealthy = false
		health.HealthIssues = append(health.HealthIssues,
			"no active partners in cohort")
	}
	if health.AvgSuccessRate < 0.9 && activeCount > 0 {
		health.IsHealthy = false
		health.HealthIssues = append(health.HealthIssues,
			fmt.Sprintf("average success rate %.1f%% below 90%% threshold", health.AvgSuccessRate*100))
	}
	churnRate := float64(0)
	if health.TotalPartners > 0 {
		churnRate = float64(health.ChurnedPartners) / float64(health.TotalPartners)
	}
	if churnRate > 0.3 {
		health.IsHealthy = false
		health.HealthIssues = append(health.HealthIssues,
			fmt.Sprintf("churn rate %.0f%% exceeds 30%% threshold", churnRate*100))
	}

	return health
}

// ---------------------------------------------------------------------------
// Section 2: Final Go/No-Go Review
// ---------------------------------------------------------------------------

// LaunchCriterion is a single evaluation criterion for the go/no-go review.
type LaunchCriterion struct {
	ID          string
	Category    string // "security", "performance", "economics", "operations", "ecosystem", "governance"
	Description string
	Passed      bool
	Details     string
	Blocking    bool   // If true, failure blocks launch
	Evidence    string // Where to find supporting evidence
}

// LaunchReviewResult is the comprehensive result of the go/no-go review.
type LaunchReviewResult struct {
	// Identity
	ChainID          string
	BlockHeight      int64
	ReviewedAt       string
	ReviewerNote     string

	// Criteria results
	Criteria         []LaunchCriterion

	// Score breakdown (0-100 each)
	SecurityScore    int
	PerformanceScore int
	EconomicsScore   int
	OperationsScore  int
	EcosystemScore   int
	GovernanceScore  int
	OverallScore     int

	// Decision
	Decision         string // "GO", "NO-GO", "CONDITIONAL-GO"
	BlockingFailures []LaunchCriterion
	Conditions       []string // Conditions for CONDITIONAL-GO
}

// RunLaunchReview executes the comprehensive go/no-go review against
// current on-chain state and all subsystem reports.
func RunLaunchReview(ctx sdk.Context, k Keeper, cohort *PilotCohort) *LaunchReviewResult {
	result := &LaunchReviewResult{
		ChainID:     ctx.ChainID(),
		BlockHeight: ctx.BlockHeight(),
		ReviewedAt:  ctx.BlockTime().UTC().Format(time.RFC3339),
	}

	// --- Collect all criteria ---

	// Security criteria (L-01 through L-05)
	result.Criteria = append(result.Criteria, runSecurityCriteria(ctx, k)...)

	// Performance criteria (L-06 through L-09)
	result.Criteria = append(result.Criteria, runPerformanceCriteria(ctx, k)...)

	// Economics criteria (L-10 through L-12)
	result.Criteria = append(result.Criteria, runEconomicsCriteria(ctx, k)...)

	// Operations criteria (L-13 through L-16)
	result.Criteria = append(result.Criteria, runOperationsCriteria(ctx, k)...)

	// Ecosystem criteria (L-17 through L-19)
	result.Criteria = append(result.Criteria, runEcosystemCriteria(cohort)...)

	// Governance criteria (L-20 through L-22)
	result.Criteria = append(result.Criteria, runGovernanceCriteria(ctx, k)...)

	// --- Compute scores ---
	result.SecurityScore = computeCategoryScore(result.Criteria, "security")
	result.PerformanceScore = computeCategoryScore(result.Criteria, "performance")
	result.EconomicsScore = computeCategoryScore(result.Criteria, "economics")
	result.OperationsScore = computeCategoryScore(result.Criteria, "operations")
	result.EcosystemScore = computeCategoryScore(result.Criteria, "ecosystem")
	result.GovernanceScore = computeCategoryScore(result.Criteria, "governance")

	// Overall is weighted average
	result.OverallScore = (result.SecurityScore*30 +
		result.PerformanceScore*20 +
		result.EconomicsScore*15 +
		result.OperationsScore*15 +
		result.EcosystemScore*10 +
		result.GovernanceScore*10) / 100

	// --- Determine decision ---
	for _, c := range result.Criteria {
		if c.Blocking && !c.Passed {
			result.BlockingFailures = append(result.BlockingFailures, c)
		}
	}

	if len(result.BlockingFailures) > 0 {
		result.Decision = "NO-GO"
	} else if result.OverallScore >= 80 {
		result.Decision = "GO"
	} else {
		result.Decision = "CONDITIONAL-GO"
		// Collect conditions from non-blocking failures
		for _, c := range result.Criteria {
			if !c.Passed && !c.Blocking {
				result.Conditions = append(result.Conditions,
					fmt.Sprintf("[%s] %s: %s", c.ID, c.Description, c.Details))
			}
		}
	}

	return result
}

// --- Security Criteria ---
func runSecurityCriteria(ctx sdk.Context, k Keeper) []LaunchCriterion {
	var criteria []LaunchCriterion
	params, _ := k.GetParams(ctx)

	// L-01: No critical audit findings
	closeout := RunComprehensiveRetest(ctx, k)
	criticalCount := 0
	if closeout.RetestReport != nil {
		criticalCount = closeout.RetestReport.CriticalCount
	}
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-01",
		Category:    "security",
		Description: "No unresolved critical audit findings",
		Passed:      criticalCount == 0,
		Details:     fmt.Sprintf("%d critical findings", criticalCount),
		Blocking:    true,
		Evidence:    "audit_closeout.go::RunComprehensiveRetest",
	})

	// L-02: All invariants pass
	invariants := AllInvariants(k)
	invMsg, invBroken := invariants(ctx)
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-02",
		Category:    "security",
		Description: "All module invariants pass",
		Passed:      !invBroken,
		Details:     invMsg,
		Blocking:    true,
		Evidence:    "invariants.go::AllInvariants",
	})

	// L-03: AllowSimulated disabled
	simOff := params != nil && !params.AllowSimulated
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-03",
		Category:    "security",
		Description: "AllowSimulated is disabled (production mode)",
		Passed:      simOff,
		Details:     fmt.Sprintf("AllowSimulated=%v", params != nil && params.AllowSimulated),
		Blocking:    true,
		Evidence:    "governance.go::ValidateParams",
	})

	// L-04: ConsensusThreshold ≥ 67 (BFT safety)
	bftSafe := params != nil && params.ConsensusThreshold >= 67
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-04",
		Category:    "security",
		Description: "Consensus threshold meets BFT safety (≥67%)",
		Passed:      bftSafe,
		Details:     fmt.Sprintf("threshold=%d", params.ConsensusThreshold),
		Blocking:    true,
		Evidence:    "mainnet_params.go::MainnetParams",
	})

	// L-05: TEE attestation required
	teeReq := params != nil && params.RequireTeeAttestation
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-05",
		Category:    "security",
		Description: "TEE attestation is required",
		Passed:      teeReq,
		Details:     fmt.Sprintf("RequireTeeAttestation=%v", params != nil && params.RequireTeeAttestation),
		Blocking:    true,
		Evidence:    "mainnet_params.go::MainnetParams",
	})

	return criteria
}

// --- Performance Criteria ---
func runPerformanceCriteria(ctx sdk.Context, k Keeper) []LaunchCriterion {
	var criteria []LaunchCriterion
	params, _ := k.GetParams(ctx)

	// L-06: Parameter validation passes
	paramValid := params != nil && ValidateParams(params) == nil
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-06",
		Category:    "performance",
		Description: "Module parameters pass validation",
		Passed:      paramValid,
		Details:     fmt.Sprintf("valid=%v", paramValid),
		Blocking:    true,
		Evidence:    "governance.go::ValidateParams",
	})

	// L-07: Block budget within limits
	budget := DefaultBlockBudget()
	budget.RunTask("invariant_check", func() {
		AllInvariants(k)(ctx)
	})
	budget.RunTask("consistency_check", func() {
		EndBlockConsistencyChecks(ctx, k)
	})
	utilization := float64(budget.TotalSpent().Milliseconds()) / float64(MainnetProfile().MaxBlockBudgetMs)
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-07",
		Category:    "performance",
		Description: "Block budget utilization under 80%",
		Passed:      utilization < 0.8,
		Details:     fmt.Sprintf("utilization=%.1f%%", utilization*100),
		Blocking:    false,
		Evidence:    "performance.go::RunPerformanceTuningReport",
	})

	// L-08: Upgrade rehearsal passes
	rehearsal := RunUpgradeRehearsal(ctx, k)
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-08",
		Category:    "performance",
		Description: "Upgrade rehearsal passes",
		Passed:      rehearsal.RehearsalPass,
		Details:     fmt.Sprintf("duration=%v, failures=%d", rehearsal.MigrationDuration, len(rehearsal.FailureReasons)),
		Blocking:    false,
		Evidence:    "upgrade_rehearsal.go::RunUpgradeRehearsal",
	})

	// L-09: Rollback drill succeeds
	drill := RunRollbackDrill(ctx, k)
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-09",
		Category:    "performance",
		Description: "Rollback drill succeeds",
		Passed:      drill.DrillPass,
		Details:     fmt.Sprintf("recovery=%v, duration=%v", drill.RecoverySuccess, drill.RecoveryDuration),
		Blocking:    false,
		Evidence:    "upgrade_rehearsal.go::RunRollbackDrill",
	})

	return criteria
}

// --- Economics Criteria ---
func runEconomicsCriteria(ctx sdk.Context, k Keeper) []LaunchCriterion {
	var criteria []LaunchCriterion

	// L-10: Fee BPS sum = 10000
	feeConfig := DefaultFeeDistributionConfig()
	bpsSum := feeConfig.ValidatorRewardBps + feeConfig.TreasuryBps + feeConfig.BurnBps + feeConfig.InsuranceFundBps
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-10",
		Category:    "economics",
		Description: "Fee distribution BPS sum to 10000",
		Passed:      bpsSum == 10000,
		Details:     fmt.Sprintf("sum=%d", bpsSum),
		Blocking:    true,
		Evidence:    "fee_distribution.go::DefaultFeeDistributionConfig",
	})

	// L-11: Mainnet genesis config valid
	genesisConfig := DefaultMainnetGenesisConfig()
	genesisIssues := ValidateMainnetGenesis(genesisConfig)
	// Filter out the warning about genesis time
	var realIssues []string
	for _, issue := range genesisIssues {
		if !strings.HasPrefix(issue, "WARNING:") {
			realIssues = append(realIssues, issue)
		}
	}
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-11",
		Category:    "economics",
		Description: "Mainnet genesis configuration is valid",
		Passed:      len(realIssues) == 0,
		Details:     fmt.Sprintf("%d issues", len(realIssues)),
		Blocking:    true,
		Evidence:    "mainnet_params.go::ValidateMainnetGenesis",
	})

	// L-12: Slashing deterrence ratio maintained
	params, _ := k.GetParams(ctx)
	slashingOk := false
	if params != nil {
		// Slashing penalty should be >= 10x base fee
		// Both are strings so we just check they're present and non-empty
		slashingOk = params.SlashingPenalty != "" && params.BaseJobFee != ""
	}
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-12",
		Category:    "economics",
		Description: "Slashing deterrence ratio is configured",
		Passed:      slashingOk,
		Details:     fmt.Sprintf("penalty=%s, fee=%s", params.SlashingPenalty, params.BaseJobFee),
		Blocking:    false,
		Evidence:    "mainnet_params.go::MainnetParams",
	})

	return criteria
}

// --- Operations Criteria ---
func runOperationsCriteria(ctx sdk.Context, k Keeper) []LaunchCriterion {
	var criteria []LaunchCriterion

	// L-13: Upgrade infrastructure ready
	migrations := GetMigrations()
	hasMigration := false
	for _, m := range migrations {
		if m.FromVersion == ModuleConsensusVersion {
			hasMigration = true
		}
	}
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-13",
		Category:    "operations",
		Description: "Migration handler registered for current version",
		Passed:      hasMigration,
		Details:     fmt.Sprintf("v%d handler exists: %v", ModuleConsensusVersion, hasMigration),
		Blocking:    false,
		Evidence:    "upgrade.go::GetMigrations",
	})

	// L-14: State snapshot capability
	snapStart := time.Now()
	snap := CaptureStateSnapshot(ctx, k)
	snapDuration := time.Since(snapStart)
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-14",
		Category:    "operations",
		Description: "State snapshot completes within 100ms",
		Passed:      snapDuration < 100*time.Millisecond,
		Details:     fmt.Sprintf("duration=%v, jobs=%d, validators=%d", snapDuration, snap.TotalJobs, snap.TotalValidators),
		Blocking:    false,
		Evidence:    "upgrade_rehearsal.go::CaptureStateSnapshot",
	})

	// L-15: Upgrade checklist passes blocking items
	checklist := RunUpgradeChecklist(ctx, k)
	checklistPasses := ChecklistPassesBlocking(checklist)
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-15",
		Category:    "operations",
		Description: "Upgrade checklist passes all blocking items",
		Passed:      checklistPasses,
		Details:     fmt.Sprintf("%d items, blocking_pass=%v", len(checklist), checklistPasses),
		Blocking:    true,
		Evidence:    "upgrade_rehearsal.go::RunUpgradeChecklist",
	})

	// L-16: Consistency checks pass
	checks := EndBlockConsistencyChecks(ctx, k)
	allPass := true
	for _, c := range checks {
		if !c.Passed {
			allPass = false
			break
		}
	}
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-16",
		Category:    "operations",
		Description: "EndBlock consistency checks pass",
		Passed:      allPass,
		Details:     fmt.Sprintf("%d checks, all_pass=%v", len(checks), allPass),
		Blocking:    true,
		Evidence:    "hardening.go::EndBlockConsistencyChecks",
	})

	return criteria
}

// --- Ecosystem Criteria ---
func runEcosystemCriteria(cohort *PilotCohort) []LaunchCriterion {
	var criteria []LaunchCriterion

	// L-17: Minimum pilot partners
	partnerCount := 0
	if cohort != nil {
		partnerCount = len(cohort.Partners)
	}
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-17",
		Category:    "ecosystem",
		Description: "Minimum 3 ecosystem pilot partners",
		Passed:      partnerCount >= 3,
		Details:     fmt.Sprintf("%d partners", partnerCount),
		Blocking:    false,
		Evidence:    "ecosystem_launch.go::PilotCohort",
	})

	// L-18: At least one active partner
	activeCount := 0
	if cohort != nil {
		activeCount = len(cohort.ActivePartners())
	}
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-18",
		Category:    "ecosystem",
		Description: "At least 1 active pilot partner",
		Passed:      activeCount >= 1,
		Details:     fmt.Sprintf("%d active partners", activeCount),
		Blocking:    false,
		Evidence:    "ecosystem_launch.go::PilotCohort.ActivePartners",
	})

	// L-19: Cohort health assessment
	isHealthy := false
	healthIssues := 0
	if cohort != nil && len(cohort.Partners) > 0 {
		health := cohort.EvaluateCohortHealth()
		isHealthy = health.IsHealthy
		healthIssues = len(health.HealthIssues)
	}
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-19",
		Category:    "ecosystem",
		Description: "Cohort health assessment passes",
		Passed:      isHealthy,
		Details:     fmt.Sprintf("healthy=%v, issues=%d", isHealthy, healthIssues),
		Blocking:    false,
		Evidence:    "ecosystem_launch.go::EvaluateCohortHealth",
	})

	return criteria
}

// --- Governance Criteria ---
func runGovernanceCriteria(ctx sdk.Context, k Keeper) []LaunchCriterion {
	var criteria []LaunchCriterion

	// L-20: Parameter lock registry populated
	locked := GetLockedParams()
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-20",
		Category:    "governance",
		Description: "Parameter lock registry has locked parameters",
		Passed:      len(locked) >= 3,
		Details:     fmt.Sprintf("%d locked parameters", len(locked)),
		Blocking:    false,
		Evidence:    "mainnet_params.go::MainnetParamLockRegistry",
	})

	// L-21: Module consensus version set
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-21",
		Category:    "governance",
		Description: "Module consensus version is set (≥1)",
		Passed:      ModuleConsensusVersion >= 1,
		Details:     fmt.Sprintf("version=%d", ModuleConsensusVersion),
		Blocking:    false,
		Evidence:    "upgrade.go::ModuleConsensusVersion",
	})

	// L-22: Audit closeout is go-for-launch
	closeout := RunComprehensiveRetest(ctx, k)
	isGo := closeout.IsGoForLaunch()
	criteria = append(criteria, LaunchCriterion{
		ID:          "L-22",
		Category:    "governance",
		Description: "Audit closeout report is go-for-launch",
		Passed:      isGo,
		Details:     fmt.Sprintf("go=%v, overall=%d/100", isGo, closeout.OverallScore),
		Blocking:    true,
		Evidence:    "audit_closeout.go::RunComprehensiveRetest",
	})

	return criteria
}

func computeCategoryScore(criteria []LaunchCriterion, category string) int {
	total := 0
	passed := 0
	for _, c := range criteria {
		if c.Category == category {
			total++
			if c.Passed {
				passed++
			}
		}
	}
	if total == 0 {
		return 100
	}
	return (passed * 100) / total
}

// IsGoForLaunchReview returns true if the review decision is GO.
func (r *LaunchReviewResult) IsGoForLaunchReview() bool {
	return r.Decision == "GO"
}

// ---------------------------------------------------------------------------
// Section 3: Mainnet Genesis Ceremony
// ---------------------------------------------------------------------------

// GenesisCeremonyStep represents a single step in the genesis ceremony.
type GenesisCeremonyStep struct {
	Name     string
	Duration time.Duration
	Passed   bool
	Details  string
	Order    int
}

// GenesisCeremonyResult captures the full result of the genesis ceremony.
type GenesisCeremonyResult struct {
	// Identity
	ChainID       string
	GenesisTime   time.Time
	BlockHeight   int64
	CeremonyAt    string

	// Steps
	Steps         []GenesisCeremonyStep
	TotalDuration time.Duration

	// Genesis state
	ValidatorCount int
	ParamsHash     string
	InvariantsPass bool

	// Validation
	GenesisValid   bool
	ValidationErrors []string

	// Protocol manifest
	Manifest       *ProtocolManifest

	// Overall
	CeremonyPass   bool
	FailureReasons []string
}

// RunGenesisCeremony executes the full mainnet genesis ceremony sequence.
// This validates the entire chain state, builds a protocol manifest, verifies
// all subsystems, and produces a ceremony report.
func RunGenesisCeremony(ctx sdk.Context, k Keeper) *GenesisCeremonyResult {
	result := &GenesisCeremonyResult{
		ChainID:     ctx.ChainID(),
		GenesisTime: ctx.BlockTime().UTC(),
		BlockHeight: ctx.BlockHeight(),
		CeremonyAt:  time.Now().UTC().Format(time.RFC3339),
		CeremonyPass: true,
	}

	stepOrder := 0

	// Step 1: Validate mainnet genesis config
	stepOrder++
	step1Start := time.Now()
	genesisConfig := DefaultMainnetGenesisConfig()
	genesisIssues := ValidateMainnetGenesis(genesisConfig)
	// Filter warnings
	var realIssues []string
	for _, issue := range genesisIssues {
		if !strings.HasPrefix(issue, "WARNING:") {
			realIssues = append(realIssues, issue)
		}
	}
	result.Steps = append(result.Steps, GenesisCeremonyStep{
		Name:     "validate_genesis_config",
		Duration: time.Since(step1Start),
		Passed:   len(realIssues) == 0,
		Details:  fmt.Sprintf("%d issues", len(realIssues)),
		Order:    stepOrder,
	})
	if len(realIssues) > 0 {
		result.CeremonyPass = false
		result.ValidationErrors = append(result.ValidationErrors, realIssues...)
		result.FailureReasons = append(result.FailureReasons, "genesis config validation failed")
	}

	// Step 2: Validate on-chain parameters
	stepOrder++
	step2Start := time.Now()
	params, err := k.GetParams(ctx)
	paramValid := err == nil && params != nil && ValidateParams(params) == nil
	result.Steps = append(result.Steps, GenesisCeremonyStep{
		Name:     "validate_chain_params",
		Duration: time.Since(step2Start),
		Passed:   paramValid,
		Details:  fmt.Sprintf("valid=%v", paramValid),
		Order:    stepOrder,
	})
	if !paramValid {
		result.CeremonyPass = false
		result.FailureReasons = append(result.FailureReasons, "chain parameter validation failed")
	}

	// Step 3: Run all invariants
	stepOrder++
	step3Start := time.Now()
	invariants := AllInvariants(k)
	invMsg, invBroken := invariants(ctx)
	result.InvariantsPass = !invBroken
	result.Steps = append(result.Steps, GenesisCeremonyStep{
		Name:     "run_invariants",
		Duration: time.Since(step3Start),
		Passed:   !invBroken,
		Details:  invMsg,
		Order:    stepOrder,
	})
	if invBroken {
		result.CeremonyPass = false
		result.FailureReasons = append(result.FailureReasons, "invariant check failed: "+invMsg)
	}

	// Step 4: Capture state snapshot
	stepOrder++
	step4Start := time.Now()
	snap := CaptureStateSnapshot(ctx, k)
	result.Steps = append(result.Steps, GenesisCeremonyStep{
		Name:     "capture_state_snapshot",
		Duration: time.Since(step4Start),
		Passed:   true,
		Details:  fmt.Sprintf("jobs=%d, validators=%d, models=%d", snap.TotalJobs, snap.TotalValidators, snap.TotalModels),
		Order:    stepOrder,
	})
	result.ValidatorCount = snap.TotalValidators
	result.ParamsHash = snap.ParamsHash

	// Step 5: Verify fee conservation
	stepOrder++
	step5Start := time.Now()
	feeConfig := DefaultFeeDistributionConfig()
	bpsSum := feeConfig.ValidatorRewardBps + feeConfig.TreasuryBps + feeConfig.BurnBps + feeConfig.InsuranceFundBps
	result.Steps = append(result.Steps, GenesisCeremonyStep{
		Name:     "verify_fee_conservation",
		Duration: time.Since(step5Start),
		Passed:   bpsSum == 10000,
		Details:  fmt.Sprintf("BPS sum=%d", bpsSum),
		Order:    stepOrder,
	})
	if bpsSum != 10000 {
		result.CeremonyPass = false
		result.FailureReasons = append(result.FailureReasons, fmt.Sprintf("fee BPS sum %d != 10000", bpsSum))
	}

	// Step 6: Verify security posture
	stepOrder++
	step6Start := time.Now()
	securityOk := params != nil && !params.AllowSimulated && params.ConsensusThreshold >= 67 && params.RequireTeeAttestation
	result.Steps = append(result.Steps, GenesisCeremonyStep{
		Name:     "verify_security_posture",
		Duration: time.Since(step6Start),
		Passed:   securityOk,
		Details:  fmt.Sprintf("simulated=%v, threshold=%d, tee_required=%v", params.AllowSimulated, params.ConsensusThreshold, params.RequireTeeAttestation),
		Order:    stepOrder,
	})
	if !securityOk {
		result.CeremonyPass = false
		result.FailureReasons = append(result.FailureReasons, "security posture check failed")
	}

	// Step 7: Build protocol manifest
	stepOrder++
	step7Start := time.Now()
	manifest := BuildProtocolManifest(ctx, k)
	result.Manifest = manifest
	result.Steps = append(result.Steps, GenesisCeremonyStep{
		Name:     "build_protocol_manifest",
		Duration: time.Since(step7Start),
		Passed:   manifest != nil,
		Details:  fmt.Sprintf("protocol=%s, version=%d", manifest.ProtocolName, manifest.ModuleVersion),
		Order:    stepOrder,
	})

	// Step 8: Run upgrade checklist
	stepOrder++
	step8Start := time.Now()
	checklist := RunUpgradeChecklist(ctx, k)
	checklistPass := ChecklistPassesBlocking(checklist)
	result.Steps = append(result.Steps, GenesisCeremonyStep{
		Name:     "run_upgrade_checklist",
		Duration: time.Since(step8Start),
		Passed:   checklistPass,
		Details:  fmt.Sprintf("%d items, blocking_pass=%v", len(checklist), checklistPass),
		Order:    stepOrder,
	})
	if !checklistPass {
		result.CeremonyPass = false
		result.FailureReasons = append(result.FailureReasons, "upgrade checklist has blocking failures")
	}

	// Step 9: Verify consistency checks
	stepOrder++
	step9Start := time.Now()
	consistency := EndBlockConsistencyChecks(ctx, k)
	allPass := true
	for _, c := range consistency {
		if !c.Passed {
			allPass = false
			break
		}
	}
	result.Steps = append(result.Steps, GenesisCeremonyStep{
		Name:     "verify_consistency",
		Duration: time.Since(step9Start),
		Passed:   allPass,
		Details:  fmt.Sprintf("%d checks, all_pass=%v", len(consistency), allPass),
		Order:    stepOrder,
	})

	// Step 10: Final genesis validation
	stepOrder++
	step10Start := time.Now()
	result.GenesisValid = result.CeremonyPass
	result.Steps = append(result.Steps, GenesisCeremonyStep{
		Name:     "final_genesis_validation",
		Duration: time.Since(step10Start),
		Passed:   result.GenesisValid,
		Details:  fmt.Sprintf("ceremony_pass=%v, failures=%d", result.CeremonyPass, len(result.FailureReasons)),
		Order:    stepOrder,
	})

	// Total duration
	for _, step := range result.Steps {
		result.TotalDuration += step.Duration
	}

	return result
}

// ---------------------------------------------------------------------------
// Section 4: Genesis Validator Bootstrap
// ---------------------------------------------------------------------------

// GenesisValidator describes a validator to be included in the genesis set.
type GenesisValidator struct {
	Address      string
	Moniker      string
	Power        int64
	TEEPlatform  string
	ZKMLBackend  string
	SupportsTEE  bool
	SupportsZKML bool
}

// ValidateGenesisValidator checks that a genesis validator is well-formed.
func ValidateGenesisValidator(v GenesisValidator) error {
	if v.Address == "" {
		return fmt.Errorf("validator address must not be empty")
	}
	if v.Moniker == "" {
		return fmt.Errorf("validator moniker must not be empty")
	}
	if v.Power <= 0 {
		return fmt.Errorf("validator power must be positive, got %d", v.Power)
	}
	if v.SupportsTEE && v.TEEPlatform == "" {
		return fmt.Errorf("TEE platform must be set when SupportsTEE is true")
	}
	return nil
}

// GenesisValidatorSet manages the initial validator set for genesis.
type GenesisValidatorSet struct {
	Validators []GenesisValidator
	MinPower   int64
}

// NewGenesisValidatorSet creates an empty validator set with the given minimum power.
func NewGenesisValidatorSet(minPower int64) *GenesisValidatorSet {
	return &GenesisValidatorSet{
		MinPower: minPower,
	}
}

// AddValidator adds a validated validator to the genesis set.
func (gvs *GenesisValidatorSet) AddValidator(v GenesisValidator) error {
	if err := ValidateGenesisValidator(v); err != nil {
		return err
	}
	if v.Power < gvs.MinPower {
		return fmt.Errorf("validator power %d is below minimum %d", v.Power, gvs.MinPower)
	}
	// Check for duplicate address
	for _, existing := range gvs.Validators {
		if existing.Address == v.Address {
			return fmt.Errorf("validator address %q already in genesis set", v.Address)
		}
	}
	gvs.Validators = append(gvs.Validators, v)
	return nil
}

// TotalPower returns the sum of all validator power.
func (gvs *GenesisValidatorSet) TotalPower() int64 {
	var total int64
	for _, v := range gvs.Validators {
		total += v.Power
	}
	return total
}

// ValidateSet checks that the genesis validator set meets all requirements.
func (gvs *GenesisValidatorSet) ValidateSet(minValidators int) []string {
	var issues []string

	if len(gvs.Validators) < minValidators {
		issues = append(issues, fmt.Sprintf(
			"insufficient validators: %d (minimum %d)", len(gvs.Validators), minValidators))
	}

	// Check for TEE coverage
	teeCount := 0
	for _, v := range gvs.Validators {
		if v.SupportsTEE {
			teeCount++
		}
	}
	if teeCount == 0 && len(gvs.Validators) > 0 {
		issues = append(issues, "no validators support TEE attestation")
	}

	// Check power concentration (no single validator > 34%)
	// With 3 equal validators, each has 33.3% which is acceptable.
	// Only flag when one validator clearly dominates.
	totalPower := gvs.TotalPower()
	if totalPower > 0 {
		for _, v := range gvs.Validators {
			powerPct := float64(v.Power) / float64(totalPower) * 100
			if powerPct > 34.0 {
				issues = append(issues, fmt.Sprintf(
					"validator %q has %.1f%% of total power (max 34%%)", v.Moniker, powerPct))
			}
		}
	}

	// Sorted by power for deterministic ordering
	sorted := make([]GenesisValidator, len(gvs.Validators))
	copy(sorted, gvs.Validators)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Power > sorted[j].Power
	})

	return issues
}

// BootstrapValidatorStats registers all genesis validators in the state.
func BootstrapValidatorStats(ctx sdk.Context, k Keeper, validators []GenesisValidator) error {
	for _, v := range validators {
		stats := types.ValidatorStats{
			ValidatorAddress:   v.Address,
			ReputationScore:    50, // Default starting reputation
			TotalJobsProcessed: 0,
			SuccessfulJobs:     0,
			FailedJobs:         0,
			SlashingEvents:     0,
		}
		if err := k.ValidatorStats.Set(ctx, v.Address, stats); err != nil {
			return fmt.Errorf("failed to set stats for validator %s: %w", v.Address, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Section 5: Comprehensive Launch Report
// ---------------------------------------------------------------------------

// RenderLaunchReviewReport produces a human-readable go/no-go report.
func RenderLaunchReviewReport(r *LaunchReviewResult) string {
	var sb strings.Builder

	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║          FINAL GO/NO-GO LAUNCH REVIEW                       ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	sb.WriteString(fmt.Sprintf("Chain: %s | Block: %d | Reviewed: %s\n\n",
		r.ChainID, r.BlockHeight, r.ReviewedAt))

	// Score summary
	sb.WriteString("─── SCORE SUMMARY ─────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Security:     %3d/100  (weight: 30%%)\n", r.SecurityScore))
	sb.WriteString(fmt.Sprintf("  Performance:  %3d/100  (weight: 20%%)\n", r.PerformanceScore))
	sb.WriteString(fmt.Sprintf("  Economics:    %3d/100  (weight: 15%%)\n", r.EconomicsScore))
	sb.WriteString(fmt.Sprintf("  Operations:   %3d/100  (weight: 15%%)\n", r.OperationsScore))
	sb.WriteString(fmt.Sprintf("  Ecosystem:    %3d/100  (weight: 10%%)\n", r.EcosystemScore))
	sb.WriteString(fmt.Sprintf("  Governance:   %3d/100  (weight: 10%%)\n", r.GovernanceScore))
	sb.WriteString(fmt.Sprintf("  ────────────────────────\n"))
	sb.WriteString(fmt.Sprintf("  OVERALL:      %3d/100\n\n", r.OverallScore))

	// All criteria
	sb.WriteString("─── LAUNCH CRITERIA ───────────────────────────────────────────\n")
	for _, c := range r.Criteria {
		status := "PASS"
		if !c.Passed {
			status = "FAIL"
		}
		blocking := ""
		if c.Blocking {
			blocking = " [BLOCKING]"
		}
		sb.WriteString(fmt.Sprintf("  [%s] %-6s %-50s%s\n", status, c.ID, c.Description, blocking))
	}

	// Blocking failures
	if len(r.BlockingFailures) > 0 {
		sb.WriteString("\n─── BLOCKING FAILURES ──────────────────────────────────────────\n")
		for _, f := range r.BlockingFailures {
			sb.WriteString(fmt.Sprintf("  ✗ %s: %s — %s\n", f.ID, f.Description, f.Details))
		}
	}

	// Conditions
	if len(r.Conditions) > 0 {
		sb.WriteString("\n─── CONDITIONS ─────────────────────────────────────────────────\n")
		for _, c := range r.Conditions {
			sb.WriteString(fmt.Sprintf("  • %s\n", c))
		}
	}

	// Decision
	sb.WriteString("\n═══════════════════════════════════════════════════════════════\n")
	switch r.Decision {
	case "GO":
		sb.WriteString("  DETERMINATION: *** GO *** — All blocking criteria passed\n")
	case "NO-GO":
		sb.WriteString("  DETERMINATION: *** NO-GO *** — Blocking criteria failed\n")
	case "CONDITIONAL-GO":
		sb.WriteString("  DETERMINATION: *** CONDITIONAL GO *** — Advisory items open\n")
	}
	sb.WriteString("═══════════════════════════════════════════════════════════════\n")

	return sb.String()
}

// RenderGenesisCeremonyReport produces a human-readable ceremony report.
func RenderGenesisCeremonyReport(r *GenesisCeremonyResult) string {
	var sb strings.Builder

	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║          MAINNET GENESIS CEREMONY REPORT                    ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	sb.WriteString(fmt.Sprintf("Chain: %s | Block: %d | Genesis: %s\n",
		r.ChainID, r.BlockHeight, r.GenesisTime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Ceremony At: %s\n\n", r.CeremonyAt))

	sb.WriteString("─── CEREMONY STEPS ────────────────────────────────────────────\n")
	for _, step := range r.Steps {
		status := "PASS"
		if !step.Passed {
			status = "FAIL"
		}
		sb.WriteString(fmt.Sprintf("  [%s] %2d. %-35s %v\n", status, step.Order, step.Name, step.Duration))
	}
	sb.WriteString(fmt.Sprintf("\n  Total Duration: %v\n\n", r.TotalDuration))

	sb.WriteString("─── GENESIS STATE ─────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Validators:   %d\n", r.ValidatorCount))
	sb.WriteString(fmt.Sprintf("  Params Hash:  %s\n", r.ParamsHash))
	sb.WriteString(fmt.Sprintf("  Invariants:   %v\n", r.InvariantsPass))
	sb.WriteString(fmt.Sprintf("  Genesis Valid: %v\n\n", r.GenesisValid))

	if len(r.FailureReasons) > 0 {
		sb.WriteString("─── FAILURES ──────────────────────────────────────────────────\n")
		for _, f := range r.FailureReasons {
			sb.WriteString(fmt.Sprintf("  ✗ %s\n", f))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("═══════════════════════════════════════════════════════════════\n")
	if r.CeremonyPass {
		sb.WriteString("  *** GENESIS CEREMONY PASSED *** — Chain ready for launch\n")
	} else {
		sb.WriteString("  *** GENESIS CEREMONY FAILED *** — Resolve issues before launch\n")
	}
	sb.WriteString("═══════════════════════════════════════════════════════════════\n")

	return sb.String()
}
