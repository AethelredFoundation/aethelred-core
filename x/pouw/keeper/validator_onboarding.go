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
// WEEK 40: Validator Onboarding Full Rollout
// ---------------------------------------------------------------------------
//
// This file implements the complete validator onboarding pipeline:
//   1. Onboarding application — structured registration request
//   2. Capability verification — hardware and software checks
//   3. Onboarding checklist — automated prerequisite validation
//   4. Validator readiness scoring — composite readiness assessment
//   5. Onboarding report — human-readable onboarding status dashboard
//
// The onboarding flow:
//   Application → Capability Check → Prerequisite Checklist → Readiness Score → Approval
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Section 1: Onboarding Application
// ---------------------------------------------------------------------------

// OnboardingApplication represents a validator's registration request.
type OnboardingApplication struct {
	ValidatorAddr    string
	Moniker          string
	OperatorContact  string
	AppliedAt        time.Time

	// Hardware declaration
	TEEPlatform      string   // e.g., "nitro", "sgx", "tdx"
	TEEVersion       string
	ZKMLBackend      string   // e.g., "ezkl", "halo2"
	MaxConcurrentJobs int32

	// Network info
	NodeVersion      string
	ChainID          string

	// Self-reported capabilities
	SupportsTEE      bool
	SupportsZKML     bool
	SupportsHybrid   bool
}

// OnboardingStatus tracks where a validator is in the onboarding pipeline.
type OnboardingStatus string

const (
	OnboardingPending    OnboardingStatus = "pending"
	OnboardingVerifying  OnboardingStatus = "verifying"
	OnboardingApproved   OnboardingStatus = "approved"
	OnboardingRejected   OnboardingStatus = "rejected"
	OnboardingActive     OnboardingStatus = "active"
)

// OnboardingRecord is the full state of a validator's onboarding process.
type OnboardingRecord struct {
	Application    OnboardingApplication
	Status         OnboardingStatus
	ChecklistItems []OnboardingCheckItem
	ReadinessScore int
	ApprovedAt     *time.Time
	RejectedAt     *time.Time
	RejectionNote  string
}

// ValidateApplication performs basic validation of an onboarding application.
func ValidateApplication(app OnboardingApplication) error {
	if app.ValidatorAddr == "" {
		return fmt.Errorf("validator address must not be empty")
	}
	if app.Moniker == "" {
		return fmt.Errorf("moniker must not be empty")
	}
	if app.MaxConcurrentJobs <= 0 {
		return fmt.Errorf("max_concurrent_jobs must be > 0, got %d", app.MaxConcurrentJobs)
	}
	if !app.SupportsTEE && !app.SupportsZKML && !app.SupportsHybrid {
		return fmt.Errorf("validator must support at least one proof type")
	}
	if app.TEEPlatform == "" && app.SupportsTEE {
		return fmt.Errorf("TEE platform must be specified when SupportsTEE=true")
	}
	if app.NodeVersion == "" {
		return fmt.Errorf("node version must not be empty")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Section 2: Capability Verification
// ---------------------------------------------------------------------------

// CapabilityCheckResult captures the result of verifying a validator's capabilities.
type CapabilityCheckResult struct {
	Category    string
	Check       string
	Passed      bool
	Details     string
	Required    bool
}

// VerifyCapabilities runs all capability checks for an onboarding application.
func VerifyCapabilities(app OnboardingApplication) []CapabilityCheckResult {
	var checks []CapabilityCheckResult

	// CAP-01: TEE platform supported
	validTEE := map[string]bool{"nitro": true, "sgx": true, "tdx": true, "": true}
	checks = append(checks, CapabilityCheckResult{
		Category: "hardware",
		Check:    "tee_platform_valid",
		Passed:   validTEE[app.TEEPlatform],
		Details:  fmt.Sprintf("platform=%q", app.TEEPlatform),
		Required: app.SupportsTEE,
	})

	// CAP-02: ZKML backend supported
	validZKML := map[string]bool{"ezkl": true, "halo2": true, "": true}
	checks = append(checks, CapabilityCheckResult{
		Category: "software",
		Check:    "zkml_backend_valid",
		Passed:   validZKML[app.ZKMLBackend],
		Details:  fmt.Sprintf("backend=%q", app.ZKMLBackend),
		Required: app.SupportsZKML,
	})

	// CAP-03: Concurrent job capacity reasonable
	checks = append(checks, CapabilityCheckResult{
		Category: "capacity",
		Check:    "concurrent_jobs_valid",
		Passed:   app.MaxConcurrentJobs >= 1 && app.MaxConcurrentJobs <= 50,
		Details:  fmt.Sprintf("max_concurrent=%d", app.MaxConcurrentJobs),
		Required: true,
	})

	// CAP-04: At least one proof type supported
	proofTypeCount := 0
	if app.SupportsTEE {
		proofTypeCount++
	}
	if app.SupportsZKML {
		proofTypeCount++
	}
	if app.SupportsHybrid {
		proofTypeCount++
	}
	checks = append(checks, CapabilityCheckResult{
		Category: "capability",
		Check:    "proof_type_support",
		Passed:   proofTypeCount >= 1,
		Details:  fmt.Sprintf("%d proof types supported", proofTypeCount),
		Required: true,
	})

	// CAP-05: Hybrid requires both TEE and ZKML
	hybridValid := !app.SupportsHybrid || (app.SupportsTEE && app.SupportsZKML)
	checks = append(checks, CapabilityCheckResult{
		Category: "capability",
		Check:    "hybrid_prerequisites",
		Passed:   hybridValid,
		Details:  fmt.Sprintf("hybrid=%v, tee=%v, zkml=%v", app.SupportsHybrid, app.SupportsTEE, app.SupportsZKML),
		Required: app.SupportsHybrid,
	})

	// CAP-06: Node version present
	checks = append(checks, CapabilityCheckResult{
		Category: "software",
		Check:    "node_version_present",
		Passed:   app.NodeVersion != "",
		Details:  fmt.Sprintf("version=%q", app.NodeVersion),
		Required: true,
	})

	return checks
}

// AllRequiredCapabilitiesPass returns true if all required checks pass.
func AllRequiredCapabilitiesPass(checks []CapabilityCheckResult) bool {
	for _, c := range checks {
		if c.Required && !c.Passed {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Section 3: Onboarding Checklist
// ---------------------------------------------------------------------------

// OnboardingCheckItem is a single item in the onboarding checklist.
type OnboardingCheckItem struct {
	ID          string
	Category    string
	Description string
	Passed      bool
	Details     string
	Required    bool
}

// RunOnboardingChecklist performs all onboarding prerequisite checks.
func RunOnboardingChecklist(ctx sdk.Context, k Keeper, app OnboardingApplication) []OnboardingCheckItem {
	var items []OnboardingCheckItem

	// OB-01: Application is valid
	appErr := ValidateApplication(app)
	items = append(items, OnboardingCheckItem{
		ID:          "OB-01",
		Category:    "application",
		Description: "Application passes validation",
		Passed:      appErr == nil,
		Details:     fmt.Sprintf("err=%v", appErr),
		Required:    true,
	})

	// OB-02: Not already registered
	_, existsErr := k.ValidatorStats.Get(ctx, app.ValidatorAddr)
	alreadyRegistered := existsErr == nil
	items = append(items, OnboardingCheckItem{
		ID:          "OB-02",
		Category:    "registration",
		Description: "Validator not already registered",
		Passed:      !alreadyRegistered,
		Details:     fmt.Sprintf("already_registered=%v", alreadyRegistered),
		Required:    true,
	})

	// OB-03: All capabilities verified
	capChecks := VerifyCapabilities(app)
	capsPass := AllRequiredCapabilitiesPass(capChecks)
	items = append(items, OnboardingCheckItem{
		ID:          "OB-03",
		Category:    "capability",
		Description: "All required capabilities verified",
		Passed:      capsPass,
		Details:     fmt.Sprintf("%d checks, all_required_pass=%v", len(capChecks), capsPass),
		Required:    true,
	})

	// OB-04: Chain ID matches
	items = append(items, OnboardingCheckItem{
		ID:          "OB-04",
		Category:    "network",
		Description: "Chain ID matches current chain",
		Passed:      app.ChainID == "" || app.ChainID == ctx.ChainID(),
		Details:     fmt.Sprintf("app=%q, chain=%q", app.ChainID, ctx.ChainID()),
		Required:    false, // Warning only if different
	})

	// OB-05: Module params are valid (chain is healthy)
	params, err := k.GetParams(ctx)
	paramsValid := err == nil && params != nil && ValidateParams(params) == nil
	items = append(items, OnboardingCheckItem{
		ID:          "OB-05",
		Category:    "chain_health",
		Description: "Module parameters are valid",
		Passed:      paramsValid,
		Details:     fmt.Sprintf("valid=%v", paramsValid),
		Required:    true,
	})

	// OB-06: Moniker is unique
	monikerUnique := true
	_ = k.ValidatorStats.Walk(ctx, nil, func(addr string, s types.ValidatorStats) (bool, error) {
		// ValidatorStats doesn't have moniker, but we check address uniqueness
		if addr == app.ValidatorAddr {
			monikerUnique = false
		}
		return false, nil
	})
	items = append(items, OnboardingCheckItem{
		ID:          "OB-06",
		Category:    "registration",
		Description: "Validator address is unique",
		Passed:      monikerUnique,
		Details:     fmt.Sprintf("addr=%s", app.ValidatorAddr),
		Required:    true,
	})

	return items
}

// ---------------------------------------------------------------------------
// Section 4: Validator Readiness Scoring
// ---------------------------------------------------------------------------

// ComputeOnboardingReadiness calculates a 0-100 readiness score for a
// validator based on their application and checklist results.
func ComputeOnboardingReadiness(app OnboardingApplication, checks []OnboardingCheckItem) int {
	score := 0
	maxScore := 0

	// Application completeness (30 points)
	maxScore += 30
	appComplete := 0
	if app.ValidatorAddr != "" {
		appComplete += 5
	}
	if app.Moniker != "" {
		appComplete += 5
	}
	if app.OperatorContact != "" {
		appComplete += 5
	}
	if app.TEEPlatform != "" {
		appComplete += 5
	}
	if app.NodeVersion != "" {
		appComplete += 5
	}
	if app.MaxConcurrentJobs > 0 {
		appComplete += 5
	}
	score += appComplete

	// Capability breadth (30 points)
	maxScore += 30
	capScore := 0
	if app.SupportsTEE {
		capScore += 10
	}
	if app.SupportsZKML {
		capScore += 10
	}
	if app.SupportsHybrid {
		capScore += 10
	}
	score += capScore

	// Checklist pass rate (40 points)
	maxScore += 40
	if len(checks) > 0 {
		passed := 0
		for _, c := range checks {
			if c.Passed {
				passed++
			}
		}
		checkScore := (passed * 40) / len(checks)
		score += checkScore
	}

	// Clamp to [0, 100]
	if score > maxScore {
		score = maxScore
	}
	if score < 0 {
		score = 0
	}

	// Scale to percentage
	return (score * 100) / maxScore
}

// OnboardingApprovalThreshold is the minimum readiness score for automatic approval.
const OnboardingApprovalThreshold = 80

// ShouldAutoApprove returns true if the readiness score meets the threshold
// and all required checklist items pass.
func ShouldAutoApprove(readinessScore int, checks []OnboardingCheckItem) bool {
	if readinessScore < OnboardingApprovalThreshold {
		return false
	}
	for _, c := range checks {
		if c.Required && !c.Passed {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Section 5: Onboarding Report
// ---------------------------------------------------------------------------

// OnboardingDashboard summarizes the onboarding status across all validators.
type OnboardingDashboard struct {
	ChainID          string
	BlockHeight      int64
	GeneratedAt      string

	TotalValidators  int
	ActiveValidators int

	// Capability coverage
	TEECapable       int
	ZKMLCapable      int
	HybridCapable    int

	// Health
	AvgReputation    float64
	TotalSlashing    int64

	// Capacity
	TotalCapacity    int64  // sum of MaxConcurrentJobs across all validators
}

// BuildOnboardingDashboard creates a dashboard from on-chain state.
func BuildOnboardingDashboard(ctx sdk.Context, k Keeper) *OnboardingDashboard {
	dash := &OnboardingDashboard{
		ChainID:     ctx.ChainID(),
		BlockHeight: ctx.BlockHeight(),
		GeneratedAt: ctx.BlockTime().UTC().Format(time.RFC3339),
	}

	var repSum int64
	_ = k.ValidatorStats.Walk(ctx, nil, func(_ string, s types.ValidatorStats) (bool, error) {
		dash.TotalValidators++
		repSum += s.ReputationScore
		dash.TotalSlashing += s.SlashingEvents
		return false, nil
	})

	if dash.TotalValidators > 0 {
		dash.AvgReputation = float64(repSum) / float64(dash.TotalValidators)
	}

	_ = k.ValidatorCapabilities.Walk(ctx, nil, func(_ string, cap types.ValidatorCapability) (bool, error) {
		if cap.IsOnline {
			dash.ActiveValidators++
		}
		if len(cap.TeePlatforms) > 0 {
			dash.TEECapable++
		}
		if len(cap.ZkmlSystems) > 0 {
			dash.ZKMLCapable++
		}
		if len(cap.TeePlatforms) > 0 && len(cap.ZkmlSystems) > 0 {
			dash.HybridCapable++
		}
		dash.TotalCapacity += cap.MaxConcurrentJobs
		return false, nil
	})

	return dash
}

// RenderOnboardingReport produces a human-readable onboarding report.
func RenderOnboardingReport(ctx sdk.Context, k Keeper) string {
	dash := BuildOnboardingDashboard(ctx, k)
	var sb strings.Builder

	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║          VALIDATOR ONBOARDING DASHBOARD                     ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	sb.WriteString(fmt.Sprintf("Chain: %s | Block: %d | Time: %s\n\n", dash.ChainID, dash.BlockHeight, dash.GeneratedAt))

	sb.WriteString("─── VALIDATOR SET ─────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Total Registered:   %d\n", dash.TotalValidators))
	sb.WriteString(fmt.Sprintf("  Active (Online):    %d\n", dash.ActiveValidators))
	sb.WriteString(fmt.Sprintf("  Avg Reputation:     %.1f / 100\n", dash.AvgReputation))
	sb.WriteString(fmt.Sprintf("  Total Slashing:     %d events\n", dash.TotalSlashing))

	sb.WriteString("\n─── CAPABILITY COVERAGE ────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  TEE Capable:       %d validators\n", dash.TEECapable))
	sb.WriteString(fmt.Sprintf("  ZKML Capable:      %d validators\n", dash.ZKMLCapable))
	sb.WriteString(fmt.Sprintf("  Hybrid Capable:    %d validators\n", dash.HybridCapable))
	sb.WriteString(fmt.Sprintf("  Total Capacity:    %d concurrent jobs\n", dash.TotalCapacity))

	// Readiness assessment
	params, _ := k.GetParams(ctx)
	sb.WriteString("\n─── READINESS ASSESSMENT ──────────────────────────────────────\n")
	if params != nil {
		minVal := params.MinValidators
		if int64(dash.ActiveValidators) >= minVal {
			sb.WriteString(fmt.Sprintf("  ✓ Active validators (%d) meets minimum (%d)\n",
				dash.ActiveValidators, minVal))
		} else {
			sb.WriteString(fmt.Sprintf("  ✗ Active validators (%d) below minimum (%d)\n",
				dash.ActiveValidators, minVal))
		}
	}

	sb.WriteString("\n══════════════════════════════════════════════════════════════\n")

	return sb.String()
}

// ---------------------------------------------------------------------------
// Section 6: Batch Onboarding Utilities
// ---------------------------------------------------------------------------

// OnboardingSummary describes the aggregate result of processing multiple applications.
type OnboardingSummary struct {
	Total       int
	Approved    int
	Rejected    int
	Pending     int
	Results     []OnboardingRecord
}

// ProcessApplicationBatch validates and scores a batch of applications.
func ProcessApplicationBatch(ctx sdk.Context, k Keeper, apps []OnboardingApplication) *OnboardingSummary {
	summary := &OnboardingSummary{
		Total: len(apps),
	}

	for _, app := range apps {
		record := OnboardingRecord{
			Application: app,
			Status:      OnboardingPending,
		}

		// Run checklist
		record.ChecklistItems = RunOnboardingChecklist(ctx, k, app)

		// Compute readiness
		record.ReadinessScore = ComputeOnboardingReadiness(app, record.ChecklistItems)

		// Determine approval
		if ShouldAutoApprove(record.ReadinessScore, record.ChecklistItems) {
			record.Status = OnboardingApproved
			now := ctx.BlockTime().UTC()
			record.ApprovedAt = &now
			summary.Approved++
		} else {
			// Check if any required items failed
			anyRequired := false
			for _, item := range record.ChecklistItems {
				if item.Required && !item.Passed {
					anyRequired = true
					break
				}
			}
			if anyRequired {
				record.Status = OnboardingRejected
				now := ctx.BlockTime().UTC()
				record.RejectedAt = &now
				record.RejectionNote = "one or more required checklist items failed"
				summary.Rejected++
			} else {
				record.Status = OnboardingPending
				summary.Pending++
			}
		}

		summary.Results = append(summary.Results, record)
	}

	// Sort results by readiness score descending
	sort.Slice(summary.Results, func(i, j int) bool {
		return summary.Results[i].ReadinessScore > summary.Results[j].ReadinessScore
	})

	return summary
}
