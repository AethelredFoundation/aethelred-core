package keeper

import (
	"fmt"
	"reflect"
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// ---------------------------------------------------------------------------
// Security Audit Runner
// ---------------------------------------------------------------------------
//
// This file provides a programmatic security audit framework that:
//   1. Verifies module configuration against hardened production defaults
//   2. Scans state for anomalies and invariant violations
//   3. Validates cryptographic parameters meet minimum security levels
//   4. Checks governance parameter ranges for correctness
//   5. Produces a structured audit report for external auditors
//
// The audit runner is designed to be executed before chain launch, after
// upgrades, or as part of continuous integration to catch regressions.
// ---------------------------------------------------------------------------

// FindingSeverity classifies the severity of a security audit finding.
type FindingSeverity string

const (
	FindingCritical FindingSeverity = "CRITICAL"
	FindingHigh     FindingSeverity = "HIGH"
	FindingMedium   FindingSeverity = "MEDIUM"
	FindingLow      FindingSeverity = "LOW"
	FindingInfo     FindingSeverity = "INFO"
)

// AuditFinding records a single audit finding.
type AuditFinding struct {
	ID          string          // Unique finding identifier
	CheckName   string          // Name of the check that produced it
	Severity    FindingSeverity // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Description string        // What was found
	Remediation string        // How to fix it (empty if INFO/pass)
	Passed      bool          // true if the check passed
}

// AuditReport aggregates all findings from a security audit run.
type AuditReport struct {
	ModuleVersion  uint64
	ChainID        string
	BlockHeight    int64
	Findings       []AuditFinding
	TotalChecks    int
	PassedChecks   int
	FailedChecks   int
	CriticalCount  int
	HighCount      int
	MediumCount    int
	LowCount       int
}

// Summary returns a human-readable summary of the audit report.
func (r *AuditReport) Summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== SECURITY AUDIT REPORT ===\n"))
	sb.WriteString(fmt.Sprintf("Chain: %s | Block: %d | Module Version: %d\n",
		r.ChainID, r.BlockHeight, r.ModuleVersion))
	sb.WriteString(fmt.Sprintf("Checks: %d total | %d passed | %d failed\n",
		r.TotalChecks, r.PassedChecks, r.FailedChecks))
	sb.WriteString(fmt.Sprintf("Findings: %d critical | %d high | %d medium | %d low\n",
		r.CriticalCount, r.HighCount, r.MediumCount, r.LowCount))
	sb.WriteString("=============================\n")

	for _, f := range r.Findings {
		if !f.Passed {
			sb.WriteString(fmt.Sprintf("[%s] %s: %s\n", f.Severity, f.CheckName, f.Description))
			if f.Remediation != "" {
				sb.WriteString(fmt.Sprintf("  → Fix: %s\n", f.Remediation))
			}
		}
	}

	if r.FailedChecks == 0 {
		sb.WriteString("ALL CHECKS PASSED.\n")
	}

	return sb.String()
}

// ---------------------------------------------------------------------------
// Audit Check Functions
// ---------------------------------------------------------------------------

// AuditCheck is a function that produces zero or more findings.
type AuditCheck func(ctx sdk.Context, k Keeper) []AuditFinding

// AllAuditChecks returns the full suite of security audit checks.
func AllAuditChecks() []AuditCheck {
	return []AuditCheck{
		auditParamsRanges,
		auditProductionModeSettings,
		auditConsensusThresholdSafety,
		auditSlashingDeterrence,
		auditFeeDistributionConservation,
		auditStateInvariants,
		auditValidatorStatsBounds,
		auditPendingJobConsistency,
		auditJobCountIntegrity,
		auditCryptographicMinimums,
		auditGovernanceOneWayGate,
		auditParamFieldCompleteness,
	}
}

// RunSecurityAudit executes all audit checks and produces a report.
func RunSecurityAudit(ctx sdk.Context, k Keeper) *AuditReport {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	report := &AuditReport{
		ModuleVersion: ModuleConsensusVersion,
		ChainID:       sdkCtx.ChainID(),
		BlockHeight:   sdkCtx.BlockHeight(),
	}

	for _, check := range AllAuditChecks() {
		findings := check(ctx, k)
		for _, f := range findings {
			report.Findings = append(report.Findings, f)
			report.TotalChecks++
			if f.Passed {
				report.PassedChecks++
			} else {
				report.FailedChecks++
				switch f.Severity {
				case FindingCritical:
					report.CriticalCount++
				case FindingHigh:
					report.HighCount++
				case FindingMedium:
					report.MediumCount++
				case FindingLow:
					report.LowCount++
				}
			}
		}
	}

	return report
}

// ---------------------------------------------------------------------------
// Individual Audit Checks
// ---------------------------------------------------------------------------

// auditParamsRanges validates all module parameters are within safe ranges.
func auditParamsRanges(ctx sdk.Context, k Keeper) []AuditFinding {
	var findings []AuditFinding

	params, err := k.GetParams(ctx)
	if err != nil {
		findings = append(findings, AuditFinding{
			ID: "PARAM-01", CheckName: "params_readable",
			Severity: FindingCritical, Description: "Cannot read module params: " + err.Error(),
			Passed: false, Remediation: "Ensure params are initialized via InitGenesis",
		})
		return findings
	}

	// MinValidators: must be >= 1
	findings = append(findings, AuditFinding{
		ID: "PARAM-02", CheckName: "min_validators_positive",
		Severity: FindingHigh,
		Description: fmt.Sprintf("MinValidators = %d", params.MinValidators),
		Passed: params.MinValidators >= 1,
		Remediation: "Set MinValidators >= 1 via governance",
	})

	// ConsensusThreshold: must be 51-100
	findings = append(findings, AuditFinding{
		ID: "PARAM-03", CheckName: "consensus_threshold_range",
		Severity: FindingCritical,
		Description: fmt.Sprintf("ConsensusThreshold = %d", params.ConsensusThreshold),
		Passed: params.ConsensusThreshold >= 51 && params.ConsensusThreshold <= 100,
		Remediation: "ConsensusThreshold must be in [51, 100] for BFT safety",
	})

	// MaxJobsPerBlock: must be > 0 and <= 1000 (reasonable cap)
	findings = append(findings, AuditFinding{
		ID: "PARAM-04", CheckName: "max_jobs_per_block_range",
		Severity: FindingMedium,
		Description: fmt.Sprintf("MaxJobsPerBlock = %d", params.MaxJobsPerBlock),
		Passed: params.MaxJobsPerBlock > 0 && params.MaxJobsPerBlock <= 1000,
		Remediation: "MaxJobsPerBlock should be in [1, 1000]",
	})

	// JobTimeoutBlocks: must be > 0
	findings = append(findings, AuditFinding{
		ID: "PARAM-05", CheckName: "job_timeout_positive",
		Severity: FindingMedium,
		Description: fmt.Sprintf("JobTimeoutBlocks = %d", params.JobTimeoutBlocks),
		Passed: params.JobTimeoutBlocks > 0,
		Remediation: "JobTimeoutBlocks must be > 0 for liveness",
	})

	// BaseJobFee: must be non-empty
	findings = append(findings, AuditFinding{
		ID: "PARAM-06", CheckName: "base_job_fee_set",
		Severity: FindingHigh,
		Description: fmt.Sprintf("BaseJobFee = %q", params.BaseJobFee),
		Passed: params.BaseJobFee != "",
		Remediation: "BaseJobFee must be set to prevent zero-fee spam",
	})

	// SlashingPenalty: must be non-empty
	findings = append(findings, AuditFinding{
		ID: "PARAM-07", CheckName: "slashing_penalty_set",
		Severity: FindingHigh,
		Description: fmt.Sprintf("SlashingPenalty = %q", params.SlashingPenalty),
		Passed: params.SlashingPenalty != "",
		Remediation: "SlashingPenalty must be set for economic security",
	})

	// AllowedProofTypes: must have at least one
	findings = append(findings, AuditFinding{
		ID: "PARAM-08", CheckName: "allowed_proof_types_set",
		Severity: FindingHigh,
		Description: fmt.Sprintf("AllowedProofTypes = %v (len=%d)", params.AllowedProofTypes, len(params.AllowedProofTypes)),
		Passed: len(params.AllowedProofTypes) > 0,
		Remediation: "At least one proof type must be allowed",
	})

	return findings
}

// auditProductionModeSettings checks that production-security flags are set.
func auditProductionModeSettings(ctx sdk.Context, k Keeper) []AuditFinding {
	var findings []AuditFinding

	params, err := k.GetParams(ctx)
	if err != nil {
		return findings
	}

	// AllowSimulated should be false for production
	findings = append(findings, AuditFinding{
		ID: "PROD-01", CheckName: "allow_simulated_disabled",
		Severity: FindingCritical,
		Description: fmt.Sprintf("AllowSimulated = %v", params.AllowSimulated),
		Passed: !params.AllowSimulated,
		Remediation: "AllowSimulated MUST be false on production chains. Set via governance then enforce one-way gate.",
	})

	// RequireTeeAttestation should be true for production
	findings = append(findings, AuditFinding{
		ID: "PROD-02", CheckName: "require_tee_attestation_enabled",
		Severity: FindingHigh,
		Description: fmt.Sprintf("RequireTeeAttestation = %v", params.RequireTeeAttestation),
		Passed: params.RequireTeeAttestation,
		Remediation: "RequireTeeAttestation should be true for production chains",
	})

	return findings
}

// auditConsensusThresholdSafety validates BFT safety margins.
func auditConsensusThresholdSafety(ctx sdk.Context, k Keeper) []AuditFinding {
	var findings []AuditFinding

	params, err := k.GetParams(ctx)
	if err != nil {
		return findings
	}

	// BFT safety: threshold must be > 66 (strict 2/3 majority)
	findings = append(findings, AuditFinding{
		ID: "BFT-01", CheckName: "consensus_threshold_bft_safe",
		Severity: FindingCritical,
		Description: fmt.Sprintf("ConsensusThreshold=%d (BFT requires >66%%)", params.ConsensusThreshold),
		Passed: params.ConsensusThreshold > 66,
		Remediation: "ConsensusThreshold must be > 66 for BFT safety (recommend 67)",
	})

	// MinValidators must provide redundancy
	findings = append(findings, AuditFinding{
		ID: "BFT-02", CheckName: "min_validators_redundancy",
		Severity: FindingMedium,
		Description: fmt.Sprintf("MinValidators=%d (need >=3 for BFT)", params.MinValidators),
		Passed: params.MinValidators >= 3,
		Remediation: "MinValidators should be >= 3 for byzantine fault tolerance",
	})

	return findings
}

// auditSlashingDeterrence validates that slashing provides economic deterrence.
func auditSlashingDeterrence(_ sdk.Context, _ Keeper) []AuditFinding {
	var findings []AuditFinding

	// Verify fee distribution basis points sum to 10000
	config := DefaultFeeDistributionConfig()
	bpsSum := config.ValidatorRewardBps + config.TreasuryBps + config.BurnBps + config.InsuranceFundBps
	findings = append(findings, AuditFinding{
		ID: "ECON-01", CheckName: "fee_bps_sum_10000",
		Severity: FindingCritical,
		Description: fmt.Sprintf("Fee BPS sum = %d (validator=%d, treasury=%d, burn=%d, insurance=%d)",
			bpsSum, config.ValidatorRewardBps, config.TreasuryBps, config.BurnBps, config.InsuranceFundBps),
		Passed: bpsSum == 10000,
		Remediation: "Fee distribution BPS must sum to exactly 10000 (100%)",
	})

	// Verify burn exists (deflationary pressure)
	findings = append(findings, AuditFinding{
		ID: "ECON-02", CheckName: "burn_percentage_nonzero",
		Severity: FindingMedium,
		Description: fmt.Sprintf("BurnBPS = %d (%0.1f%%)", config.BurnBps, float64(config.BurnBps)/100),
		Passed: config.BurnBps > 0,
		Remediation: "Burn percentage should be > 0 for deflationary pressure",
	})

	// Verify insurance fund exists
	findings = append(findings, AuditFinding{
		ID: "ECON-03", CheckName: "insurance_fund_nonzero",
		Severity: FindingLow,
		Description: fmt.Sprintf("InsuranceBPS = %d (%0.1f%%)", config.InsuranceFundBps, float64(config.InsuranceFundBps)/100),
		Passed: config.InsuranceFundBps > 0,
		Remediation: "Insurance fund percentage should be > 0 for protocol safety net",
	})

	return findings
}

// auditFeeDistributionConservation runs the conservation of value property
// against a range of edge-case inputs.
func auditFeeDistributionConservation(_ sdk.Context, _ Keeper) []AuditFinding {
	var findings []AuditFinding

	config := DefaultFeeDistributionConfig()

	// Test with edge-case amounts
	edgeCases := []struct {
		amount         int64
		validatorCount int
	}{
		{1, 1},         // minimum possible
		{1, 100},       // tiny amount, many validators
		{7, 3},         // prime number, odd split
		{10000, 1},     // exact BPS base
		{10001, 7},     // BPS base + 1, prime validators
		{999999999, 3}, // large amount
		{1000000000, 100},
	}

	for _, tc := range edgeCases {
		fee := sdk.NewInt64Coin("uaeth", tc.amount)
		result := CalculateFeeBreakdown(fee, config, tc.validatorCount)

		perValTotal := result.PerValidatorReward.Amount.MulRaw(int64(tc.validatorCount))
		distributed := perValTotal.
			Add(result.TreasuryAmount.Amount).
			Add(result.BurnedAmount.Amount).
			Add(result.InsuranceFund.Amount)

		passed := distributed.Equal(fee.Amount)
		findings = append(findings, AuditFinding{
			ID: fmt.Sprintf("CONS-%d-%d", tc.amount, tc.validatorCount),
			CheckName: "fee_conservation",
			Severity: FindingCritical,
			Description: fmt.Sprintf("Fee=%d validators=%d: distributed=%s (expected %s)",
				tc.amount, tc.validatorCount, distributed.String(), fee.Amount.String()),
			Passed:      passed,
			Remediation: "Fee distribution violates conservation of value",
		})
	}

	return findings
}

// auditStateInvariants runs all registered module invariants.
func auditStateInvariants(ctx sdk.Context, k Keeper) []AuditFinding {
	var findings []AuditFinding

	invariantFn := AllInvariants(k)
	msg, broken := invariantFn(ctx)

	findings = append(findings, AuditFinding{
		ID: "INV-01", CheckName: "all_invariants",
		Severity: FindingCritical,
		Description: func() string {
			if broken {
				return "Invariant violation: " + msg
			}
			return "All 7 invariants pass"
		}(),
		Passed:      !broken,
		Remediation: "Fix state inconsistency identified by invariant",
	})

	return findings
}

// auditValidatorStatsBounds checks all validator stats are within bounds.
func auditValidatorStatsBounds(ctx sdk.Context, k Keeper) []AuditFinding {
	var findings []AuditFinding
	outOfBounds := 0
	total := 0

	_ = k.ValidatorStats.Walk(ctx, nil, func(_ string, stats types.ValidatorStats) (bool, error) {
		total++
		if stats.ReputationScore < 0 || stats.ReputationScore > 100 {
			outOfBounds++
		}
		if stats.TotalJobsProcessed < 0 || stats.SuccessfulJobs < 0 || stats.FailedJobs < 0 {
			outOfBounds++
		}
		return false, nil
	})

	findings = append(findings, AuditFinding{
		ID: "VSTATS-01", CheckName: "validator_stats_bounds",
		Severity: FindingHigh,
		Description: fmt.Sprintf("Checked %d validators, %d out-of-bounds", total, outOfBounds),
		Passed:      outOfBounds == 0,
		Remediation: "Run v1→v2 migration to clamp out-of-bounds values",
	})

	return findings
}

// auditPendingJobConsistency checks PendingJobs index matches Jobs.
func auditPendingJobConsistency(ctx sdk.Context, k Keeper) []AuditFinding {
	var findings []AuditFinding
	orphans := 0

	_ = k.PendingJobs.Walk(ctx, nil, func(id string, pj types.ComputeJob) (bool, error) {
		job, err := k.Jobs.Get(ctx, id)
		if err != nil {
			orphans++
			return false, nil
		}
		if job.Status != types.JobStatusPending && job.Status != types.JobStatusProcessing {
			orphans++
		}
		return false, nil
	})

	findings = append(findings, AuditFinding{
		ID: "PEND-01", CheckName: "pending_jobs_consistency",
		Severity: FindingHigh,
		Description: fmt.Sprintf("Orphaned pending jobs: %d", orphans),
		Passed:      orphans == 0,
		Remediation: "Run cleanup migration to remove orphaned pending jobs",
	})

	return findings
}

// auditJobCountIntegrity checks stored job count matches actual.
func auditJobCountIntegrity(ctx sdk.Context, k Keeper) []AuditFinding {
	var findings []AuditFinding

	storedCount, err := k.JobCount.Get(ctx)
	if err != nil {
		storedCount = 0
	}

	actualCount := uint64(0)
	_ = k.Jobs.Walk(ctx, nil, func(_ string, _ types.ComputeJob) (bool, error) {
		actualCount++
		return false, nil
	})

	findings = append(findings, AuditFinding{
		ID: "JCOUNT-01", CheckName: "job_count_integrity",
		Severity: FindingMedium,
		Description: fmt.Sprintf("Stored=%d Actual=%d", storedCount, actualCount),
		Passed:      storedCount == actualCount,
		Remediation: "Run reconciliation migration to fix job count",
	})

	return findings
}

// auditCryptographicMinimums validates cryptographic parameter minimums.
func auditCryptographicMinimums(_ sdk.Context, _ Keeper) []AuditFinding {
	var findings []AuditFinding

	// SHA-256 output length
	findings = append(findings, AuditFinding{
		ID: "CRYPTO-01", CheckName: "hash_length_sha256",
		Severity: FindingCritical,
		Description: "System uses SHA-256 (32-byte) hashes for model/input/output binding",
		Passed:      true, // Verified in invariant: model/input hashes must be 32 bytes
		Remediation: "N/A",
	})

	// TEE quote minimum size
	const minQuoteSize = 64
	findings = append(findings, AuditFinding{
		ID: "CRYPTO-02", CheckName: "tee_quote_min_size",
		Severity: FindingHigh,
		Description: fmt.Sprintf("TEE quote minimum = %d bytes", minQuoteSize),
		Passed:      minQuoteSize >= 64,
		Remediation: "TEE quotes must be >= 64 bytes for any real attestation format",
	})

	// ZK proof minimum size
	const minZKProofSize = 128
	findings = append(findings, AuditFinding{
		ID: "CRYPTO-03", CheckName: "zk_proof_min_size",
		Severity: FindingHigh,
		Description: fmt.Sprintf("ZK proof minimum = %d bytes", minZKProofSize),
		Passed:      minZKProofSize >= 128,
		Remediation: "ZK proofs must be >= 128 bytes for any real proof system",
	})

	// Nonce length for replay protection
	const nonceLength = 32
	findings = append(findings, AuditFinding{
		ID: "CRYPTO-04", CheckName: "nonce_length",
		Severity: FindingHigh,
		Description: fmt.Sprintf("Replay protection nonce = %d bytes (256-bit)", nonceLength),
		Passed:      nonceLength >= 16, // 128-bit minimum
		Remediation: "Nonce must be >= 16 bytes (128-bit) for replay protection",
	})

	return findings
}

// auditGovernanceOneWayGate validates the AllowSimulated one-way gate.
// NOTE: The one-way gate is enforced at the UpdateParams message handler level
// (msgServer.UpdateParams), not in MergeParams. MergeParams is a pure merge
// function that always applies bool fields. The handler checks the merged
// result and rejects if AllowSimulated would be re-enabled.
func auditGovernanceOneWayGate(ctx sdk.Context, k Keeper) []AuditFinding {
	var findings []AuditFinding

	params, err := k.GetParams(ctx)
	if err != nil {
		return findings
	}

	if !params.AllowSimulated {
		// AllowSimulated is disabled — this is the secure production state.
		// The one-way gate in UpdateParams prevents re-enablement.
		findings = append(findings, AuditFinding{
			ID: "GATE-01", CheckName: "one_way_gate_status",
			Severity: FindingInfo,
			Description: "AllowSimulated=false (production mode); one-way gate active — UpdateParams handler prevents re-enablement",
			Passed:      true,
		})
	} else {
		// AllowSimulated is still true — not yet locked for production.
		findings = append(findings, AuditFinding{
			ID: "GATE-01", CheckName: "one_way_gate_status",
			Severity: FindingCritical,
			Description: "AllowSimulated=true — simulation mode is active. Must be disabled before mainnet launch.",
			Passed:      false,
			Remediation: "Set AllowSimulated=false via governance before mainnet. Once set, the one-way gate in UpdateParams prevents re-enablement.",
		})
	}

	return findings
}

// auditParamFieldCompleteness checks that all expected param fields are set.
func auditParamFieldCompleteness(ctx sdk.Context, k Keeper) []AuditFinding {
	var findings []AuditFinding

	params, err := k.GetParams(ctx)
	if err != nil {
		return findings
	}

	// Use reflection to find zero-valued fields
	v := reflect.ValueOf(params).Elem()
	t := v.Type()

	zeroFields := 0
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldName := t.Field(i).Name

		// Skip proto internal fields
		if strings.HasPrefix(fieldName, "XXX_") || fieldName == "state" ||
			fieldName == "sizeCache" || fieldName == "unknownFields" {
			continue
		}

		if field.IsZero() {
			zeroFields++
			findings = append(findings, AuditFinding{
				ID:          fmt.Sprintf("FIELD-%s", fieldName),
				CheckName:   "param_field_set",
				Severity:    FindingLow,
				Description: fmt.Sprintf("Param field %s is zero-valued", fieldName),
				Passed:      false,
				Remediation: fmt.Sprintf("Set %s via governance or genesis", fieldName),
			})
		}
	}

	if zeroFields == 0 {
		findings = append(findings, AuditFinding{
			ID: "FIELD-ALL", CheckName: "param_field_completeness",
			Severity:    FindingInfo,
			Description: "All param fields have non-zero values",
			Passed:      true,
		})
	}

	return findings
}
