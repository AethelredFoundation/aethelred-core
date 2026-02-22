package keeper

// ---------------------------------------------------------------------------
// Threat Model — Aethelred L1 Blockchain for Verified AI Computations
// ---------------------------------------------------------------------------
//
// This file documents the formal threat model for the Aethelred protocol.
// It identifies attack surfaces, trust boundaries, attacker capabilities,
// and the mitigations implemented in the codebase.
//
// VERSION: 1.0 (pre-audit)
// SCOPE:   pouw, seal, verify, validator modules
// DATE:    Week 27 of 52 — Audit Prep Phase
// ---------------------------------------------------------------------------

import "fmt"

// ---------------------------------------------------------------------------
// 1. Attacker Classes
// ---------------------------------------------------------------------------

// AttackerClass describes a category of adversary.
type AttackerClass struct {
	ID          string // Unique identifier (e.g., "ATK-01")
	Name        string // Human-readable name
	Capability  string // What the attacker can do
	Motivation  string // Why they would attack
	Assumptions string // What we assume about them
}

// AttackerClasses enumerates all modelled adversaries.
var AttackerClasses = []AttackerClass{
	{
		ID:          "ATK-01",
		Name:        "Rogue Validator",
		Capability:  "Operates one or more validator nodes; can produce arbitrary compute outputs, submit fake attestations, and withhold vote extensions.",
		Motivation:  "Extract rewards without performing real computation; grief the network.",
		Assumptions: "Controls < 1/3 of total validator set (BFT assumption).",
	},
	{
		ID:          "ATK-02",
		Name:        "Colluding Validator Coalition",
		Capability:  "Two or more validators coordinate to submit identical incorrect outputs.",
		Motivation:  "Achieve false consensus to approve fraudulent compute results.",
		Assumptions: "Controls < 1/3 of total validator set; communication via side-channel.",
	},
	{
		ID:          "ATK-03",
		Name:        "TEE Breakout Attacker",
		Capability:  "Can extract secrets from a compromised TEE enclave or forge attestation quotes.",
		Motivation:  "Submit fabricated attestation data that appears legitimate.",
		Assumptions: "Compromises a single TEE platform (e.g. one Nitro enclave). Cannot compromise all TEE platforms simultaneously.",
	},
	{
		ID:          "ATK-04",
		Name:        "Governance Manipulator",
		Capability:  "Holds sufficient governance voting power to pass parameter change proposals.",
		Motivation:  "Weaken protocol security (e.g. enable AllowSimulated, lower consensus threshold, reduce slashing penalties).",
		Assumptions: "Has passed a governance vote; cannot modify code directly.",
	},
	{
		ID:          "ATK-05",
		Name:        "Replay Attacker",
		Capability:  "Captures valid vote extensions and replays them for different jobs or at different block heights.",
		Motivation:  "Earn verification rewards without performing fresh computation.",
		Assumptions: "Has network-level observation of CometBFT gossip messages.",
	},
	{
		ID:          "ATK-06",
		Name:        "Economic Griefing Attacker",
		Capability:  "Submits many small fee jobs to congest the scheduler and starve legitimate jobs.",
		Motivation:  "Denial of service; prevent competitors from using the network.",
		Assumptions: "Has moderate economic resources for fee payments.",
	},
	{
		ID:          "ATK-07",
		Name:        "State Corruption Attacker",
		Capability:  "Exploits consensus bugs or state machine errors to corrupt module state.",
		Motivation:  "Trigger invariant violations that halt the chain or enable theft.",
		Assumptions: "Requires finding a bug in the state transition logic.",
	},
}

// ---------------------------------------------------------------------------
// 2. Trust Boundaries
// ---------------------------------------------------------------------------

// TrustBoundary defines where trusted and untrusted zones meet.
type TrustBoundary struct {
	ID          string
	Name        string
	Description string
	Crossed     string // What crosses this boundary
}

// TrustBoundaries enumerates all trust boundaries in the system.
var TrustBoundaries = []TrustBoundary{
	{
		ID:          "TB-01",
		Name:        "Validator ↔ Consensus",
		Description: "Vote extensions from validators enter the consensus handler. The extension payload is untrusted until validated.",
		Crossed:     "VerificationWire JSON blobs in vote extensions",
	},
	{
		ID:          "TB-02",
		Name:        "TEE Enclave ↔ Host",
		Description: "TEE attestation quotes exit the enclave and are transmitted to the on-chain verifier. The quote is trusted only after platform-specific validation.",
		Crossed:     "TEE attestation (quote, measurement, nonce, userData)",
	},
	{
		ID:          "TB-03",
		Name:        "External User ↔ Transaction Handler",
		Description: "Users submit MsgSubmitJob, MsgRegisterModel, etc. All user-supplied data is untrusted.",
		Crossed:     "Transaction messages via ABCI DeliverTx",
	},
	{
		ID:          "TB-04",
		Name:        "Governance ↔ Module Parameters",
		Description: "Governance proposals update module parameters. The parameter update must pass validation and one-way-gate checks.",
		Crossed:     "MsgUpdateParams with partial Params struct",
	},
	{
		ID:          "TB-05",
		Name:        "Module ↔ Module (keeper-to-keeper)",
		Description: "pouw keeper calls into seal, verify, and validator keepers. Return values are trusted if keepers are correctly implemented.",
		Crossed:     "Keeper method calls and return values",
	},
	{
		ID:          "TB-06",
		Name:        "State Store ↔ Application Logic",
		Description: "Collections read/write to the IAVL tree. Store corruption or prefix collisions could violate invariants.",
		Crossed:     "Proto-marshalled state values in collections",
	},
}

// ---------------------------------------------------------------------------
// 3. Attack Surfaces
// ---------------------------------------------------------------------------

// AttackSurface describes a specific attack vector.
type AttackSurface struct {
	ID           string
	Name         string
	Module       string
	Attacker     string // References AttackerClass.ID
	Boundary     string // References TrustBoundary.ID
	Vector       string
	Impact       string // "critical", "high", "medium", "low"
	Mitigation   string
	Status       string // "mitigated", "partial", "open"
	TestCoverage string // Reference to test function(s) that verify mitigation
}

// AttackSurfaces enumerates all modelled attack vectors.
var AttackSurfaces = []AttackSurface{
	// --- Consensus Attacks ---
	{
		ID: "AS-01", Name: "Fake TEE Attestation",
		Module: "pouw/consensus", Attacker: "ATK-03", Boundary: "TB-02",
		Vector:       "Validator submits forged TEE attestation quote with correct format but invalid cryptographic binding.",
		Impact:       "high",
		Mitigation:   "validateTEEAttestationWireStrict checks: platform allowlist, measurement non-empty, quote >=64 bytes, userData == OutputHash cross-binding, timestamp freshness <10min, simulated platform rejected when AllowSimulated=false.",
		Status:       "mitigated",
		TestCoverage: "TestProductionMode_TEE*, TestByzantine_*",
	},
	{
		ID: "AS-02", Name: "Vote Extension Replay",
		Module: "pouw/consensus", Attacker: "ATK-05", Boundary: "TB-01",
		Vector:       "Attacker replays a previously valid vote extension at a different block height or for a different job.",
		Impact:       "high",
		Mitigation:   "validateVerificationWire requires 32-byte nonce for freshness. Vote extensions are height-scoped by CometBFT. JobID in extension must match active job.",
		Status:       "mitigated",
		TestCoverage: "TestByzantine_ReplayAttack*, TestNegative_*",
	},
	{
		ID: "AS-03", Name: "Simulated Verification in Production",
		Module: "pouw/consensus", Attacker: "ATK-01", Boundary: "TB-01",
		Vector:       "Validator runs with no real TEE/zkML verifier, hoping simulated results are accepted.",
		Impact:       "critical",
		Mitigation:   "ConsensusHandler.ProcessBlock checks AllowSimulated param. If false (production), rejects any job without a configured verifier. Simulated TEE platform string rejected in production.",
		Status:       "mitigated",
		TestCoverage: "TestProductionMode_*, TestNegative_SimulatedInProduction",
	},
	{
		ID: "AS-04", Name: "Byzantine Minority False Consensus",
		Module: "pouw/consensus", Attacker: "ATK-02", Boundary: "TB-01",
		Vector:       "< 1/3 colluding validators attempt to push incorrect output past consensus threshold.",
		Impact:       "critical",
		Mitigation:   "AggregateVoteExtensions requires (totalVotes * ConsensusThreshold / 100) + 1 agreeing validators. Default threshold 67% (2/3 supermajority).",
		Status:       "mitigated",
		TestCoverage: "TestByzantine_ConsensusThreshold*, TestByzantine_Collusion*",
	},
	{
		ID: "AS-05", Name: "Double-Sign Detection Evasion",
		Module: "pouw/evidence", Attacker: "ATK-01", Boundary: "TB-01",
		Vector:       "Validator submits two distinct outputs for the same job hoping only one is checked.",
		Impact:       "high",
		Mitigation:   "DetectDoubleSigners scans all vote extensions per validator per job, deduplicates by output hash. Severity: critical, penalty: 50% slash + jail.",
		Status:       "mitigated",
		TestCoverage: "TestSlashing_DoubleSign*, TestEvidence_*",
	},

	// --- Governance Attacks ---
	{
		ID: "AS-06", Name: "Re-enable AllowSimulated",
		Module: "pouw/governance", Attacker: "ATK-04", Boundary: "TB-04",
		Vector:       "Governance proposal to set AllowSimulated=true after it was disabled in production.",
		Impact:       "critical",
		Mitigation:   "MergeParams enforces one-way gate: if current AllowSimulated=false and update.AllowSimulated=true, the update is silently rejected. This is not bypassable via governance.",
		Status:       "mitigated",
		TestCoverage: "TestTokenomics_MergeParams_OneWayGate*, TestGovernance_AllowSimulated*",
	},
	{
		ID: "AS-07", Name: "Lower Consensus Threshold Below Safety",
		Module: "pouw/governance", Attacker: "ATK-04", Boundary: "TB-04",
		Vector:       "Governance proposal to lower ConsensusThreshold below 51%, enabling minority consensus.",
		Impact:       "critical",
		Mitigation:   "ValidateParams enforces ConsensusThreshold in range [51, 100]. Any value < 51 is rejected.",
		Status:       "mitigated",
		TestCoverage: "TestTokenomics_ValidateParams_*",
	},
	{
		ID: "AS-08", Name: "Zero Slashing Penalty",
		Module: "pouw/governance", Attacker: "ATK-04", Boundary: "TB-04",
		Vector:       "Set SlashingPenalty to 0, making misbehavior cost-free.",
		Impact:       "high",
		Mitigation:   "ValidateParams requires BaseJobFee, VerificationReward, and SlashingPenalty to be valid positive coin strings.",
		Status:       "mitigated",
		TestCoverage: "TestTokenomics_ValidateParams_*",
	},

	// --- Economic Attacks ---
	{
		ID: "AS-09", Name: "Scheduler Congestion / Job Spam",
		Module: "pouw/scheduler", Attacker: "ATK-06", Boundary: "TB-03",
		Vector:       "Attacker submits many low-fee jobs to fill the scheduler queue, delaying legitimate jobs.",
		Impact:       "medium",
		Mitigation:   "MaxJobsPerBlock limits per-block throughput. BaseJobFee sets minimum cost. Priority queue in scheduler ranks by fee. Rate limiter available.",
		Status:       "mitigated",
		TestCoverage: "TestScheduler_*, TestLoad_*",
	},
	{
		ID: "AS-10", Name: "Fee Distribution Rounding Exploit",
		Module: "pouw/fee_distribution", Attacker: "ATK-07", Boundary: "TB-06",
		Vector:       "Craft fee amounts that cause integer rounding to leak or create tokens.",
		Impact:       "high",
		Mitigation:   "CalculateFeeBreakdown uses integer-only BPS math. Dust (rounding remainder) is deterministically added to treasury. Conservation invariant: sum of all buckets == total fee, verified in stress tests.",
		Status:       "mitigated",
		TestCoverage: "TestTokenomics_Breakdown_Conservation*, TestLoad_FeeBreakdownStress",
	},

	// --- State Integrity Attacks ---
	{
		ID: "AS-11", Name: "Orphaned Pending Job Accumulation",
		Module: "pouw/keeper", Attacker: "ATK-07", Boundary: "TB-06",
		Vector:       "Bug in UpdateJob causes completed/failed jobs to remain in PendingJobs index, inflating pending count and blocking scheduler.",
		Impact:       "medium",
		Mitigation:   "Invariant 'no-orphan-pending-jobs' detects terminal jobs in PendingJobs. Migration v1→v2 cleans orphans by cross-referencing Jobs authoritative status.",
		Status:       "mitigated",
		TestCoverage: "TestUpgrade_MigrateV1ToV2_CleansOrphanPendingJobs, invariant tests",
	},
	{
		ID: "AS-12", Name: "Job Count Skew",
		Module: "pouw/keeper", Attacker: "ATK-07", Boundary: "TB-06",
		Vector:       "JobCount item drifts from actual job count, causing scheduling errors.",
		Impact:       "low",
		Mitigation:   "Invariant 'job-count-consistency' detects drift. Migration v1→v2 reconciles count. PostUpgradeValidation verifies.",
		Status:       "mitigated",
		TestCoverage: "TestUpgrade_MigrateV1ToV2_ReconcilesJobCount, invariant tests",
	},
	{
		ID: "AS-13", Name: "Validator Reputation Overflow",
		Module: "pouw/keeper", Attacker: "ATK-07", Boundary: "TB-06",
		Vector:       "Reputation score exceeds [0, 100] range, causing reward scaling to produce unexpected values.",
		Impact:       "medium",
		Mitigation:   "Invariant 'validator-stats-non-negative' checks 0 <= score <= 100. Migration clamps out-of-range scores. RewardScaleByReputation uses clamped formula: reward * (50 + score/2) / 100.",
		Status:       "mitigated",
		TestCoverage: "TestUpgrade_MigrateV1ToV2_ClampsReputationScore, invariant tests",
	},

	// --- Seal / Audit Trail Attacks ---
	{
		ID: "AS-14", Name: "Seal Forgery",
		Module: "seal/keeper", Attacker: "ATK-03", Boundary: "TB-05",
		Vector:       "Attacker creates a seal without corresponding verified computation, breaking the audit trail.",
		Impact:       "high",
		Mitigation:   "CreateSeal validates seal via seal.Validate(). Completed jobs invariant checks all completed jobs have SealId. Seal must reference valid job.",
		Status:       "mitigated",
		TestCoverage: "TestSeal_*, completed-jobs-have-seals invariant",
	},
	{
		ID: "AS-15", Name: "Audit Log Tampering",
		Module: "pouw/audit", Attacker: "ATK-07", Boundary: "TB-06",
		Vector:       "Attacker modifies historical audit records to hide evidence of misbehavior.",
		Impact:       "high",
		Mitigation:   "AuditLogger uses SHA-256 hash chaining. Each record includes PreviousHash. VerifyChain() detects any break in the chain. Records are also emitted as SDK events (on-chain, immutable).",
		Status:       "mitigated",
		TestCoverage: "TestAudit_HashChain*, TestAudit_VerifyChain*",
	},

	// --- Incomplete / Open Items ---
	{
		ID: "AS-16", Name: "Downtime Slashing Not Implemented",
		Module: "pouw/evidence", Attacker: "ATK-01", Boundary: "TB-01",
		Vector:       "Validator goes offline indefinitely, never responds to assigned jobs. ProcessEndBlockEvidence is a stub.",
		Impact:       "medium",
		Mitigation:   "Downtime condition defined in validator/slashing.go (1% penalty). ProcessEndBlockEvidence exists as stub — integration with missed-block tracker is TODO.",
		Status:       "open",
		TestCoverage: "None — requires integration with validator module missed-block tracking",
	},
	{
		ID: "AS-17", Name: "Vote Extension Signing Not Implemented",
		Module: "app/abci", Attacker: "ATK-05", Boundary: "TB-01",
		Vector:       "Vote extensions are not ed25519-signed, allowing network-level forgery.",
		Impact:       "high",
		Mitigation:   "TODO in app/abci.go line 47. CometBFT's VoteExtension mechanism provides implicit signing at the consensus layer, but application-level signing adds defense-in-depth.",
		Status:       "partial",
		TestCoverage: "TestByzantine_UnsignedExtension (validates rejection in production mode)",
	},
	{
		ID: "AS-18", Name: "Seal Export Truncation",
		Module: "seal/keeper", Attacker: "ATK-07", Boundary: "TB-06",
		Vector:       "ExportGenesis previously risked truncating seal export for large chains.",
		Impact:       "low",
		Mitigation:   "ExportGenesis uses paginated export via ExportAllSeals; no hard cap. Added stress test to assert >10k seals export cleanly.",
		Status:       "mitigated",
		TestCoverage: "TestExportGenesis_NoTruncation (>10k seals)",
	},
}

// ---------------------------------------------------------------------------
// 4. Security Properties (must all hold for protocol correctness)
// ---------------------------------------------------------------------------

// SecurityProperty defines a safety or liveness property of the protocol.
type SecurityProperty struct {
	ID        string
	Category  string // "safety", "liveness", "economic", "audit"
	Name      string
	Statement string
	Mechanism string // How it's enforced
}

// SecurityProperties enumerates the protocol's core security properties.
var SecurityProperties = []SecurityProperty{
	// Safety
	{
		ID: "SP-01", Category: "safety", Name: "Consensus Integrity",
		Statement: "No compute result is marked as consensus-verified unless ≥ ConsensusThreshold% of validators independently produced the same output hash.",
		Mechanism: "AggregateVoteExtensions counting + ConsensusThreshold param (min 51%).",
	},
	{
		ID: "SP-02", Category: "safety", Name: "Fee Conservation",
		Statement: "For any fee amount and any validator count, the sum of (validator rewards + treasury + burn + insurance) equals the total fee. No tokens are created or destroyed outside of explicit burns.",
		Mechanism: "CalculateFeeBreakdown integer BPS math + dust-to-treasury rule.",
	},
	{
		ID: "SP-03", Category: "safety", Name: "State Machine Monotonicity",
		Statement: "Job status transitions are monotonic: Pending → Processing → {Completed, Failed, Expired}. No backward transitions are possible.",
		Mechanism: "UpdateJob validates transition legality. job-state-machine invariant.",
	},
	{
		ID: "SP-04", Category: "safety", Name: "One-Way Security Gate",
		Statement: "Once AllowSimulated is set to false, no governance action can re-enable it.",
		Mechanism: "MergeParams one-way gate check. UpdateParams silently rejects re-enablement.",
	},
	{
		ID: "SP-05", Category: "safety", Name: "Attestation Authenticity",
		Statement: "In production mode (AllowSimulated=false), every accepted verification must include valid TEE attestation or zkML proof. Simulated attestations are always rejected.",
		Mechanism: "validateTEEAttestationWireStrict + validateZKProofWire + simulation guard.",
	},
	{
		ID: "SP-06", Category: "safety", Name: "Deterministic State Transitions",
		Statement: "All state transitions are deterministic across validators. Non-deterministic operations (time.Now, rand) are replaced by block time and deterministic seeds.",
		Mechanism: "NewComputeJobWithBlockTime uses blockTime param. Scheduler uses deterministic priority.",
	},

	// Liveness
	{
		ID: "SP-07", Category: "liveness", Name: "Job Progress",
		Statement: "Every pending job either completes, fails, or expires within JobTimeoutBlocks blocks.",
		Mechanism: "Scheduler checks job expiry each block. Expired jobs are transitioned to JobStatusExpired.",
	},
	{
		ID: "SP-08", Category: "liveness", Name: "Scheduler Fairness",
		Statement: "The scheduler processes up to MaxJobsPerBlock jobs per block, ordered by priority (fee-weighted).",
		Mechanism: "JobScheduler.GetNextBatch with priority queue and block cap.",
	},

	// Economic
	{
		ID: "SP-09", Category: "economic", Name: "Misbehavior is Costly",
		Statement: "Every detected misbehavior results in token slashing proportional to severity. Collusion (100%), double-sign (50%), fake attestation (100%).",
		Mechanism: "EvidenceCollector + ApplyPenalty with severity-scaled slash fractions.",
	},
	{
		ID: "SP-10", Category: "economic", Name: "Reputation-Scaled Rewards",
		Statement: "Validator rewards are scaled by reputation score: reward * (50 + score/2) / 100. A score of 0 yields 50% reward; a score of 100 yields 100% reward.",
		Mechanism: "RewardScaleByReputation formula in fee_distribution.go.",
	},

	// Audit
	{
		ID: "SP-11", Category: "audit", Name: "Tamper-Evident Audit Trail",
		Statement: "All security-relevant actions are recorded as hash-chained audit records. Any modification to a historical record breaks the chain and is detectable.",
		Mechanism: "AuditLogger SHA-256 hash chain + VerifyChain() integrity check.",
	},
	{
		ID: "SP-12", Category: "audit", Name: "Complete Seal Coverage",
		Statement: "Every completed compute job has an associated digital seal linking it to the verified output, model, and consensus round.",
		Mechanism: "completed-jobs-have-seals invariant. CreateSeal on job completion.",
	},
}

// ---------------------------------------------------------------------------
// 5. Audit Summary Helpers
// ---------------------------------------------------------------------------

// ThreatModelSummary returns a human-readable summary of the threat model.
func ThreatModelSummary() string {
	mitigated, partial, open := 0, 0, 0
	for _, as := range AttackSurfaces {
		switch as.Status {
		case "mitigated":
			mitigated++
		case "partial":
			partial++
		case "open":
			open++
		}
	}

	return fmt.Sprintf(
		"Aethelred Threat Model v1.0\n"+
			"  Attacker classes:      %d\n"+
			"  Trust boundaries:      %d\n"+
			"  Attack surfaces:       %d (mitigated: %d, partial: %d, open: %d)\n"+
			"  Security properties:   %d\n"+
			"  Modules in scope:      pouw, seal, verify, validator\n",
		len(AttackerClasses),
		len(TrustBoundaries),
		len(AttackSurfaces), mitigated, partial, open,
		len(SecurityProperties),
	)
}
