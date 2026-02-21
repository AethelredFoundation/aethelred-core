//! Pillar 6: Bi-Cameral Governance - Proof of Sovereign Authority
//!
//! ## The Competitor Gap
//!
//! - **Ethereum/Solana**: Governed by "Token Weight"
//! - If a hostile entity buys 51% of tokens, they can hijack the chain
//! - Banks (FAB/UBS) hate this risk
//!
//! ## The Problem
//!
//! Enterprises cannot build critical infrastructure on a chain where
//! "Anonymous Whales" control the upgrades.
//!
//! ## The Aethelred Advantage
//!
//! Implement a **Bi-Cameral Governance Model** (Two Houses):
//!
//! ### House of Tokens (The Commons)
//! - AETHEL holders vote on economic parameters (fees, burn rates)
//! - Democratic, one-token-one-vote (with quadratic scaling)
//!
//! ### House of Sovereigns (The Senate)
//! - A "White-Listed Council" of verified nodes (FAB, M42, DBS)
//! - Hold **Veto Power** over security upgrades and compliance modules
//!
//! ## Tremendous Value
//!
//! Banks get certainty that the protocol won't change overnight due to
//! a "crypto mob," while still allowing decentralized economic growth.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};

// ============================================================================
// Governance Roles
// ============================================================================

/// Types of governance participants
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GovernanceRole {
    /// Token holder (Commons member)
    TokenHolder {
        address: [u8; 32],
        voting_power: u128,
    },
    /// Verified sovereign entity (Senate member)
    Sovereign {
        entity: SovereignEntity,
        seat_id: u64,
    },
    /// Delegated voter
    Delegate {
        address: [u8; 32],
        delegators: Vec<[u8; 32]>,
        total_delegated_power: u128,
    },
}

/// Verified sovereign entities that can hold Senate seats
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SovereignEntity {
    /// Entity unique identifier
    pub entity_id: [u8; 32],
    /// Entity name
    pub name: String,
    /// Entity type
    pub entity_type: EntityType,
    /// Jurisdiction
    pub jurisdiction: Jurisdiction,
    /// Verification status
    pub verification: VerificationStatus,
    /// Public key for voting
    pub voting_key: [u8; 32],
    /// Joining timestamp
    pub joined_at: u64,
    /// Staked amount (skin in the game)
    pub stake: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityType {
    /// Financial institution (banks, asset managers)
    FinancialInstitution {
        license_type: String,
        regulator: String,
    },
    /// Healthcare provider
    HealthcareProvider {
        accreditation: String,
    },
    /// Government entity
    Government {
        department: String,
    },
    /// Technology company (AI providers)
    TechnologyCompany {
        specialization: String,
    },
    /// Research institution
    ResearchInstitution {
        focus_area: String,
    },
    /// Validator operator
    ValidatorOperator {
        nodes_operated: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Jurisdiction {
    UAE,
    Singapore,
    Switzerland,
    UK,
    EU,
    USA,
    Japan,
    HongKong,
    International,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// Pending verification
    Pending,
    /// Verified by KYB process
    Verified {
        verified_at: u64,
        verifier: String,
        valid_until: u64,
    },
    /// Verification expired
    Expired,
    /// Suspended
    Suspended {
        reason: String,
        suspended_at: u64,
    },
}

// ============================================================================
// House of Tokens (The Commons)
// ============================================================================

/// The House of Tokens - Democratic token holder governance
pub struct HouseOfTokens {
    /// Token holder registry
    holders: HashMap<[u8; 32], TokenHolderInfo>,
    /// Delegation registry
    delegations: HashMap<[u8; 32], [u8; 32]>, // delegator -> delegate
    /// Active proposals
    proposals: HashMap<u64, CommonsProposal>,
    /// Configuration
    config: CommonsConfig,
    /// Voting history
    voting_history: Vec<VotingRecord>,
}

#[derive(Debug, Clone)]
pub struct TokenHolderInfo {
    pub address: [u8; 32],
    pub balance: u128,
    pub staked: u128,
    pub voting_power: u128,
    pub delegated_to: Option<[u8; 32]>,
    pub last_vote: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct CommonsConfig {
    /// Minimum tokens to create proposal
    pub proposal_threshold: u128,
    /// Quorum percentage (of total supply)
    pub quorum_percentage: f64,
    /// Voting period in blocks
    pub voting_period_blocks: u64,
    /// Time lock for execution
    pub timelock_blocks: u64,
    /// Use quadratic voting
    pub quadratic_voting: bool,
    /// Maximum voting power percentage per address
    pub max_voting_power_percentage: f64,
}

impl Default for CommonsConfig {
    fn default() -> Self {
        CommonsConfig {
            proposal_threshold: 10_000 * 10u128.pow(18), // 10,000 AETH
            quorum_percentage: 0.04, // 4% of total supply
            voting_period_blocks: 50_400, // ~7 days at 12s blocks
            timelock_blocks: 14_400, // ~2 days
            quadratic_voting: true,
            max_voting_power_percentage: 0.10, // 10% cap
        }
    }
}

/// A proposal in the House of Tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonsProposal {
    /// Proposal ID
    pub id: u64,
    /// Proposer address
    pub proposer: [u8; 32],
    /// Proposal type
    pub proposal_type: CommonsProposalType,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// Execution payload
    pub payload: Vec<u8>,
    /// Creation block
    pub created_at_block: u64,
    /// Voting start block
    pub voting_start_block: u64,
    /// Voting end block
    pub voting_end_block: u64,
    /// Votes for
    pub votes_for: u128,
    /// Votes against
    pub votes_against: u128,
    /// Abstentions
    pub abstentions: u128,
    /// Individual votes
    pub votes: HashMap<[u8; 32], Vote>,
    /// Status
    pub status: ProposalStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommonsProposalType {
    /// Change fee parameters
    FeeParameter {
        parameter: String,
        old_value: String,
        new_value: String,
    },
    /// Change burn rate parameters
    BurnParameter {
        parameter: String,
        old_value: String,
        new_value: String,
    },
    /// Treasury spending
    TreasurySpend {
        recipient: [u8; 32],
        amount: u128,
        purpose: String,
    },
    /// Inflation rate change
    InflationChange {
        old_rate: f64,
        new_rate: f64,
    },
    /// Signal proposal (non-binding)
    Signal {
        topic: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub voter: [u8; 32],
    pub voting_power: u128,
    pub choice: VoteChoice,
    pub timestamp: u64,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteChoice {
    For,
    Against,
    Abstain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingRecord {
    pub proposal_id: u64,
    pub passed: bool,
    pub votes_for: u128,
    pub votes_against: u128,
    pub quorum_reached: bool,
    pub vetoed: bool,
    pub executed: bool,
    pub finalized_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    /// Proposal is pending (waiting for voting to start)
    Pending,
    /// Voting is active
    Active,
    /// Voting ended, passed
    Passed,
    /// Voting ended, failed
    Failed,
    /// Passed but vetoed by Senate
    Vetoed,
    /// In timelock before execution
    Queued,
    /// Executed
    Executed,
    /// Cancelled by proposer
    Cancelled,
    /// Expired
    Expired,
}

impl HouseOfTokens {
    pub fn new(config: CommonsConfig) -> Self {
        HouseOfTokens {
            holders: HashMap::new(),
            delegations: HashMap::new(),
            proposals: HashMap::new(),
            config,
            voting_history: Vec::new(),
        }
    }

    /// Calculate voting power (with quadratic scaling)
    pub fn calculate_voting_power(&self, balance: u128) -> u128 {
        if self.config.quadratic_voting {
            // Quadratic voting: sqrt of tokens
            ((balance as f64).sqrt() * 1000.0) as u128
        } else {
            balance
        }
    }

    /// Create a new proposal
    pub fn create_proposal(
        &mut self,
        proposer: [u8; 32],
        proposal_type: CommonsProposalType,
        title: String,
        description: String,
        payload: Vec<u8>,
        current_block: u64,
    ) -> Result<u64, GovernanceError> {
        // Check threshold
        let holder = self.holders.get(&proposer)
            .ok_or(GovernanceError::NotAHolder)?;

        if holder.voting_power < self.config.proposal_threshold {
            return Err(GovernanceError::InsufficientVotingPower {
                required: self.config.proposal_threshold,
                actual: holder.voting_power,
            });
        }

        let proposal_id = self.proposals.len() as u64 + 1;
        let voting_start = current_block + 1;
        let voting_end = voting_start + self.config.voting_period_blocks;

        let proposal = CommonsProposal {
            id: proposal_id,
            proposer,
            proposal_type,
            title,
            description,
            payload,
            created_at_block: current_block,
            voting_start_block: voting_start,
            voting_end_block: voting_end,
            votes_for: 0,
            votes_against: 0,
            abstentions: 0,
            votes: HashMap::new(),
            status: ProposalStatus::Pending,
        };

        self.proposals.insert(proposal_id, proposal);
        Ok(proposal_id)
    }

    /// Cast a vote
    pub fn vote(
        &mut self,
        proposal_id: u64,
        voter: [u8; 32],
        choice: VoteChoice,
        current_block: u64,
        reason: Option<String>,
    ) -> Result<(), GovernanceError> {
        let proposal = self.proposals.get_mut(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        // Check voting period
        if current_block < proposal.voting_start_block {
            return Err(GovernanceError::VotingNotStarted);
        }
        if current_block > proposal.voting_end_block {
            return Err(GovernanceError::VotingEnded);
        }

        // Check if already voted
        if proposal.votes.contains_key(&voter) {
            return Err(GovernanceError::AlreadyVoted);
        }

        // Get voting power
        let holder = self.holders.get(&voter)
            .ok_or(GovernanceError::NotAHolder)?;

        let voting_power = self.calculate_voting_power(holder.balance + holder.staked);

        // Apply max voting power cap
        let total_supply: u128 = self.holders.values().map(|h| h.balance + h.staked).sum();
        let max_power = (total_supply as f64 * self.config.max_voting_power_percentage) as u128;
        let effective_power = voting_power.min(max_power);

        // Record vote
        let vote = Vote {
            voter,
            voting_power: effective_power,
            choice,
            timestamp: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            reason,
        };

        match choice {
            VoteChoice::For => proposal.votes_for += effective_power,
            VoteChoice::Against => proposal.votes_against += effective_power,
            VoteChoice::Abstain => proposal.abstentions += effective_power,
        }

        proposal.votes.insert(voter, vote);
        Ok(())
    }

    /// Finalize a proposal
    pub fn finalize(&mut self, proposal_id: u64, current_block: u64) -> Result<ProposalStatus, GovernanceError> {
        let proposal = self.proposals.get_mut(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        if current_block <= proposal.voting_end_block {
            return Err(GovernanceError::VotingNotEnded);
        }

        // Calculate quorum
        let total_supply: u128 = self.holders.values().map(|h| h.balance + h.staked).sum();
        let quorum = (total_supply as f64 * self.config.quorum_percentage) as u128;
        let total_votes = proposal.votes_for + proposal.votes_against + proposal.abstentions;

        let quorum_reached = total_votes >= quorum;
        let passed = quorum_reached && proposal.votes_for > proposal.votes_against;

        proposal.status = if passed {
            ProposalStatus::Passed
        } else {
            ProposalStatus::Failed
        };

        Ok(proposal.status)
    }
}

// ============================================================================
// House of Sovereigns (The Senate)
// ============================================================================

/// The House of Sovereigns - Enterprise governance with veto power
pub struct HouseOfSovereigns {
    /// Senate members
    members: HashMap<[u8; 32], SenateMember>,
    /// Minimum members required
    min_members: usize,
    /// Maximum members allowed
    max_members: usize,
    /// Active veto proposals
    veto_proposals: HashMap<u64, VetoProposal>,
    /// Security proposals (Senate-only)
    security_proposals: HashMap<u64, SecurityProposal>,
    /// Configuration
    config: SenateConfig,
}

#[derive(Debug, Clone)]
pub struct SenateMember {
    pub entity: SovereignEntity,
    pub seat: SeatInfo,
    pub voting_record: SenateVotingRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeatInfo {
    /// Seat ID
    pub seat_id: u64,
    /// Seat type
    pub seat_type: SeatType,
    /// Term expiration
    pub term_expires: u64,
    /// Can be removed?
    pub removable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SeatType {
    /// Founding member (permanent seat)
    Founding,
    /// Elected seat (term limits)
    Elected,
    /// Observer seat (no voting, advisory)
    Observer,
    /// Technical seat (validator operators)
    Technical,
}

#[derive(Debug, Clone, Default)]
pub struct SenateVotingRecord {
    pub total_votes: u64,
    pub vetoes_cast: u64,
    pub security_proposals_passed: u64,
    pub last_active: u64,
}

#[derive(Debug, Clone)]
pub struct SenateConfig {
    /// Veto threshold (percentage of Senate required to veto)
    pub veto_threshold: f64,
    /// Security proposal threshold
    pub security_threshold: f64,
    /// Member addition threshold
    pub member_addition_threshold: f64,
    /// Maximum term length (in seconds)
    pub max_term_length: u64,
    /// Minimum stake for membership
    pub min_stake: u128,
}

impl Default for SenateConfig {
    fn default() -> Self {
        SenateConfig {
            veto_threshold: 0.51, // Simple majority to veto
            security_threshold: 0.67, // Supermajority for security
            member_addition_threshold: 0.67, // Supermajority to add members
            max_term_length: 2 * 365 * 24 * 3600, // 2 years
            min_stake: 100_000 * 10u128.pow(18), // 100,000 AETH
        }
    }
}

/// A veto proposal against a Commons proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VetoProposal {
    pub id: u64,
    /// The Commons proposal being vetoed
    pub target_proposal_id: u64,
    /// Initiator
    pub initiator: [u8; 32],
    /// Reason for veto
    pub reason: String,
    /// Category
    pub veto_category: VetoCategory,
    /// Votes
    pub votes: HashMap<[u8; 32], bool>,
    /// Status
    pub status: VetoStatus,
    /// Created at
    pub created_at: u64,
    /// Expires at
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VetoCategory {
    /// Security concern
    Security,
    /// Regulatory compliance concern
    RegulatoryCompliance,
    /// Technical feasibility concern
    Technical,
    /// Economic stability concern
    Economic,
    /// Governance process concern
    Process,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum VetoStatus {
    Pending,
    Passed,   // Veto successful
    Failed,   // Veto failed
    Expired,
}

/// A security/compliance proposal (Senate-only)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProposal {
    pub id: u64,
    pub proposer: [u8; 32],
    pub proposal_type: SecurityProposalType,
    pub title: String,
    pub description: String,
    pub payload: Vec<u8>,
    pub votes: HashMap<[u8; 32], bool>,
    pub status: ProposalStatus,
    pub created_at: u64,
    pub voting_deadline: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityProposalType {
    /// Emergency pause
    EmergencyPause {
        duration: Duration,
        affected_modules: Vec<String>,
    },
    /// Validator set change
    ValidatorSetChange {
        additions: Vec<[u8; 32]>,
        removals: Vec<[u8; 32]>,
    },
    /// Security upgrade
    SecurityUpgrade {
        description: String,
        upgrade_hash: [u8; 32],
    },
    /// Compliance module change
    ComplianceModule {
        module_name: String,
        action: String,
    },
    /// TEE policy change
    TEEPolicy {
        policy: String,
    },
    /// Emergency fund release
    EmergencyFundRelease {
        amount: u128,
        recipient: [u8; 32],
        reason: String,
    },
}

impl HouseOfSovereigns {
    pub fn new(config: SenateConfig) -> Self {
        HouseOfSovereigns {
            members: HashMap::new(),
            min_members: 5,
            max_members: 21,
            veto_proposals: HashMap::new(),
            security_proposals: HashMap::new(),
            config,
        }
    }

    /// Add a founding member
    pub fn add_founding_member(&mut self, entity: SovereignEntity) -> Result<u64, GovernanceError> {
        if entity.stake < self.config.min_stake {
            return Err(GovernanceError::InsufficientStake {
                required: self.config.min_stake,
                actual: entity.stake,
            });
        }

        let seat_id = self.members.len() as u64 + 1;

        let member = SenateMember {
            entity: entity.clone(),
            seat: SeatInfo {
                seat_id,
                seat_type: SeatType::Founding,
                term_expires: u64::MAX, // Founding members have no term limit
                removable: false,
            },
            voting_record: SenateVotingRecord::default(),
        };

        self.members.insert(entity.entity_id, member);
        Ok(seat_id)
    }

    /// Initiate a veto
    pub fn initiate_veto(
        &mut self,
        initiator: [u8; 32],
        target_proposal_id: u64,
        reason: String,
        category: VetoCategory,
    ) -> Result<u64, GovernanceError> {
        // Check if initiator is a member
        if !self.members.contains_key(&initiator) {
            return Err(GovernanceError::NotASenator);
        }

        let veto_id = self.veto_proposals.len() as u64 + 1;
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let veto = VetoProposal {
            id: veto_id,
            target_proposal_id,
            initiator,
            reason,
            veto_category: category,
            votes: HashMap::new(),
            status: VetoStatus::Pending,
            created_at: now,
            expires_at: now + 7 * 24 * 3600, // 7 days to vote
        };

        self.veto_proposals.insert(veto_id, veto);
        Ok(veto_id)
    }

    /// Vote on a veto
    pub fn vote_on_veto(
        &mut self,
        veto_id: u64,
        voter: [u8; 32],
        support_veto: bool,
    ) -> Result<(), GovernanceError> {
        // Check if voter is a member
        if !self.members.contains_key(&voter) {
            return Err(GovernanceError::NotASenator);
        }

        let veto = self.veto_proposals.get_mut(&veto_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        if veto.votes.contains_key(&voter) {
            return Err(GovernanceError::AlreadyVoted);
        }

        veto.votes.insert(voter, support_veto);

        // Check if threshold reached
        let total_members = self.members.len();
        let support_count = veto.votes.values().filter(|&&v| v).count();
        let threshold = (total_members as f64 * self.config.veto_threshold) as usize;

        if support_count >= threshold {
            veto.status = VetoStatus::Passed;
        }

        Ok(())
    }

    /// Create a security proposal
    pub fn create_security_proposal(
        &mut self,
        proposer: [u8; 32],
        proposal_type: SecurityProposalType,
        title: String,
        description: String,
        payload: Vec<u8>,
    ) -> Result<u64, GovernanceError> {
        if !self.members.contains_key(&proposer) {
            return Err(GovernanceError::NotASenator);
        }

        let proposal_id = self.security_proposals.len() as u64 + 1;
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let proposal = SecurityProposal {
            id: proposal_id,
            proposer,
            proposal_type,
            title,
            description,
            payload,
            votes: HashMap::new(),
            status: ProposalStatus::Active,
            created_at: now,
            voting_deadline: now + 3 * 24 * 3600, // 3 days for security proposals
        };

        self.security_proposals.insert(proposal_id, proposal);
        Ok(proposal_id)
    }

    /// Get member count
    pub fn member_count(&self) -> usize {
        self.members.len()
    }
}

// ============================================================================
// Unified Governance System
// ============================================================================

/// The complete Bi-Cameral governance system
pub struct BicameralGovernance {
    /// House of Tokens (Commons)
    pub commons: HouseOfTokens,
    /// House of Sovereigns (Senate)
    pub senate: HouseOfSovereigns,
    /// Governance treasury
    pub treasury: Treasury,
    /// Proposal counter
    next_proposal_id: u64,
}

#[derive(Debug, Clone)]
pub struct Treasury {
    /// Balance
    pub balance: u128,
    /// Reserved funds
    pub reserved: u128,
    /// Emergency fund
    pub emergency_fund: u128,
}

impl BicameralGovernance {
    pub fn new() -> Self {
        BicameralGovernance {
            commons: HouseOfTokens::new(CommonsConfig::default()),
            senate: HouseOfSovereigns::new(SenateConfig::default()),
            treasury: Treasury {
                balance: 0,
                reserved: 0,
                emergency_fund: 0,
            },
            next_proposal_id: 0,
        }
    }

    /// Check if a proposal can be executed
    pub fn can_execute(&self, proposal_id: u64) -> Result<bool, GovernanceError> {
        // Check if passed in Commons
        let proposal = self.commons.proposals.get(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        if proposal.status != ProposalStatus::Passed {
            return Ok(false);
        }

        // Check if vetoed by Senate
        for veto in self.senate.veto_proposals.values() {
            if veto.target_proposal_id == proposal_id && veto.status == VetoStatus::Passed {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Generate governance comparison report
    pub fn comparison_report(&self) -> String {
        r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║              BI-CAMERAL GOVERNANCE: ENTERPRISE STABILITY                       ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                                ║
║  THE PROBLEM WITH TOKEN-ONLY GOVERNANCE:                                       ║
║  ┌──────────────────────────────────────────────────────────────────────────┐ ║
║  │                                                                          │ ║
║  │  Ethereum/Solana: Governed by "Token Weight"                            │ ║
║  │                                                                          │ ║
║  │  Attack Scenario:                                                        │ ║
║  │  1. Hostile entity accumulates 51% of tokens                            │ ║
║  │  2. Proposes malicious upgrade (backdoor, freeze, etc.)                 │ ║
║  │  3. Vote passes (they have majority)                                    │ ║
║  │  4. Banks lose control of their infrastructure                          │ ║
║  │                                                                          │ ║
║  │  Result: FAB/DBS CANNOT use Ethereum for critical systems               │ ║
║  │                                                                          │ ║
║  └──────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                ║
║  THE AETHELRED SOLUTION: BI-CAMERAL GOVERNANCE                                 ║
║  ┌──────────────────────────────────────────────────────────────────────────┐ ║
║  │                                                                          │ ║
║  │  HOUSE OF TOKENS (The Commons)                                          │ ║
║  │  ┌─────────────────────────────────────────────────────────────────┐    │ ║
║  │  │  Who: All AETH token holders                                    │    │ ║
║  │  │  Power: Vote on economic parameters                             │    │ ║
║  │  │  • Fee rates                                                    │    │ ║
║  │  │  • Burn parameters                                              │    │ ║
║  │  │  • Treasury spending                                            │    │ ║
║  │  │  • Inflation rates                                              │    │ ║
║  │  │  Voting: Quadratic (prevents whale domination)                  │    │ ║
║  │  └─────────────────────────────────────────────────────────────────┘    │ ║
║  │                                                                          │ ║
║  │                           ▼ Proposals flow to ▼                         │ ║
║  │                                                                          │ ║
║  │  HOUSE OF SOVEREIGNS (The Senate)                                       │ ║
║  │  ┌─────────────────────────────────────────────────────────────────┐    │ ║
║  │  │  Who: Verified entities (FAB, M42, DBS, validators)             │    │ ║
║  │  │  Power: VETO over security & compliance                         │    │ ║
║  │  │  • Security upgrades                                            │    │ ║
║  │  │  • Compliance module changes                                    │    │ ║
║  │  │  • TEE policy changes                                           │    │ ║
║  │  │  • Emergency actions                                            │    │ ║
║  │  │  Voting: One entity, one vote (KYB verified)                    │    │ ║
║  │  └─────────────────────────────────────────────────────────────────┘    │ ║
║  │                                                                          │ ║
║  └──────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                ║
║  ATTACK SCENARIO (Mitigated):                                                  ║
║  ┌──────────────────────────────────────────────────────────────────────────┐ ║
║  │  1. Hostile entity buys 51% of tokens                                   │ ║
║  │  2. Proposes malicious security upgrade                                 │ ║
║  │  3. Vote passes in Commons (they have majority)                         │ ║
║  │  4. Senate reviews... FAB sees the backdoor                             │ ║
║  │  5. FAB + DBS + M42 VETO (51% of Senate)                               │ ║
║  │  6. Proposal blocked, network safe                                      │ ║
║  │                                                                          │ ║
║  │  Result: Banks maintain control over security                           │ ║
║  └──────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                ║
║  COMPARISON:                                                                   ║
║  ┌─────────────────┬─────────────────┬─────────────────────────────────────┐  ║
║  │  Feature        │  Ethereum       │  Aethelred                          │  ║
║  │  ────────────────────────────────────────────────────────────────────── │  ║
║  │  Voting         │  Token weight   │  Quadratic + Senate veto            │  ║
║  │  Whale attack   │  Vulnerable     │  Mitigated                          │  ║
║  │  Enterprise     │  Risky          │  Safe                               │  ║
║  │  Compliance     │  Ad-hoc         │  Built-in Senate oversight          │  ║
║  │  Emergency      │  Slow/chaotic   │  Senate can act fast                │  ║
║  └─────────────────┴─────────────────┴─────────────────────────────────────┘  ║
║                                                                                ║
║  WHY BANKS CHOOSE AETHELRED:                                                   ║
║  "We can participate in decentralized governance while maintaining            ║
║   the security controls our regulators require."                              ║
║                                                                                ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"#.to_string()
    }
}

impl Default for BicameralGovernance {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Clone)]
pub enum GovernanceError {
    NotAHolder,
    NotASenator,
    InsufficientVotingPower { required: u128, actual: u128 },
    InsufficientStake { required: u128, actual: u128 },
    ProposalNotFound,
    VotingNotStarted,
    VotingEnded,
    VotingNotEnded,
    AlreadyVoted,
    NotAuthorized,
    InvalidProposal(String),
}

impl std::fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GovernanceError::NotAHolder => write!(f, "Address is not a token holder"),
            GovernanceError::NotASenator => write!(f, "Address is not a Senate member"),
            GovernanceError::InsufficientVotingPower { required, actual } => {
                write!(f, "Insufficient voting power: {} required, {} actual", required, actual)
            }
            GovernanceError::InsufficientStake { required, actual } => {
                write!(f, "Insufficient stake: {} required, {} actual", required, actual)
            }
            GovernanceError::ProposalNotFound => write!(f, "Proposal not found"),
            GovernanceError::VotingNotStarted => write!(f, "Voting has not started"),
            GovernanceError::VotingEnded => write!(f, "Voting has ended"),
            GovernanceError::VotingNotEnded => write!(f, "Voting has not ended"),
            GovernanceError::AlreadyVoted => write!(f, "Already voted on this proposal"),
            GovernanceError::NotAuthorized => write!(f, "Not authorized for this action"),
            GovernanceError::InvalidProposal(msg) => write!(f, "Invalid proposal: {}", msg),
        }
    }
}

impl std::error::Error for GovernanceError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quadratic_voting_power() {
        let commons = HouseOfTokens::new(CommonsConfig::default());

        // With quadratic voting, 10,000 tokens gives sqrt(10,000) * 1000 = 100,000 power
        let power_10k = commons.calculate_voting_power(10_000);
        let power_1m = commons.calculate_voting_power(1_000_000);

        // 100x more tokens should give only 10x more voting power
        assert!(power_1m < power_10k * 20);
    }

    #[test]
    fn test_senate_veto() {
        let mut senate = HouseOfSovereigns::new(SenateConfig::default());

        // Add founding members
        for i in 0..5 {
            let entity = SovereignEntity {
                entity_id: [i; 32],
                name: format!("Bank {}", i),
                entity_type: EntityType::FinancialInstitution {
                    license_type: "Banking".to_string(),
                    regulator: "Central Bank".to_string(),
                },
                jurisdiction: Jurisdiction::UAE,
                verification: VerificationStatus::Verified {
                    verified_at: 0,
                    verifier: "Aethelred".to_string(),
                    valid_until: u64::MAX,
                },
                voting_key: [i; 32],
                joined_at: 0,
                stake: 100_000 * 10u128.pow(18),
            };
            senate.add_founding_member(entity).unwrap();
        }

        assert_eq!(senate.member_count(), 5);

        // Initiate veto
        let veto_id = senate.initiate_veto(
            [0; 32],
            1,
            "Security concern".to_string(),
            VetoCategory::Security,
        ).unwrap();

        // Vote to veto
        for i in 0..3 {
            senate.vote_on_veto(veto_id, [i; 32], true).unwrap();
        }

        // Check veto passed (3/5 > 51%)
        let veto = senate.veto_proposals.get(&veto_id).unwrap();
        assert_eq!(veto.status, VetoStatus::Passed);
    }

    #[test]
    fn test_bicameral_governance() {
        let governance = BicameralGovernance::new();
        let report = governance.comparison_report();

        assert!(report.contains("BI-CAMERAL"));
        assert!(report.contains("HOUSE OF TOKENS"));
        assert!(report.contains("HOUSE OF SOVEREIGNS"));
        assert!(report.contains("VETO"));
    }
}
