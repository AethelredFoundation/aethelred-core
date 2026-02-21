//! Pillar 1: Proof of Useful Work (PoUW)
//!
//! ## The Competitor Gap
//!
//! - **Bitcoin**: Wastes energy on meaningless hashes (PoW)
//! - **Ethereum/Solana**: Rewards passive capital (PoS) - A validator with $10M
//!   secures the network but adds **zero productivity**
//!
//! ## The Aethelred Advantage
//!
//! 80% of hashing power directed at **useful AI inference**:
//! - Protein folding
//! - Medical image analysis
//! - Financial risk modeling
//! - Climate simulations
//!
//! Only 20% is consensus overhead.
//!
//! ## The Useful Work Router
//!
//! A mempool layer that splits transactions into:
//! - **Financial Txs** (fast, lightweight) → High TPS for payments
//! - **Compute Jobs** (heavy, AI inference) → Utilizes idle GPU power
//!
//! This ensures the network is always productive, not just secure.

use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::cmp::Ordering;
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};

// ============================================================================
// Work Categories
// ============================================================================

/// Categories of useful work the network can perform
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum UsefulWorkCategory {
    /// Scientific research computations
    Scientific {
        domain: ScientificDomain,
        priority: ResearchPriority,
    },
    /// Financial AI computations
    Financial {
        model_type: FinancialModelType,
        urgency: Urgency,
    },
    /// Healthcare AI computations
    Healthcare {
        computation_type: HealthcareComputation,
        hipaa_required: bool,
    },
    /// Environmental/Climate modeling
    Environmental {
        simulation_type: EnvironmentalSimulation,
    },
    /// General ML inference
    GeneralML {
        model_hash: [u8; 32],
        framework: MLFramework,
    },
    /// Rendering and graphics
    Rendering {
        render_type: RenderType,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ScientificDomain {
    /// Protein structure prediction (AlphaFold-style)
    ProteinFolding,
    /// Drug discovery and molecular docking
    DrugDiscovery,
    /// Genomic analysis
    Genomics,
    /// Astronomical data processing
    Astronomy,
    /// Particle physics simulations
    ParticlePhysics,
    /// Materials science
    MaterialsScience,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ResearchPriority {
    /// Urgent research (pandemic response, etc.)
    Critical,
    /// High-priority funded research
    High,
    /// Standard academic research
    Normal,
    /// Background computation
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum FinancialModelType {
    /// Credit risk scoring
    CreditScoring,
    /// Fraud detection
    FraudDetection,
    /// Market risk (VaR, etc.)
    MarketRisk,
    /// Anti-money laundering
    AML,
    /// Algorithmic trading signals
    TradingSignals,
    /// Insurance underwriting
    InsuranceUnderwriting,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Urgency {
    /// Real-time (< 100ms)
    RealTime,
    /// Near real-time (< 1s)
    NearRealTime,
    /// Batch processing (< 1 hour)
    Batch,
    /// Background (best effort)
    Background,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum HealthcareComputation {
    /// Medical image analysis (X-ray, MRI, CT)
    MedicalImaging,
    /// Diagnostic AI
    Diagnosis,
    /// Treatment recommendation
    TreatmentPlan,
    /// Drug interaction analysis
    DrugInteraction,
    /// Patient risk stratification
    RiskStratification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EnvironmentalSimulation {
    /// Climate modeling
    ClimateModeling,
    /// Weather prediction
    WeatherPrediction,
    /// Carbon footprint analysis
    CarbonAnalysis,
    /// Biodiversity modeling
    BiodiversityModeling,
    /// Ocean current simulation
    OceanSimulation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MLFramework {
    ONNX,
    TensorFlow,
    PyTorch,
    JAX,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RenderType {
    /// 3D scene rendering
    Scene3D,
    /// Neural radiance fields
    NeRF,
    /// Diffusion model image generation
    DiffusionModel,
    /// Video encoding/transcoding
    VideoProcessing,
}

// ============================================================================
// Transaction Types
// ============================================================================

/// A transaction in the Aethelred network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AethelredTransaction {
    /// Standard financial transaction (fast path)
    Financial(FinancialTransaction),
    /// Compute job (useful work path)
    Compute(ComputeJob),
    /// Governance transaction
    Governance(GovernanceTransaction),
    /// Bridge transaction
    Bridge(BridgeTransaction),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinancialTransaction {
    /// Transaction hash
    pub hash: [u8; 32],
    /// Sender address
    pub from: [u8; 32],
    /// Recipient address
    pub to: [u8; 32],
    /// Amount in smallest unit
    pub amount: u128,
    /// Gas price
    pub gas_price: u64,
    /// Gas limit
    pub gas_limit: u64,
    /// Nonce
    pub nonce: u64,
    /// Standard signature (Ed25519)
    pub signature: [u8; 64],
    /// Post-quantum signature (Dilithium3)
    pub pq_signature: Option<Vec<u8>>,
    /// Timestamp
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeJob {
    /// Job ID
    pub id: [u8; 32],
    /// Work category
    pub category: UsefulWorkCategory,
    /// Model hash (SHA-256 of model weights)
    pub model_hash: [u8; 32],
    /// Input data hash
    pub input_hash: [u8; 32],
    /// Encrypted input data (for TEE processing)
    pub encrypted_input: Vec<u8>,
    /// Requester address
    pub requester: [u8; 32],
    /// Compute bounty (payment for work)
    pub bounty: u128,
    /// Maximum execution time
    pub max_execution_time: Duration,
    /// Required TEE platform
    pub required_tee: Option<TEERequirement>,
    /// Deadline
    pub deadline: Option<u64>,
    /// Priority multiplier (higher = more priority, more cost)
    pub priority_multiplier: f64,
    /// Signature
    pub signature: [u8; 64],
    /// Post-quantum signature
    pub pq_signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceTransaction {
    pub hash: [u8; 32],
    pub proposer: [u8; 32],
    pub action: GovernanceAction,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceAction {
    Propose { proposal_id: u64, description: String },
    Vote { proposal_id: u64, vote: bool },
    Veto { proposal_id: u64, reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeTransaction {
    pub hash: [u8; 32],
    pub source_chain: String,
    pub destination_chain: String,
    pub payload: Vec<u8>,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TEERequirement {
    IntelSGX { min_svn: u16 },
    AMDSEV { variant: String },
    AWSNitro,
    Any,
}

// ============================================================================
// The Useful Work Router
// ============================================================================

/// The Useful Work Router - Heart of the PoUW consensus
///
/// Splits the mempool into two lanes:
/// 1. **Fast Lane**: Financial transactions (high TPS, low latency)
/// 2. **Compute Lane**: AI inference jobs (high value, parallel execution)
pub struct UsefulWorkRouter {
    /// Fast lane for financial transactions
    fast_lane: VecDeque<FinancialTransaction>,
    /// Compute lane for AI jobs (priority queue)
    compute_lane: BinaryHeap<PrioritizedComputeJob>,
    /// Governance transactions
    governance_queue: VecDeque<GovernanceTransaction>,
    /// Bridge transactions
    bridge_queue: VecDeque<BridgeTransaction>,
    /// Active compute jobs being processed
    active_jobs: HashMap<[u8; 32], ActiveJob>,
    /// Completed jobs awaiting finalization
    completed_jobs: HashMap<[u8; 32], CompletedJob>,
    /// Router configuration
    config: RouterConfig,
    /// Metrics
    metrics: RouterMetrics,
}

#[derive(Debug, Clone)]
pub struct RouterConfig {
    /// Maximum transactions in fast lane
    pub max_fast_lane_size: usize,
    /// Maximum jobs in compute lane
    pub max_compute_lane_size: usize,
    /// Target ratio of useful work (0.8 = 80%)
    pub useful_work_ratio: f64,
    /// Minimum bounty for compute jobs
    pub min_compute_bounty: u128,
    /// Maximum parallel compute jobs
    pub max_parallel_jobs: usize,
    /// Block time target
    pub block_time_target: Duration,
}

impl Default for RouterConfig {
    fn default() -> Self {
        RouterConfig {
            max_fast_lane_size: 10_000,
            max_compute_lane_size: 1_000,
            useful_work_ratio: 0.80, // 80% useful work
            min_compute_bounty: 1_000_000, // Minimum 0.001 AETH
            max_parallel_jobs: 64,
            block_time_target: Duration::from_millis(400),
        }
    }
}

/// A compute job with priority for the heap
#[derive(Debug, Clone)]
struct PrioritizedComputeJob {
    job: ComputeJob,
    priority_score: u64,
    received_at: SystemTime,
}

impl PartialEq for PrioritizedComputeJob {
    fn eq(&self, other: &Self) -> bool {
        self.priority_score == other.priority_score
    }
}

impl Eq for PrioritizedComputeJob {}

impl PartialOrd for PrioritizedComputeJob {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritizedComputeJob {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first
        self.priority_score.cmp(&other.priority_score)
    }
}

#[derive(Debug, Clone)]
pub struct ActiveJob {
    pub job: ComputeJob,
    pub assigned_validator: [u8; 32],
    pub started_at: SystemTime,
    pub tee_attestation: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct CompletedJob {
    pub job_id: [u8; 32],
    pub result_hash: [u8; 32],
    pub validator: [u8; 32],
    pub execution_time: Duration,
    pub tee_attestation: Vec<u8>,
    pub useful_work_units: u64,
    pub completed_at: SystemTime,
}

#[derive(Debug, Clone, Default)]
pub struct RouterMetrics {
    /// Total financial transactions processed
    pub total_financial_txs: u64,
    /// Total compute jobs processed
    pub total_compute_jobs: u64,
    /// Total useful work units generated
    pub total_useful_work_units: u64,
    /// Energy spent on useful work (in kWh equivalent)
    pub useful_work_energy_kwh: f64,
    /// Energy that would have been wasted (saved)
    pub energy_saved_kwh: f64,
    /// Average compute job execution time
    pub avg_job_execution_time: Duration,
    /// Current useful work ratio
    pub current_useful_work_ratio: f64,
}

impl UsefulWorkRouter {
    pub fn new(config: RouterConfig) -> Self {
        UsefulWorkRouter {
            fast_lane: VecDeque::new(),
            compute_lane: BinaryHeap::new(),
            governance_queue: VecDeque::new(),
            bridge_queue: VecDeque::new(),
            active_jobs: HashMap::new(),
            completed_jobs: HashMap::new(),
            config,
            metrics: RouterMetrics::default(),
        }
    }

    /// Submit a transaction to the router
    pub fn submit(&mut self, tx: AethelredTransaction) -> Result<(), RouterError> {
        match tx {
            AethelredTransaction::Financial(ftx) => {
                if self.fast_lane.len() >= self.config.max_fast_lane_size {
                    return Err(RouterError::FastLaneFull);
                }
                self.fast_lane.push_back(ftx);
            }
            AethelredTransaction::Compute(job) => {
                if job.bounty < self.config.min_compute_bounty {
                    return Err(RouterError::BountyTooLow {
                        provided: job.bounty,
                        minimum: self.config.min_compute_bounty,
                    });
                }
                if self.compute_lane.len() >= self.config.max_compute_lane_size {
                    return Err(RouterError::ComputeLaneFull);
                }
                let priority_score = self.calculate_priority(&job);
                self.compute_lane.push(PrioritizedComputeJob {
                    job,
                    priority_score,
                    received_at: SystemTime::now(),
                });
            }
            AethelredTransaction::Governance(gtx) => {
                self.governance_queue.push_back(gtx);
            }
            AethelredTransaction::Bridge(btx) => {
                self.bridge_queue.push_back(btx);
            }
        }
        Ok(())
    }

    /// Calculate priority score for a compute job
    fn calculate_priority(&self, job: &ComputeJob) -> u64 {
        let mut score: u64 = 0;

        // Base score from bounty (logarithmic to prevent plutocracy)
        score += (job.bounty as f64).log2() as u64 * 100;

        // Category-based priority
        score += match &job.category {
            UsefulWorkCategory::Healthcare { .. } => 500, // Healthcare gets priority
            UsefulWorkCategory::Scientific { priority, .. } => match priority {
                ResearchPriority::Critical => 1000,
                ResearchPriority::High => 400,
                ResearchPriority::Normal => 200,
                ResearchPriority::Low => 50,
            },
            UsefulWorkCategory::Financial { urgency, .. } => match urgency {
                Urgency::RealTime => 800,
                Urgency::NearRealTime => 400,
                Urgency::Batch => 100,
                Urgency::Background => 25,
            },
            UsefulWorkCategory::Environmental { .. } => 300,
            UsefulWorkCategory::GeneralML { .. } => 100,
            UsefulWorkCategory::Rendering { .. } => 50,
        };

        // Deadline urgency
        if let Some(deadline) = job.deadline {
            let now = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if deadline > now {
                let time_left = deadline - now;
                if time_left < 60 {
                    score += 500; // Less than 1 minute
                } else if time_left < 300 {
                    score += 200; // Less than 5 minutes
                }
            }
        }

        // Priority multiplier
        score = (score as f64 * job.priority_multiplier) as u64;

        score
    }

    /// Build the next block with optimal useful work ratio
    pub fn build_block(&mut self, block_gas_limit: u64) -> BlockProposal {
        let mut proposal = BlockProposal {
            financial_txs: Vec::new(),
            compute_jobs: Vec::new(),
            governance_txs: Vec::new(),
            bridge_txs: Vec::new(),
            useful_work_ratio: 0.0,
            estimated_gas: 0,
        };

        let target_useful_work_gas = (block_gas_limit as f64 * self.config.useful_work_ratio) as u64;
        let target_financial_gas = block_gas_limit - target_useful_work_gas;

        // Fill compute jobs first (useful work)
        let mut compute_gas_used: u64 = 0;
        while let Some(pjob) = self.compute_lane.peek() {
            let job_gas = self.estimate_compute_gas(&pjob.job);
            if compute_gas_used + job_gas > target_useful_work_gas {
                break;
            }
            if let Some(pjob) = self.compute_lane.pop() {
                compute_gas_used += job_gas;
                proposal.compute_jobs.push(pjob.job);
            }
        }

        // Fill financial transactions
        let mut financial_gas_used: u64 = 0;
        while let Some(ftx) = self.fast_lane.front() {
            let tx_gas = ftx.gas_limit;
            if financial_gas_used + tx_gas > target_financial_gas {
                break;
            }
            if let Some(ftx) = self.fast_lane.pop_front() {
                financial_gas_used += tx_gas;
                proposal.financial_txs.push(ftx);
            }
        }

        // Add governance and bridge transactions (low gas, high priority)
        while let Some(gtx) = self.governance_queue.pop_front() {
            proposal.governance_txs.push(gtx);
        }
        while let Some(btx) = self.bridge_queue.pop_front() {
            proposal.bridge_txs.push(btx);
        }

        // Calculate actual useful work ratio
        let total_gas = compute_gas_used + financial_gas_used;
        proposal.useful_work_ratio = if total_gas > 0 {
            compute_gas_used as f64 / total_gas as f64
        } else {
            0.0
        };
        proposal.estimated_gas = total_gas;

        proposal
    }

    fn estimate_compute_gas(&self, job: &ComputeJob) -> u64 {
        // Base gas for compute job
        let base_gas = 100_000u64;

        // Category-specific gas estimation
        let category_gas = match &job.category {
            UsefulWorkCategory::Scientific { domain, .. } => match domain {
                ScientificDomain::ProteinFolding => 5_000_000,
                ScientificDomain::DrugDiscovery => 3_000_000,
                ScientificDomain::Genomics => 2_000_000,
                ScientificDomain::Astronomy => 1_500_000,
                ScientificDomain::ParticlePhysics => 4_000_000,
                ScientificDomain::MaterialsScience => 2_500_000,
            },
            UsefulWorkCategory::Healthcare { computation_type, .. } => match computation_type {
                HealthcareComputation::MedicalImaging => 2_000_000,
                HealthcareComputation::Diagnosis => 1_000_000,
                HealthcareComputation::TreatmentPlan => 1_500_000,
                HealthcareComputation::DrugInteraction => 500_000,
                HealthcareComputation::RiskStratification => 800_000,
            },
            UsefulWorkCategory::Financial { model_type, .. } => match model_type {
                FinancialModelType::CreditScoring => 500_000,
                FinancialModelType::FraudDetection => 300_000,
                FinancialModelType::MarketRisk => 1_000_000,
                FinancialModelType::AML => 700_000,
                FinancialModelType::TradingSignals => 200_000,
                FinancialModelType::InsuranceUnderwriting => 600_000,
            },
            UsefulWorkCategory::Environmental { simulation_type } => match simulation_type {
                EnvironmentalSimulation::ClimateModeling => 10_000_000,
                EnvironmentalSimulation::WeatherPrediction => 3_000_000,
                EnvironmentalSimulation::CarbonAnalysis => 1_000_000,
                EnvironmentalSimulation::BiodiversityModeling => 2_000_000,
                EnvironmentalSimulation::OceanSimulation => 5_000_000,
            },
            UsefulWorkCategory::GeneralML { .. } => 1_000_000,
            UsefulWorkCategory::Rendering { render_type } => match render_type {
                RenderType::Scene3D => 2_000_000,
                RenderType::NeRF => 5_000_000,
                RenderType::DiffusionModel => 3_000_000,
                RenderType::VideoProcessing => 1_500_000,
            },
        };

        base_gas + category_gas
    }

    /// Record a completed job
    pub fn complete_job(&mut self, completed: CompletedJob) {
        self.metrics.total_compute_jobs += 1;
        self.metrics.total_useful_work_units += completed.useful_work_units;
        self.completed_jobs.insert(completed.job_id, completed);
    }

    /// Get current metrics
    pub fn metrics(&self) -> &RouterMetrics {
        &self.metrics
    }

    /// Calculate ESG impact
    pub fn calculate_esg_impact(&self) -> ESGImpact {
        // Traditional PoW would waste ~100% on useless hashes
        // Aethelred uses 80% for useful work
        let wasted_energy_ratio = 1.0 - self.config.useful_work_ratio;
        let useful_energy_ratio = self.config.useful_work_ratio;

        // Estimate based on Bitcoin's energy usage as baseline
        // Bitcoin: ~150 TWh/year for zero useful computation
        // Aethelred: Same energy, 80% useful
        let estimated_annual_energy_twh = 0.1; // Much smaller network initially
        let useful_computation_twh = estimated_annual_energy_twh * useful_energy_ratio;

        ESGImpact {
            useful_work_ratio: useful_energy_ratio,
            useful_computation_twh,
            wasted_energy_twh: estimated_annual_energy_twh * wasted_energy_ratio,
            equivalent_research_value_usd: useful_computation_twh * 1_000_000.0, // $1M per TWh of compute
            carbon_offset_potential_tons: useful_computation_twh * 500.0, // Rough estimate
            research_contributions: ResearchContributions {
                protein_structures_predicted: self.metrics.total_useful_work_units / 1000,
                drug_candidates_screened: self.metrics.total_useful_work_units / 500,
                climate_simulations_run: self.metrics.total_useful_work_units / 10000,
                medical_images_analyzed: self.metrics.total_useful_work_units / 100,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlockProposal {
    pub financial_txs: Vec<FinancialTransaction>,
    pub compute_jobs: Vec<ComputeJob>,
    pub governance_txs: Vec<GovernanceTransaction>,
    pub bridge_txs: Vec<BridgeTransaction>,
    pub useful_work_ratio: f64,
    pub estimated_gas: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ESGImpact {
    /// Ratio of energy used for useful work
    pub useful_work_ratio: f64,
    /// Useful computation in TWh
    pub useful_computation_twh: f64,
    /// Wasted energy in TWh
    pub wasted_energy_twh: f64,
    /// Equivalent research value in USD
    pub equivalent_research_value_usd: f64,
    /// Carbon offset potential in tons
    pub carbon_offset_potential_tons: f64,
    /// Research contributions
    pub research_contributions: ResearchContributions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchContributions {
    pub protein_structures_predicted: u64,
    pub drug_candidates_screened: u64,
    pub climate_simulations_run: u64,
    pub medical_images_analyzed: u64,
}

#[derive(Debug, Clone)]
pub enum RouterError {
    FastLaneFull,
    ComputeLaneFull,
    BountyTooLow { provided: u128, minimum: u128 },
    InvalidJob(String),
}

impl std::fmt::Display for RouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouterError::FastLaneFull => write!(f, "Fast lane is full"),
            RouterError::ComputeLaneFull => write!(f, "Compute lane is full"),
            RouterError::BountyTooLow { provided, minimum } => {
                write!(f, "Bounty {} is below minimum {}", provided, minimum)
            }
            RouterError::InvalidJob(msg) => write!(f, "Invalid job: {}", msg),
        }
    }
}

impl std::error::Error for RouterError {}

// ============================================================================
// Useful Work Validator
// ============================================================================

/// A validator in the Proof of Useful Work consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsefulWorkValidator {
    /// Validator address
    pub address: [u8; 32],
    /// Staked amount
    pub stake: u128,
    /// Available compute resources
    pub compute_resources: ComputeResources,
    /// TEE capabilities
    pub tee_capabilities: Vec<TEERequirement>,
    /// Total useful work units completed
    pub total_useful_work: u64,
    /// Reputation score (0-100)
    pub reputation: u8,
    /// Specializations (work categories they're good at)
    pub specializations: Vec<UsefulWorkCategory>,
    /// Online status
    pub is_online: bool,
    /// Last seen timestamp
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeResources {
    /// GPU type
    pub gpu_type: String,
    /// GPU memory in GB
    pub gpu_memory_gb: u32,
    /// Number of GPUs
    pub gpu_count: u8,
    /// CPU cores
    pub cpu_cores: u32,
    /// RAM in GB
    pub ram_gb: u32,
    /// Available storage in GB
    pub storage_gb: u64,
    /// Network bandwidth in Gbps
    pub bandwidth_gbps: f64,
}

/// Validator selection for compute jobs
pub struct ValidatorSelector {
    validators: Vec<UsefulWorkValidator>,
}

impl ValidatorSelector {
    pub fn new(validators: Vec<UsefulWorkValidator>) -> Self {
        ValidatorSelector { validators }
    }

    /// Select the best validator for a compute job
    pub fn select_for_job(&self, job: &ComputeJob) -> Option<&UsefulWorkValidator> {
        self.validators
            .iter()
            .filter(|v| v.is_online)
            .filter(|v| self.can_handle_job(v, job))
            .max_by_key(|v| self.score_validator_for_job(v, job))
    }

    fn can_handle_job(&self, validator: &UsefulWorkValidator, job: &ComputeJob) -> bool {
        // Check TEE requirements
        if let Some(ref required_tee) = job.required_tee {
            if !validator.tee_capabilities.contains(required_tee) {
                return false;
            }
        }

        // Check if validator has enough resources
        // (simplified - real implementation would check GPU memory, etc.)
        true
    }

    fn score_validator_for_job(&self, validator: &UsefulWorkValidator, job: &ComputeJob) -> u64 {
        let mut score: u64 = 0;

        // Reputation bonus
        score += validator.reputation as u64 * 10;

        // Specialization bonus
        if validator.specializations.contains(&job.category) {
            score += 500;
        }

        // Useful work track record
        score += (validator.total_useful_work as f64).log2() as u64 * 50;

        // Stake weight (but capped to prevent plutocracy)
        score += (validator.stake as f64).log2().min(100.0) as u64;

        score
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_creation() {
        let router = UsefulWorkRouter::new(RouterConfig::default());
        assert_eq!(router.config.useful_work_ratio, 0.80);
    }

    #[test]
    fn test_compute_job_submission() {
        let mut router = UsefulWorkRouter::new(RouterConfig::default());

        let job = ComputeJob {
            id: [1u8; 32],
            category: UsefulWorkCategory::Healthcare {
                computation_type: HealthcareComputation::MedicalImaging,
                hipaa_required: true,
            },
            model_hash: [2u8; 32],
            input_hash: [3u8; 32],
            encrypted_input: vec![0u8; 100],
            requester: [4u8; 32],
            bounty: 10_000_000, // Above minimum
            max_execution_time: Duration::from_secs(60),
            required_tee: Some(TEERequirement::IntelSGX { min_svn: 10 }),
            deadline: None,
            priority_multiplier: 1.0,
            signature: [0u8; 64],
            pq_signature: None,
        };

        let result = router.submit(AethelredTransaction::Compute(job));
        assert!(result.is_ok());
    }

    #[test]
    fn test_bounty_too_low() {
        let mut router = UsefulWorkRouter::new(RouterConfig::default());

        let job = ComputeJob {
            id: [1u8; 32],
            category: UsefulWorkCategory::GeneralML {
                model_hash: [0u8; 32],
                framework: MLFramework::ONNX,
            },
            model_hash: [2u8; 32],
            input_hash: [3u8; 32],
            encrypted_input: vec![],
            requester: [4u8; 32],
            bounty: 100, // Below minimum
            max_execution_time: Duration::from_secs(60),
            required_tee: None,
            deadline: None,
            priority_multiplier: 1.0,
            signature: [0u8; 64],
            pq_signature: None,
        };

        let result = router.submit(AethelredTransaction::Compute(job));
        assert!(matches!(result, Err(RouterError::BountyTooLow { .. })));
    }

    #[test]
    fn test_block_building() {
        let mut router = UsefulWorkRouter::new(RouterConfig::default());

        // Submit some compute jobs
        for i in 0..5 {
            let job = ComputeJob {
                id: [i; 32],
                category: UsefulWorkCategory::Scientific {
                    domain: ScientificDomain::ProteinFolding,
                    priority: ResearchPriority::High,
                },
                model_hash: [2u8; 32],
                input_hash: [3u8; 32],
                encrypted_input: vec![],
                requester: [4u8; 32],
                bounty: 10_000_000,
                max_execution_time: Duration::from_secs(60),
                required_tee: None,
                deadline: None,
                priority_multiplier: 1.0,
                signature: [0u8; 64],
                pq_signature: None,
            };
            router.submit(AethelredTransaction::Compute(job)).unwrap();
        }

        // Submit some financial transactions
        for i in 0..10 {
            let ftx = FinancialTransaction {
                hash: [i; 32],
                from: [1u8; 32],
                to: [2u8; 32],
                amount: 1000,
                gas_price: 1,
                gas_limit: 21000,
                nonce: i as u64,
                signature: [0u8; 64],
                pq_signature: None,
                timestamp: 0,
            };
            router.submit(AethelredTransaction::Financial(ftx)).unwrap();
        }

        let proposal = router.build_block(30_000_000);
        assert!(!proposal.compute_jobs.is_empty());
        assert!(!proposal.financial_txs.is_empty());
        // Should be close to 80% useful work ratio
        assert!(proposal.useful_work_ratio > 0.5);
    }

    #[test]
    fn test_esg_impact() {
        let router = UsefulWorkRouter::new(RouterConfig::default());
        let impact = router.calculate_esg_impact();

        assert_eq!(impact.useful_work_ratio, 0.80);
        assert!(impact.equivalent_research_value_usd > 0.0);
    }
}
