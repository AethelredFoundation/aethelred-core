//! Pillar 5: Congestion-Squared Deflation
//!
//! ## The Competitor Gap
//!
//! - **Solana**: Fees are too cheap (spam problems)
//! - **Ethereum**: Fees are volatile but linear
//!
//! ## The Aethelred Advantage
//!
//! Turn network congestion into a value driver for holders.
//!
//! ## Quadratic Burning
//!
//! The more the network is used, the burn rate increases **exponentially (squared)**:
//!
//! | Network Load | Fee Burn Rate |
//! |--------------|---------------|
//! | 30% Load     | 5% Fee Burn   |
//! | 50% Load     | 10% Fee Burn  |
//! | 70% Load     | 15% Fee Burn  |
//! | 90% Load     | 25% Fee Burn  |
//!
//! This ensures that if Aethelred becomes the global AI layer, the supply shock
//! is **massive**, rewarding early adopters.

// H-08: Production safety — prevent shipping dev tokenomics stubs.
// Building with `--features production` will fail here, forcing
// the integrator to wire in the production-grade implementation.
#[cfg(feature = "production")]
compile_error!(
    "quadratic_burn stub is active in a production build. \
     Replace with the production tokenomics engine before shipping."
);

use std::collections::VecDeque;
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};

// ============================================================================
// Token Economics
// ============================================================================

/// AETH Token Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AETHTokenConfig {
    /// Total initial supply (in smallest unit)
    pub total_supply: u128,
    /// Decimals
    pub decimals: u8,
    /// Symbol
    pub symbol: String,
    /// Maximum burn rate (percentage of fees)
    pub max_burn_rate: f64,
    /// Minimum burn rate
    pub min_burn_rate: f64,
    /// Target inflation rate (for staking rewards)
    pub target_inflation_rate: f64,
    /// Quadratic burn parameters
    pub burn_params: QuadraticBurnParams,
}

impl Default for AETHTokenConfig {
    fn default() -> Self {
        AETHTokenConfig {
            total_supply: 1_000_000_000 * 10u128.pow(18), // 1 billion AETH
            decimals: 18,
            symbol: "AETH".to_string(),
            max_burn_rate: 0.50, // 50% max burn at full load
            min_burn_rate: 0.01, // 1% minimum burn
            target_inflation_rate: 0.02, // 2% annual inflation for staking
            burn_params: QuadraticBurnParams::default(),
        }
    }
}

/// Parameters for quadratic burn calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuadraticBurnParams {
    /// Base coefficient (a in ax²)
    pub coefficient: f64,
    /// Exponent (typically 2 for quadratic)
    pub exponent: f64,
    /// Offset (minimum burn rate)
    pub offset: f64,
    /// Smoothing factor for load calculation
    pub smoothing_factor: f64,
    /// Number of blocks to average for load
    pub load_window_blocks: u64,
}

impl Default for QuadraticBurnParams {
    fn default() -> Self {
        QuadraticBurnParams {
            coefficient: 0.5,  // 0.5 * load²
            exponent: 2.0,     // Quadratic
            offset: 0.01,      // 1% minimum
            smoothing_factor: 0.8,
            load_window_blocks: 100,
        }
    }
}

// ============================================================================
// Congestion Calculation
// ============================================================================

/// Network congestion tracker
pub struct CongestionTracker {
    /// Recent block gas usage
    block_gas_history: VecDeque<BlockGasUsage>,
    /// Configuration
    config: CongestionConfig,
    /// Current computed metrics
    current_metrics: CongestionMetrics,
}

#[derive(Debug, Clone)]
pub struct BlockGasUsage {
    pub block_number: u64,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub timestamp: u64,
    pub transaction_count: u32,
    pub compute_job_count: u32,
}

#[derive(Debug, Clone)]
pub struct CongestionConfig {
    /// Maximum blocks to track
    pub max_history_blocks: usize,
    /// Block gas limit
    pub block_gas_limit: u64,
    /// Target gas utilization
    pub target_utilization: f64,
    /// High congestion threshold
    pub high_congestion_threshold: f64,
    /// Critical congestion threshold
    pub critical_congestion_threshold: f64,
}

impl Default for CongestionConfig {
    fn default() -> Self {
        CongestionConfig {
            max_history_blocks: 1000,
            block_gas_limit: 30_000_000,
            target_utilization: 0.50, // 50% is healthy
            high_congestion_threshold: 0.75,
            critical_congestion_threshold: 0.90,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CongestionMetrics {
    /// Current network load (0.0 - 1.0)
    pub current_load: f64,
    /// Average load over window
    pub average_load: f64,
    /// Peak load in window
    pub peak_load: f64,
    /// Congestion level
    pub congestion_level: CongestionLevel,
    /// Trend (increasing, decreasing, stable)
    pub trend: LoadTrend,
    /// Estimated time to critical (if trending up)
    pub time_to_critical: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CongestionLevel {
    /// Network is underutilized
    Low,
    /// Network is at healthy utilization
    Normal,
    /// Network is getting busy
    High,
    /// Network is near capacity
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoadTrend {
    Increasing,
    Stable,
    Decreasing,
}

impl CongestionTracker {
    pub fn new(config: CongestionConfig) -> Self {
        CongestionTracker {
            block_gas_history: VecDeque::new(),
            config,
            current_metrics: CongestionMetrics {
                current_load: 0.0,
                average_load: 0.0,
                peak_load: 0.0,
                congestion_level: CongestionLevel::Low,
                trend: LoadTrend::Stable,
                time_to_critical: None,
            },
        }
    }

    /// Record a new block's gas usage
    pub fn record_block(&mut self, block: BlockGasUsage) {
        // Add to history
        self.block_gas_history.push_back(block.clone());

        // Trim old blocks
        while self.block_gas_history.len() > self.config.max_history_blocks {
            self.block_gas_history.pop_front();
        }

        // Update metrics
        self.update_metrics();
    }

    fn update_metrics(&mut self) {
        if self.block_gas_history.is_empty() {
            return;
        }

        // Calculate current load
        let latest = self.block_gas_history.back().unwrap();
        self.current_metrics.current_load =
            latest.gas_used as f64 / latest.gas_limit as f64;

        // Calculate average load
        let total_load: f64 = self.block_gas_history.iter()
            .map(|b| b.gas_used as f64 / b.gas_limit as f64)
            .sum();
        self.current_metrics.average_load =
            total_load / self.block_gas_history.len() as f64;

        // Calculate peak load
        self.current_metrics.peak_load = self.block_gas_history.iter()
            .map(|b| b.gas_used as f64 / b.gas_limit as f64)
            .fold(0.0, f64::max);

        // Determine congestion level
        self.current_metrics.congestion_level = if self.current_metrics.average_load < 0.30 {
            CongestionLevel::Low
        } else if self.current_metrics.average_load < self.config.high_congestion_threshold {
            CongestionLevel::Normal
        } else if self.current_metrics.average_load < self.config.critical_congestion_threshold {
            CongestionLevel::High
        } else {
            CongestionLevel::Critical
        };

        // Calculate trend
        self.current_metrics.trend = self.calculate_trend();
    }

    fn calculate_trend(&self) -> LoadTrend {
        if self.block_gas_history.len() < 10 {
            return LoadTrend::Stable;
        }

        let recent: Vec<f64> = self.block_gas_history.iter()
            .rev()
            .take(10)
            .map(|b| b.gas_used as f64 / b.gas_limit as f64)
            .collect();

        let older: Vec<f64> = self.block_gas_history.iter()
            .rev()
            .skip(10)
            .take(10)
            .map(|b| b.gas_used as f64 / b.gas_limit as f64)
            .collect();

        if older.is_empty() {
            return LoadTrend::Stable;
        }

        let recent_avg: f64 = recent.iter().sum::<f64>() / recent.len() as f64;
        let older_avg: f64 = older.iter().sum::<f64>() / older.len() as f64;

        let diff = recent_avg - older_avg;
        if diff > 0.05 {
            LoadTrend::Increasing
        } else if diff < -0.05 {
            LoadTrend::Decreasing
        } else {
            LoadTrend::Stable
        }
    }

    /// Get current metrics
    pub fn metrics(&self) -> &CongestionMetrics {
        &self.current_metrics
    }

    /// Get current load (0.0 - 1.0)
    pub fn current_load(&self) -> f64 {
        self.current_metrics.current_load
    }
}

// ============================================================================
// Quadratic Burn Engine
// ============================================================================

/// The quadratic fee burn engine
pub struct QuadraticBurnEngine {
    /// Token configuration
    token_config: AETHTokenConfig,
    /// Congestion tracker
    congestion: CongestionTracker,
    /// Burn statistics
    stats: BurnStatistics,
    /// Historical burn data
    burn_history: VecDeque<BurnRecord>,
}

const BURN_RATE_SCALE: u128 = 1_000_000_000; // 1e9 fixed-point for burn rates [0,1]

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BurnStatistics {
    /// Total AETH burned all time
    pub total_burned: u128,
    /// Burned in last 24 hours
    pub burned_24h: u128,
    /// Burned in last 7 days
    pub burned_7d: u128,
    /// Burned in last 30 days
    pub burned_30d: u128,
    /// Current burn rate (percentage)
    pub current_burn_rate: f64,
    /// Average burn rate (24h)
    pub average_burn_rate_24h: f64,
    /// Effective annual deflation rate
    pub annual_deflation_rate: f64,
    /// Circulating supply
    pub circulating_supply: u128,
    /// Current price impact estimate (percentage increase per year at current rate)
    pub estimated_price_impact: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnRecord {
    pub block_number: u64,
    pub timestamp: u64,
    pub fees_collected: u128,
    pub fees_burned: u128,
    pub burn_rate: f64,
    pub network_load: f64,
}

impl QuadraticBurnEngine {
    pub fn new(token_config: AETHTokenConfig) -> Self {
        QuadraticBurnEngine {
            token_config,
            congestion: CongestionTracker::new(CongestionConfig::default()),
            stats: BurnStatistics::default(),
            burn_history: VecDeque::new(),
        }
    }

    /// Calculate burn rate based on current network load
    pub fn calculate_burn_rate(&self, network_load: f64) -> f64 {
        let params = &self.token_config.burn_params;

        // Quadratic formula: burn_rate = a * load^2 + offset
        let raw_burn_rate = params.coefficient * network_load.powf(params.exponent) + params.offset;

        // Clamp to min/max
        raw_burn_rate
            .max(self.token_config.min_burn_rate)
            .min(self.token_config.max_burn_rate)
    }

    fn burn_rate_to_fixed(&self, burn_rate: f64) -> u128 {
        if !burn_rate.is_finite() || burn_rate <= 0.0 {
            return 0;
        }
        let clamped = burn_rate
            .max(self.token_config.min_burn_rate)
            .min(self.token_config.max_burn_rate);
        let scaled = (clamped * BURN_RATE_SCALE as f64).floor();
        if scaled <= 0.0 {
            0
        } else if scaled >= BURN_RATE_SCALE as f64 {
            BURN_RATE_SCALE
        } else {
            scaled as u128
        }
    }

    /// Process a block and calculate burns
    pub fn process_block(
        &mut self,
        block: BlockGasUsage,
        total_fees_collected: u128,
    ) -> BurnResult {
        // Update congestion
        self.congestion.record_block(block.clone());

        // Calculate burn rate
        let network_load = self.congestion.current_load();
        let burn_rate = self.calculate_burn_rate(network_load);

        // Calculate amounts
        let burn_rate_fixed = self.burn_rate_to_fixed(burn_rate);
        let fees_to_burn = total_fees_collected
            .saturating_mul(burn_rate_fixed)
            / BURN_RATE_SCALE;
        let fees_to_validators = total_fees_collected - fees_to_burn;

        // Record burn
        let record = BurnRecord {
            block_number: block.block_number,
            timestamp: block.timestamp,
            fees_collected: total_fees_collected,
            fees_burned: fees_to_burn,
            burn_rate,
            network_load,
        };
        self.burn_history.push_back(record);

        // Trim old history (keep 1 week)
        while self.burn_history.len() > 50_000 {
            self.burn_history.pop_front();
        }

        // Update statistics
        self.update_statistics(fees_to_burn);

        BurnResult {
            fees_collected: total_fees_collected,
            fees_burned: fees_to_burn,
            fees_to_validators,
            burn_rate,
            network_load,
            congestion_level: self.congestion.metrics().congestion_level,
        }
    }

    fn update_statistics(&mut self, burned_this_block: u128) {
        self.stats.total_burned += burned_this_block;
        self.stats.current_burn_rate = self.calculate_burn_rate(self.congestion.current_load());

        // Calculate time-based statistics
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let day_ago = now.saturating_sub(86400);
        let week_ago = now.saturating_sub(86400 * 7);
        let month_ago = now.saturating_sub(86400 * 30);

        self.stats.burned_24h = self.burn_history.iter()
            .filter(|r| r.timestamp >= day_ago)
            .map(|r| r.fees_burned)
            .sum();

        self.stats.burned_7d = self.burn_history.iter()
            .filter(|r| r.timestamp >= week_ago)
            .map(|r| r.fees_burned)
            .sum();

        self.stats.burned_30d = self.burn_history.iter()
            .filter(|r| r.timestamp >= month_ago)
            .map(|r| r.fees_burned)
            .sum();

        // Calculate average burn rate
        let recent_records: Vec<_> = self.burn_history.iter()
            .filter(|r| r.timestamp >= day_ago)
            .collect();

        if !recent_records.is_empty() {
            self.stats.average_burn_rate_24h = recent_records.iter()
                .map(|r| r.burn_rate)
                .sum::<f64>() / recent_records.len() as f64;
        }

        // Estimate annual deflation
        if self.stats.circulating_supply > 0 {
            let daily_burn_rate = self.stats.burned_24h as f64 / self.stats.circulating_supply as f64;
            self.stats.annual_deflation_rate = daily_burn_rate * 365.0;

            // Price impact estimate (very simplified)
            // Assumes supply/demand relationship
            self.stats.estimated_price_impact = self.stats.annual_deflation_rate * 2.0;
        }
    }

    /// Get current burn statistics
    pub fn statistics(&self) -> &BurnStatistics {
        &self.stats
    }

    /// Get burn schedule preview
    pub fn burn_schedule_preview(&self) -> BurnSchedulePreview {
        let loads = vec![0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0];
        let rates: Vec<_> = loads.iter()
            .map(|&load| (load, self.calculate_burn_rate(load)))
            .collect();

        BurnSchedulePreview {
            load_to_burn_rate: rates,
            current_load: self.congestion.current_load(),
            current_burn_rate: self.stats.current_burn_rate,
        }
    }

    /// Generate comparison report
    pub fn comparison_report(&self) -> String {
        format!(r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║              QUADRATIC BURN: AETHELRED TOKENOMICS                              ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                                ║
║  BURN SCHEDULE (Quadratic):                                                    ║
║  ┌────────────────────────────────────────────────────────────────────────┐   ║
║  │  Network Load   │  Burn Rate   │  If 1M AETH Fees/Day                 │   ║
║  │  ───────────────┼──────────────┼──────────────────────────────────────│   ║
║  │      10%        │     1.5%     │    15,000 AETH burned                │   ║
║  │      30%        │     5.5%     │    55,000 AETH burned                │   ║
║  │      50%        │    13.5%     │   135,000 AETH burned                │   ║
║  │      70%        │    25.5%     │   255,000 AETH burned                │   ║
║  │      90%        │    41.5%     │   415,000 AETH burned                │   ║
║  │     100%        │    50.0%     │   500,000 AETH burned                │   ║
║  └────────────────────────────────────────────────────────────────────────┘   ║
║                                                                                ║
║  COMPARISON WITH COMPETITORS:                                                  ║
║  ┌────────────────────────────────────────────────────────────────────────┐   ║
║  │  Chain      │  Fee Model          │  Burn Mechanism    │  Result       │   ║
║  │  ──────────────────────────────────────────────────────────────────────│   ║
║  │  Bitcoin    │  Fixed              │  None              │  Inflationary │   ║
║  │  Ethereum   │  EIP-1559 (linear)  │  Base fee burned   │  Deflationary │   ║
║  │  Solana     │  Very low fixed     │  50% burned        │  Near-zero    │   ║
║  │  Aethelred  │  Quadratic burn     │  Up to 50%         │  HYPER-DEFL   │   ║
║  └────────────────────────────────────────────────────────────────────────┘   ║
║                                                                                ║
║  THE QUADRATIC ADVANTAGE:                                                      ║
║  ┌────────────────────────────────────────────────────────────────────────┐   ║
║  │                                                                        │   ║
║  │  Linear Burn (Ethereum):                                              │   ║
║  │  • 50% load → 50% burn rate                                          │   ║
║  │  • Predictable, but not exciting                                     │   ║
║  │                                                                        │   ║
║  │  Quadratic Burn (Aethelred):                                          │   ║
║  │  • 50% load → 13.5% burn rate  (mild)                                │   ║
║  │  • 90% load → 41.5% burn rate  (MASSIVE)                             │   ║
║  │                                                                        │   ║
║  │  Why This Works:                                                      │   ║
║  │  1. Low usage = Low burn = Affordable for developers                 │   ║
║  │  2. High usage = High burn = Supply shock for holders                │   ║
║  │  3. Creates natural economic cycle                                   │   ║
║  │                                                                        │   ║
║  └────────────────────────────────────────────────────────────────────────┘   ║
║                                                                                ║
║  CURRENT STATUS:                                                               ║
║  • Network Load: {:.1}%                                                        ║
║  • Current Burn Rate: {:.2}%                                                   ║
║  • Total Burned: {} AETH                                                       ║
║  • Est. Annual Deflation: {:.2}%                                               ║
║                                                                                ║
║  IF AETHELRED BECOMES THE GLOBAL AI LAYER:                                     ║
║  • Constant 90%+ utilization                                                   ║
║  • 40%+ of all fees burned                                                     ║
║  • Significant supply reduction each year                                      ║
║  • Early adopters rewarded massively                                           ║
║                                                                                ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"#,
            self.congestion.current_load() * 100.0,
            self.stats.current_burn_rate * 100.0,
            self.stats.total_burned / 10u128.pow(18),
            self.stats.annual_deflation_rate * 100.0,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnResult {
    pub fees_collected: u128,
    pub fees_burned: u128,
    pub fees_to_validators: u128,
    pub burn_rate: f64,
    pub network_load: f64,
    pub congestion_level: CongestionLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnSchedulePreview {
    pub load_to_burn_rate: Vec<(f64, f64)>,
    pub current_load: f64,
    pub current_burn_rate: f64,
}

// ============================================================================
// Fee Calculator
// ============================================================================

/// Dynamic fee calculator with congestion pricing
pub struct FeeCalculator {
    /// Base fee per gas
    base_fee: u128,
    /// Congestion tracker
    congestion: CongestionTracker,
    /// Fee configuration
    config: FeeConfig,
}

#[derive(Debug, Clone)]
pub struct FeeConfig {
    /// Minimum base fee
    pub min_base_fee: u128,
    /// Maximum base fee
    pub max_base_fee: u128,
    /// Fee adjustment rate per block
    pub adjustment_rate: f64,
    /// Target utilization
    pub target_utilization: f64,
}

impl Default for FeeConfig {
    fn default() -> Self {
        FeeConfig {
            min_base_fee: 1_000_000_000, // 1 Gwei equivalent
            max_base_fee: 1_000_000_000_000, // 1000 Gwei equivalent
            adjustment_rate: 0.125, // 12.5% max change per block
            target_utilization: 0.50,
        }
    }
}

impl FeeCalculator {
    pub fn new(config: FeeConfig) -> Self {
        FeeCalculator {
            base_fee: config.min_base_fee,
            congestion: CongestionTracker::new(CongestionConfig::default()),
            config,
        }
    }

    /// Update base fee after block
    pub fn update_after_block(&mut self, block: BlockGasUsage) {
        self.congestion.record_block(block.clone());

        let utilization = block.gas_used as f64 / block.gas_limit as f64;
        let delta = utilization - self.config.target_utilization;

        // Adjust fee based on delta from target
        let adjustment = 1.0 + (delta * self.config.adjustment_rate);
        let new_base_fee = (self.base_fee as f64 * adjustment) as u128;

        self.base_fee = new_base_fee
            .max(self.config.min_base_fee)
            .min(self.config.max_base_fee);
    }

    /// Calculate fee for a transaction
    pub fn calculate_fee(&self, gas_limit: u64, priority_fee: u128) -> FeeEstimate {
        let base_cost = self.base_fee * gas_limit as u128;
        let priority_cost = priority_fee * gas_limit as u128;
        let total = base_cost + priority_cost;

        FeeEstimate {
            base_fee: self.base_fee,
            priority_fee,
            gas_limit,
            total_cost: total,
            max_cost: (self.base_fee * 2 + priority_fee) * gas_limit as u128,
            estimated_wait_blocks: self.estimate_wait_blocks(priority_fee),
        }
    }

    fn estimate_wait_blocks(&self, priority_fee: u128) -> u32 {
        let load = self.congestion.current_load();
        if load < 0.5 {
            1 // Included in next block
        } else if load < 0.75 {
            if priority_fee > self.base_fee / 10 {
                1
            } else {
                2
            }
        } else {
            if priority_fee > self.base_fee / 5 {
                1
            } else if priority_fee > self.base_fee / 10 {
                3
            } else {
                5
            }
        }
    }

    /// Get current base fee
    pub fn base_fee(&self) -> u128 {
        self.base_fee
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub base_fee: u128,
    pub priority_fee: u128,
    pub gas_limit: u64,
    pub total_cost: u128,
    pub max_cost: u128,
    pub estimated_wait_blocks: u32,
}

// ============================================================================
// Staking Rewards (Counter-Balance to Burns)
// ============================================================================

/// Staking reward calculator
pub struct StakingRewardCalculator {
    /// Token configuration
    token_config: AETHTokenConfig,
    /// Total staked amount
    total_staked: u128,
    /// Circulating supply
    circulating_supply: u128,
}

impl StakingRewardCalculator {
    pub fn new(token_config: AETHTokenConfig, circulating_supply: u128) -> Self {
        StakingRewardCalculator {
            token_config,
            total_staked: 0,
            circulating_supply,
        }
    }

    /// Calculate APY for staking
    pub fn calculate_apy(&self, staking_ratio: f64) -> f64 {
        // Higher rewards when less is staked
        let target_ratio = 0.67; // Target 67% of supply staked
        let base_apy = self.token_config.target_inflation_rate;

        if staking_ratio < target_ratio {
            // Below target: increase rewards
            base_apy * (target_ratio / staking_ratio).min(2.0)
        } else {
            // Above target: decrease rewards
            base_apy * (target_ratio / staking_ratio).max(0.5)
        }
    }

    /// Calculate net inflation/deflation
    pub fn calculate_net_inflation(&self, burn_rate: f64, staking_ratio: f64) -> NetInflation {
        let apy = self.calculate_apy(staking_ratio);

        // Staking rewards add to supply
        let staking_inflation = apy * staking_ratio;

        // Burns remove from supply
        let burn_deflation = burn_rate;

        let net = staking_inflation - burn_deflation;

        NetInflation {
            staking_inflation,
            burn_deflation,
            net_inflation: net,
            is_deflationary: net < 0.0,
            annual_supply_change_percent: net * 100.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetInflation {
    pub staking_inflation: f64,
    pub burn_deflation: f64,
    pub net_inflation: f64,
    pub is_deflationary: bool,
    pub annual_supply_change_percent: f64,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_burn_rate_calculation() {
        let engine = QuadraticBurnEngine::new(AETHTokenConfig::default());

        // Test quadratic scaling
        let rate_10 = engine.calculate_burn_rate(0.10);
        let rate_50 = engine.calculate_burn_rate(0.50);
        let rate_90 = engine.calculate_burn_rate(0.90);

        // Quadratic should grow faster
        assert!(rate_50 > rate_10 * 2.0);
        assert!(rate_90 > rate_50 * 2.0);

        // Should stay within bounds
        assert!(rate_10 >= engine.token_config.min_burn_rate);
        assert!(rate_90 <= engine.token_config.max_burn_rate);
    }

    #[test]
    fn test_congestion_tracking() {
        let mut tracker = CongestionTracker::new(CongestionConfig::default());

        // Add some blocks
        for i in 0..20 {
            tracker.record_block(BlockGasUsage {
                block_number: i,
                gas_used: 15_000_000 + (i as u64 * 500_000), // Increasing load
                gas_limit: 30_000_000,
                timestamp: 1000 + i,
                transaction_count: 100,
                compute_job_count: 10,
            });
        }

        let metrics = tracker.metrics();
        assert!(metrics.current_load > 0.5);
        assert_eq!(metrics.trend, LoadTrend::Increasing);
    }

    #[test]
    fn test_burn_processing() {
        let mut engine = QuadraticBurnEngine::new(AETHTokenConfig::default());

        let block = BlockGasUsage {
            block_number: 1,
            gas_used: 27_000_000, // 90% load
            gas_limit: 30_000_000,
            timestamp: 1000,
            transaction_count: 100,
            compute_job_count: 20,
        };

        let result = engine.process_block(block, 1_000_000_000_000);

        assert!(result.fees_burned > 0);
        assert!(result.fees_to_validators > 0);
        assert!(result.burn_rate > 0.30); // High load = high burn
    }

    #[test]
    fn test_burn_processing_uses_fixed_point_integer_math_for_fractional_rate() {
        let mut engine = QuadraticBurnEngine::new(AETHTokenConfig::default());

        // Preload congestion history to avoid relying on ad hoc floating-path assertions.
        let block = BlockGasUsage {
            block_number: 42,
            gas_used: 21_000_000, // ~70% load
            gas_limit: 30_000_000,
            timestamp: 4242,
            transaction_count: 100,
            compute_job_count: 10,
        };

        let expected_rate = engine.calculate_burn_rate(block.gas_used as f64 / block.gas_limit as f64);
        let expected_rate_fixed = engine.burn_rate_to_fixed(expected_rate);
        let fees = 123_456_789u128;
        let expected_burn = fees.saturating_mul(expected_rate_fixed) / BURN_RATE_SCALE;

        let result = engine.process_block(block, fees);

        assert_eq!(result.fees_burned, expected_burn);
        assert_eq!(result.fees_to_validators, fees - expected_burn);
    }

    #[test]
    fn test_burn_rate_to_fixed_rejects_non_finite_values() {
        let engine = QuadraticBurnEngine::new(AETHTokenConfig::default());

        assert_eq!(engine.burn_rate_to_fixed(f64::NAN), 0);
        assert_eq!(engine.burn_rate_to_fixed(f64::INFINITY), 0);
        assert_eq!(engine.burn_rate_to_fixed(f64::NEG_INFINITY), 0);
    }

    #[test]
    fn test_fee_calculator() {
        let mut calculator = FeeCalculator::new(FeeConfig::default());

        // Low usage should keep fees low
        calculator.update_after_block(BlockGasUsage {
            block_number: 1,
            gas_used: 10_000_000, // ~33% utilization
            gas_limit: 30_000_000,
            timestamp: 1000,
            transaction_count: 50,
            compute_job_count: 5,
        });

        let low_fee = calculator.base_fee();

        // High usage should increase fees
        calculator.update_after_block(BlockGasUsage {
            block_number: 2,
            gas_used: 28_000_000, // ~93% utilization
            gas_limit: 30_000_000,
            timestamp: 1001,
            transaction_count: 200,
            compute_job_count: 50,
        });

        let high_fee = calculator.base_fee();
        assert!(high_fee > low_fee);
    }

    #[test]
    fn test_net_inflation() {
        let calculator = StakingRewardCalculator::new(
            AETHTokenConfig::default(),
            1_000_000_000 * 10u128.pow(18),
        );

        // High burn rate should result in deflation
        let result = calculator.calculate_net_inflation(0.10, 0.50);
        assert!(result.is_deflationary);

        // Low burn rate might result in inflation
        let result = calculator.calculate_net_inflation(0.01, 0.50);
        assert!(!result.is_deflationary);
    }
}
