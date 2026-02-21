//! Pillar 7: Zero-Copy AI Bridge - Data-in-Place Processing
//!
//! ## The Competitor Gap
//!
//! - **Polkadot/Cosmos**: Move tokens well, but terrible at moving heavy AI data
//! - If M42 (UAE) wants to use a model on Aethelred but data is on a private
//!   hospital chain, current bridges require copying/moving the data
//!   (slow, expensive, non-compliant)
//!
//! ## The Aethelred Advantage
//!
//! Build a "Data-in-Place" Interoperability Protocol.
//!
//! ## The Pointer-Swizzling Bridge
//!
//! Instead of bridging the DATA, Aethelred bridges the **compute instruction**
//! to the external data source.
//!
//! ### How It Works
//!
//! 1. Aethelred TEE node connects directly to Hospital's S3 bucket
//! 2. Secure, attested tunnel established
//! 3. Data processed in RAM (never stored)
//! 4. Only the RESULT written to the chain
//! 5. Data never "moves" to blockchain storage
//!
//! ## Tremendous Value
//!
//! Unlocks **Exabyte-scale AI**. You can train models on petabytes of data
//! without ever paying gas fees to store that data on-chain.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};

// ============================================================================
// Data Source Types
// ============================================================================

/// Supported external data sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataSource {
    /// AWS S3 bucket
    AWSS3 {
        bucket: String,
        region: String,
        prefix: Option<String>,
        credentials: CredentialReference,
    },
    /// Azure Blob Storage
    AzureBlob {
        account: String,
        container: String,
        credentials: CredentialReference,
    },
    /// Google Cloud Storage
    GCS {
        bucket: String,
        prefix: Option<String>,
        credentials: CredentialReference,
    },
    /// IPFS/Filecoin
    IPFS {
        cid: String,
        gateway: Option<String>,
    },
    /// Private database (SQL)
    Database {
        db_type: DatabaseType,
        connection: EncryptedConnection,
    },
    /// REST API endpoint
    RestAPI {
        base_url: String,
        auth: AuthMethod,
    },
    /// Another blockchain
    Blockchain {
        chain: ChainType,
        contract: String,
        method: String,
    },
    /// Local encrypted storage
    LocalEncrypted {
        path: String,
        encryption_key_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DatabaseType {
    PostgreSQL,
    MySQL,
    MongoDB,
    Snowflake,
    BigQuery,
    Redshift,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedConnection {
    /// Encrypted connection string
    pub encrypted_conn_string: Vec<u8>,
    /// Key ID for decryption (in TEE)
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    /// OAuth 2.0
    OAuth2 {
        token_url: String,
        client_id: String,
        scope: String,
    },
    /// API Key
    APIKey {
        key_header: String,
        key_id: String,
    },
    /// JWT
    JWT {
        secret_id: String,
        claims: HashMap<String, String>,
    },
    /// Mutual TLS
    MutualTLS {
        cert_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainType {
    Ethereum,
    Polygon,
    Solana,
    Cosmos,
    Avalanche,
    BNBChain,
    Custom(String),
}

/// Reference to credentials stored in secure enclave
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialReference {
    /// Credential ID
    pub id: String,
    /// Credential type
    pub cred_type: CredentialType,
    /// Expiry
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialType {
    AWSRole,
    AWSAccessKey,
    AzureServicePrincipal,
    GCPServiceAccount,
    CustomSecret,
}

// ============================================================================
// Data Pointer (Swizzled Reference)
// ============================================================================

/// A pointer to external data (never the data itself)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPointer {
    /// Unique pointer ID
    pub id: [u8; 32],
    /// Data source
    pub source: DataSource,
    /// Path within the source
    pub path: String,
    /// Schema description
    pub schema: DataSchema,
    /// Size hint (bytes)
    pub size_hint: Option<u64>,
    /// Last verified timestamp
    pub last_verified: u64,
    /// Checksum for integrity
    pub checksum: Option<[u8; 32]>,
    /// Access policy
    pub access_policy: AccessPolicy,
    /// Owner
    pub owner: [u8; 32],
    /// Compliance metadata
    pub compliance: ComplianceMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSchema {
    /// Schema type
    pub schema_type: SchemaType,
    /// Schema definition (JSON Schema, Protobuf, etc.)
    pub definition: String,
    /// Column/field descriptions
    pub fields: Vec<FieldInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SchemaType {
    /// Tabular data (CSV, Parquet)
    Tabular,
    /// Image data
    Image { format: String, dimensions: (u32, u32) },
    /// Text data
    Text { encoding: String },
    /// JSON document
    JSON,
    /// Binary blob
    Binary,
    /// Time series
    TimeSeries { interval: Duration },
    /// Graph data
    Graph,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldInfo {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
    pub description: Option<String>,
    pub pii: bool, // Is this PII data?
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    /// Who can read
    pub readers: Vec<[u8; 32]>,
    /// Who can compute on the data
    pub compute_allowed: Vec<[u8; 32]>,
    /// Approved model hashes
    pub approved_models: Vec<[u8; 32]>,
    /// Time-based access
    pub valid_from: Option<u64>,
    pub valid_until: Option<u64>,
    /// Rate limiting
    pub max_accesses_per_day: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceMetadata {
    /// Data classification
    pub classification: DataClassification,
    /// Retention policy
    pub retention_policy: Option<RetentionPolicy>,
    /// Geographic restrictions
    pub geo_restrictions: Option<GeoRestrictions>,
    /// Audit requirements
    pub audit_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
    TopSecret,
    PHI,  // Protected Health Information
    PII,  // Personally Identifiable Information
    PCI,  // Payment Card Industry
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub min_retention_days: u32,
    pub max_retention_days: u32,
    pub deletion_policy: DeletionPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeletionPolicy {
    HardDelete,
    SoftDelete,
    ArchiveFirst,
    RequiresApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoRestrictions {
    pub allowed_regions: Vec<String>,
    pub blocked_regions: Vec<String>,
    pub processing_must_stay_in_region: bool,
}

// ============================================================================
// Compute Instruction (What Gets Bridged)
// ============================================================================

/// A compute instruction that travels to the data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeInstruction {
    /// Instruction ID
    pub id: [u8; 32],
    /// Target data pointer
    pub data_pointer: DataPointer,
    /// Model to execute
    pub model: ModelReference,
    /// Pre-processing steps
    pub preprocessing: Vec<PreprocessStep>,
    /// Post-processing steps
    pub postprocessing: Vec<PostprocessStep>,
    /// Output specification
    pub output_spec: OutputSpec,
    /// Execution constraints
    pub constraints: ExecutionConstraints,
    /// Requester
    pub requester: [u8; 32],
    /// Signature
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelReference {
    /// Model hash
    pub hash: [u8; 32],
    /// Model location (if not already cached)
    pub source: Option<DataSource>,
    /// Model type
    pub model_type: ModelType,
    /// Input shape
    pub input_shape: Vec<usize>,
    /// Output shape
    pub output_shape: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModelType {
    ONNX,
    TensorFlowSavedModel,
    PyTorchScript,
    XGBoost,
    LightGBM,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PreprocessStep {
    /// Normalize values
    Normalize { mean: Vec<f64>, std: Vec<f64> },
    /// Resize image
    Resize { width: u32, height: u32 },
    /// Tokenize text
    Tokenize { vocab_id: String, max_length: usize },
    /// Feature selection
    SelectFeatures { columns: Vec<String> },
    /// Filtering
    Filter { condition: String },
    /// Sampling
    Sample { fraction: f64, seed: u64 },
    /// Custom transformation
    Custom { code_hash: [u8; 32] },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PostprocessStep {
    /// Softmax
    Softmax,
    /// Argmax
    Argmax,
    /// Threshold
    Threshold { value: f64 },
    /// Top-K
    TopK { k: usize },
    /// Decode tokens
    DecodeTokens { vocab_id: String },
    /// Custom
    Custom { code_hash: [u8; 32] },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputSpec {
    /// What to return
    pub return_type: ReturnType,
    /// Encryption
    pub encryption: OutputEncryption,
    /// Destination
    pub destination: OutputDestination,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReturnType {
    /// Full output tensor
    FullOutput,
    /// Just the top prediction
    TopPrediction,
    /// Summary statistics
    Summary,
    /// Commitment only (hash of output)
    CommitmentOnly,
    /// Aggregated (for privacy)
    Aggregated { aggregation: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputEncryption {
    /// Plaintext (for public results)
    None,
    /// Encrypted for requester
    ForRequester,
    /// Encrypted for specific recipients
    ForRecipients(Vec<[u8; 32]>),
    /// Homomorphically encrypted (can compute on encrypted)
    Homomorphic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputDestination {
    /// Return to requester
    ToRequester,
    /// Write to chain
    ToChain,
    /// Write to external storage
    ToStorage(DataSource),
    /// Multiple destinations
    Multiple(Vec<OutputDestination>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConstraints {
    /// Maximum execution time
    pub max_time: Duration,
    /// Maximum memory
    pub max_memory_mb: u64,
    /// Required TEE
    pub required_tee: Option<TEERequirement>,
    /// Deadline
    pub deadline: Option<u64>,
    /// Maximum cost (in AETH)
    pub max_cost: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEERequirement {
    pub platforms: Vec<String>,
    pub min_security_version: u16,
}

// ============================================================================
// Zero-Copy Bridge
// ============================================================================

/// The Zero-Copy AI Bridge
pub struct ZeroCopyBridge {
    /// Registered data pointers
    pointers: HashMap<[u8; 32], DataPointer>,
    /// Active tunnels
    active_tunnels: HashMap<[u8; 32], SecureTunnel>,
    /// Pending instructions
    pending_instructions: HashMap<[u8; 32], ComputeInstruction>,
    /// Execution results
    results: HashMap<[u8; 32], ExecutionResult>,
    /// Configuration
    config: BridgeConfig,
    /// Metrics
    metrics: BridgeMetrics,
}

#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Maximum concurrent tunnels
    pub max_concurrent_tunnels: usize,
    /// Tunnel timeout
    pub tunnel_timeout: Duration,
    /// Maximum data size per instruction
    pub max_data_size_bytes: u64,
    /// Supported data sources
    pub supported_sources: Vec<String>,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        BridgeConfig {
            max_concurrent_tunnels: 100,
            tunnel_timeout: Duration::from_secs(300),
            max_data_size_bytes: 10 * 1024 * 1024 * 1024, // 10 GB
            supported_sources: vec![
                "s3".to_string(),
                "azure".to_string(),
                "gcs".to_string(),
                "ipfs".to_string(),
                "postgres".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecureTunnel {
    /// Tunnel ID
    pub id: [u8; 32],
    /// Source data pointer
    pub data_pointer_id: [u8; 32],
    /// TEE node handling this tunnel
    pub tee_node: [u8; 32],
    /// Tunnel encryption key (encrypted for TEE)
    pub encrypted_key: Vec<u8>,
    /// Status
    pub status: TunnelStatus,
    /// Created at
    pub created_at: SystemTime,
    /// Data transferred (bytes)
    pub bytes_transferred: u64,
    /// Attestation
    pub attestation: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelStatus {
    Establishing,
    Active,
    DataTransfer,
    Processing,
    Closing,
    Closed,
    Failed,
}

#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Instruction ID
    pub instruction_id: [u8; 32],
    /// Success?
    pub success: bool,
    /// Output commitment (hash)
    pub output_commitment: [u8; 32],
    /// Encrypted output (if applicable)
    pub encrypted_output: Option<Vec<u8>>,
    /// Execution time
    pub execution_time: Duration,
    /// Data processed (bytes)
    pub data_processed: u64,
    /// TEE attestation
    pub attestation: Vec<u8>,
    /// Gas used
    pub gas_used: u64,
}

#[derive(Debug, Clone, Default)]
pub struct BridgeMetrics {
    pub total_instructions: u64,
    pub successful_instructions: u64,
    pub failed_instructions: u64,
    pub total_data_processed_bytes: u64,
    pub total_tunnels_created: u64,
    pub average_execution_time: Duration,
}

impl ZeroCopyBridge {
    pub fn new(config: BridgeConfig) -> Self {
        ZeroCopyBridge {
            pointers: HashMap::new(),
            active_tunnels: HashMap::new(),
            pending_instructions: HashMap::new(),
            results: HashMap::new(),
            config,
            metrics: BridgeMetrics::default(),
        }
    }

    /// Register a data pointer
    pub fn register_pointer(&mut self, pointer: DataPointer) -> Result<[u8; 32], BridgeError> {
        // Validate the pointer
        self.validate_pointer(&pointer)?;

        let id = pointer.id;
        self.pointers.insert(id, pointer);
        Ok(id)
    }

    fn validate_pointer(&self, pointer: &DataPointer) -> Result<(), BridgeError> {
        // Check source type is supported
        let source_type = match &pointer.source {
            DataSource::AWSS3 { .. } => "s3",
            DataSource::AzureBlob { .. } => "azure",
            DataSource::GCS { .. } => "gcs",
            DataSource::IPFS { .. } => "ipfs",
            DataSource::Database { db_type, .. } => match db_type {
                DatabaseType::PostgreSQL => "postgres",
                _ => "database",
            },
            DataSource::RestAPI { .. } => "rest",
            DataSource::Blockchain { .. } => "blockchain",
            DataSource::LocalEncrypted { .. } => "local",
        };

        if !self.config.supported_sources.contains(&source_type.to_string()) {
            return Err(BridgeError::UnsupportedSource(source_type.to_string()));
        }

        Ok(())
    }

    /// Submit a compute instruction
    pub fn submit_instruction(
        &mut self,
        instruction: ComputeInstruction,
    ) -> Result<[u8; 32], BridgeError> {
        // Verify the data pointer exists
        if !self.pointers.contains_key(&instruction.data_pointer.id) {
            return Err(BridgeError::PointerNotFound);
        }

        // Verify access policy
        self.verify_access(&instruction)?;

        let id = instruction.id;
        self.pending_instructions.insert(id, instruction);
        self.metrics.total_instructions += 1;

        Ok(id)
    }

    fn verify_access(&self, instruction: &ComputeInstruction) -> Result<(), BridgeError> {
        let policy = &instruction.data_pointer.access_policy;

        // Check requester is authorized
        if !policy.compute_allowed.contains(&instruction.requester) {
            return Err(BridgeError::AccessDenied);
        }

        // Check model is approved
        if !policy.approved_models.is_empty() &&
           !policy.approved_models.contains(&instruction.model.hash) {
            return Err(BridgeError::ModelNotApproved);
        }

        // Check time validity
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(from) = policy.valid_from {
            if now < from {
                return Err(BridgeError::AccessNotYetValid);
            }
        }

        if let Some(until) = policy.valid_until {
            if now > until {
                return Err(BridgeError::AccessExpired);
            }
        }

        Ok(())
    }

    /// Create a secure tunnel to the data source
    pub fn create_tunnel(
        &mut self,
        instruction_id: [u8; 32],
        tee_node: [u8; 32],
    ) -> Result<[u8; 32], BridgeError> {
        let instruction = self.pending_instructions.get(&instruction_id)
            .ok_or(BridgeError::InstructionNotFound)?;

        if self.active_tunnels.len() >= self.config.max_concurrent_tunnels {
            return Err(BridgeError::TooManyTunnels);
        }

        let tunnel_id = self.generate_tunnel_id();

        let tunnel = SecureTunnel {
            id: tunnel_id,
            data_pointer_id: instruction.data_pointer.id,
            tee_node,
            encrypted_key: vec![], // Would be generated in TEE
            status: TunnelStatus::Establishing,
            created_at: SystemTime::now(),
            bytes_transferred: 0,
            attestation: None,
        };

        self.active_tunnels.insert(tunnel_id, tunnel);
        self.metrics.total_tunnels_created += 1;

        Ok(tunnel_id)
    }

    fn generate_tunnel_id(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"tunnel");
        hasher.update(&(self.active_tunnels.len() as u64).to_le_bytes());
        hasher.update(&SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_le_bytes());
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        id
    }

    /// Record execution result
    pub fn record_result(&mut self, result: ExecutionResult) {
        if result.success {
            self.metrics.successful_instructions += 1;
        } else {
            self.metrics.failed_instructions += 1;
        }
        self.metrics.total_data_processed_bytes += result.data_processed;

        self.results.insert(result.instruction_id, result);
    }

    /// Get metrics
    pub fn metrics(&self) -> &BridgeMetrics {
        &self.metrics
    }

    /// Generate comparison report
    pub fn comparison_report(&self) -> String {
        r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║              ZERO-COPY AI BRIDGE: DATA-IN-PLACE PROCESSING                     ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                                ║
║  THE PROBLEM WITH TRADITIONAL BRIDGES:                                         ║
║  ┌──────────────────────────────────────────────────────────────────────────┐ ║
║  │                                                                          │ ║
║  │  Polkadot/Cosmos/LayerZero: Move tokens well, but...                    │ ║
║  │                                                                          │ ║
║  │  Scenario: Hospital in UAE wants M42 AI to analyze 10TB of CT scans    │ ║
║  │                                                                          │ ║
║  │  Traditional Approach:                                                   │ ║
║  │  1. Copy 10TB from Hospital S3 → Bridge                                 │ ║
║  │  2. Bridge encrypts and transmits → Aethelred                          │ ║
║  │  3. Aethelred stores on-chain (10TB @ $X/GB = $$$$$)                   │ ║
║  │  4. Run AI model                                                        │ ║
║  │  5. Store results                                                       │ ║
║  │                                                                          │ ║
║  │  Problems:                                                               │ ║
║  │  ❌ Cost: Billions in storage fees                                      │ ║
║  │  ❌ Speed: Days to transfer 10TB                                        │ ║
║  │  ❌ Compliance: Data left original jurisdiction                         │ ║
║  │  ❌ Privacy: Data copied multiple times                                 │ ║
║  │                                                                          │ ║
║  └──────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                ║
║  THE AETHELRED SOLUTION: POINTER-SWIZZLING BRIDGE                              ║
║  ┌──────────────────────────────────────────────────────────────────────────┐ ║
║  │                                                                          │ ║
║  │  Instead of bridging DATA, bridge the COMPUTE INSTRUCTION               │ ║
║  │                                                                          │ ║
║  │  ┌─────────────┐                              ┌─────────────────────┐   │ ║
║  │  │  Hospital   │                              │   Aethelred TEE     │   │ ║
║  │  │  S3 Bucket  │◄─────Secure Tunnel──────────►│   Validator Node    │   │ ║
║  │  │  (10TB)     │                              │   (Intel SGX)       │   │ ║
║  │  └─────────────┘                              └─────────────────────┘   │ ║
║  │        │                                               │                 │ ║
║  │        │                                               │                 │ ║
║  │        │  Data STREAMS                                 │                 │ ║
║  │        │  directly to                                  │                 │ ║
║  │        │  TEE RAM                                      │                 │ ║
║  │        │                                               ▼                 │ ║
║  │        │                                   ┌─────────────────────┐       │ ║
║  │        └──────────────────────────────────►│   Process in RAM    │       │ ║
║  │                                            │   (Never stored)    │       │ ║
║  │                                            └──────────┬──────────┘       │ ║
║  │                                                       │                  │ ║
║  │                                                       ▼                  │ ║
║  │                                            ┌─────────────────────┐       │ ║
║  │                                            │   Result (1KB)      │       │ ║
║  │                                            │   → On-Chain        │       │ ║
║  │                                            └─────────────────────┘       │ ║
║  │                                                                          │ ║
║  │  What Gets Bridged:                                                      │ ║
║  │  ✅ Compute instruction (few KB)                                        │ ║
║  │  ✅ Data pointer (few bytes)                                            │ ║
║  │  ✅ Result commitment (32 bytes)                                        │ ║
║  │                                                                          │ ║
║  │  What NEVER Moves:                                                       │ ║
║  │  ❌ The actual 10TB of CT scans                                         │ ║
║  │                                                                          │ ║
║  └──────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                ║
║  COMPARISON:                                                                   ║
║  ┌─────────────────┬─────────────────┬─────────────────────────────────────┐  ║
║  │  Metric         │  Traditional    │  Zero-Copy (Aethelred)              │  ║
║  │  ────────────────────────────────────────────────────────────────────── │  ║
║  │  Transfer       │  10 TB          │  10 KB (instruction only)           │  ║
║  │  Storage Cost   │  $100,000+      │  $0.01 (result only)                │  ║
║  │  Time           │  Hours/Days     │  Seconds                            │  ║
║  │  Compliance     │  Data moved     │  Data stays in place                │  ║
║  │  Privacy        │  Multiple copies│  Zero copies (RAM only)             │  ║
║  └─────────────────┴─────────────────┴─────────────────────────────────────┘  ║
║                                                                                ║
║  USE CASES:                                                                    ║
║  • Medical imaging analysis (HIPAA compliant - data stays at hospital)       ║
║  • Financial modeling on bank databases (data never leaves bank)             ║
║  • Federated learning across institutions                                     ║
║  • Cross-border AI without data transfer                                      ║
║                                                                                ║
║  "Process petabytes of data. Pay for kilobytes of results."                  ║
║                                                                                ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"#.to_string()
    }
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Clone)]
pub enum BridgeError {
    UnsupportedSource(String),
    PointerNotFound,
    InstructionNotFound,
    AccessDenied,
    ModelNotApproved,
    AccessNotYetValid,
    AccessExpired,
    TooManyTunnels,
    TunnelFailed(String),
    DataTooLarge,
    ExecutionFailed(String),
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::UnsupportedSource(s) => write!(f, "Unsupported data source: {}", s),
            BridgeError::PointerNotFound => write!(f, "Data pointer not found"),
            BridgeError::InstructionNotFound => write!(f, "Instruction not found"),
            BridgeError::AccessDenied => write!(f, "Access denied"),
            BridgeError::ModelNotApproved => write!(f, "Model not approved for this data"),
            BridgeError::AccessNotYetValid => write!(f, "Access not yet valid"),
            BridgeError::AccessExpired => write!(f, "Access expired"),
            BridgeError::TooManyTunnels => write!(f, "Too many concurrent tunnels"),
            BridgeError::TunnelFailed(msg) => write!(f, "Tunnel failed: {}", msg),
            BridgeError::DataTooLarge => write!(f, "Data exceeds maximum size"),
            BridgeError::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
        }
    }
}

impl std::error::Error for BridgeError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_creation() {
        let bridge = ZeroCopyBridge::new(BridgeConfig::default());
        assert_eq!(bridge.metrics().total_instructions, 0);
    }

    #[test]
    fn test_pointer_registration() {
        let mut bridge = ZeroCopyBridge::new(BridgeConfig::default());

        let pointer = DataPointer {
            id: [1u8; 32],
            source: DataSource::AWSS3 {
                bucket: "hospital-data".to_string(),
                region: "me-central-1".to_string(),
                prefix: Some("ct-scans/".to_string()),
                credentials: CredentialReference {
                    id: "aws-role-1".to_string(),
                    cred_type: CredentialType::AWSRole,
                    expires_at: None,
                },
            },
            path: "patient-12345/".to_string(),
            schema: DataSchema {
                schema_type: SchemaType::Image {
                    format: "DICOM".to_string(),
                    dimensions: (512, 512),
                },
                definition: "{}".to_string(),
                fields: vec![],
            },
            size_hint: Some(10_000_000_000), // 10 GB
            last_verified: 0,
            checksum: None,
            access_policy: AccessPolicy {
                readers: vec![[2u8; 32]],
                compute_allowed: vec![[2u8; 32]],
                approved_models: vec![],
                valid_from: None,
                valid_until: None,
                max_accesses_per_day: None,
            },
            owner: [1u8; 32],
            compliance: ComplianceMetadata {
                classification: DataClassification::PHI,
                retention_policy: None,
                geo_restrictions: Some(GeoRestrictions {
                    allowed_regions: vec!["UAE".to_string()],
                    blocked_regions: vec![],
                    processing_must_stay_in_region: true,
                }),
                audit_required: true,
            },
        };

        let result = bridge.register_pointer(pointer);
        assert!(result.is_ok());
    }

    #[test]
    fn test_access_policy() {
        let mut bridge = ZeroCopyBridge::new(BridgeConfig::default());

        let pointer = DataPointer {
            id: [1u8; 32],
            source: DataSource::AWSS3 {
                bucket: "test".to_string(),
                region: "us-east-1".to_string(),
                prefix: None,
                credentials: CredentialReference {
                    id: "test".to_string(),
                    cred_type: CredentialType::AWSAccessKey,
                    expires_at: None,
                },
            },
            path: "/".to_string(),
            schema: DataSchema {
                schema_type: SchemaType::Tabular,
                definition: "{}".to_string(),
                fields: vec![],
            },
            size_hint: None,
            last_verified: 0,
            checksum: None,
            access_policy: AccessPolicy {
                readers: vec![[2u8; 32]],
                compute_allowed: vec![[2u8; 32]],
                approved_models: vec![[3u8; 32]],
                valid_from: None,
                valid_until: None,
                max_accesses_per_day: None,
            },
            owner: [1u8; 32],
            compliance: ComplianceMetadata {
                classification: DataClassification::Internal,
                retention_policy: None,
                geo_restrictions: None,
                audit_required: false,
            },
        };

        bridge.register_pointer(pointer.clone()).unwrap();

        // Unauthorized requester
        let instruction = ComputeInstruction {
            id: [10u8; 32],
            data_pointer: pointer.clone(),
            model: ModelReference {
                hash: [3u8; 32],
                source: None,
                model_type: ModelType::ONNX,
                input_shape: vec![1, 224, 224, 3],
                output_shape: vec![1, 1000],
            },
            preprocessing: vec![],
            postprocessing: vec![],
            output_spec: OutputSpec {
                return_type: ReturnType::TopPrediction,
                encryption: OutputEncryption::ForRequester,
                destination: OutputDestination::ToRequester,
            },
            constraints: ExecutionConstraints {
                max_time: Duration::from_secs(60),
                max_memory_mb: 8192,
                required_tee: None,
                deadline: None,
                max_cost: None,
            },
            requester: [99u8; 32], // Unauthorized
            signature: vec![],
        };

        let result = bridge.submit_instruction(instruction);
        assert!(matches!(result, Err(BridgeError::AccessDenied)));
    }
}
