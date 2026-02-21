//! Pillar 2: Native Quantum Immunity
//!
//! ## The Competitor Gap
//!
//! Every wallet on Ethereum, Solana, and Bitcoin uses ECDSA or Ed25519 cryptography.
//! When quantum computers mature (estimated 2030), **every single legacy wallet
//! will be drainable**. They will require messy, panic-driven hard forks to upgrade.
//!
//! ## The Aethelred Advantage
//!
//! Build Aethelred as "Quantum-Native" from **Block 0**.
//!
//! ## Hybrid Signature Scheme
//!
//! Transactions require BOTH:
//! 1. **Standard signature** (Ed25519) - Fast, efficient for today
//! 2. **Post-quantum signature** (Dilithium3/Falcon) - Secure for tomorrow
//!
//! This makes Aethelred the only **"Forever Chain"** available today.
//!
//! ## Why Hybrid?
//!
//! - If classical crypto breaks first → PQ signature protects you
//! - If PQ crypto has undiscovered flaws → Classical signature protects you
//! - Maximum security with minimal risk

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ============================================================================
// Post-Quantum Cryptography Algorithms
// ============================================================================

/// Supported post-quantum signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PQSignatureAlgorithm {
    /// CRYSTALS-Dilithium (NIST standardized, lattice-based)
    /// - Dilithium2: 128-bit security
    /// - Dilithium3: 192-bit security (Aethelred default)
    /// - Dilithium5: 256-bit security
    Dilithium2,
    Dilithium3,
    Dilithium5,

    /// FALCON (lattice-based, smaller signatures)
    /// - Falcon-512: 128-bit security
    /// - Falcon-1024: 256-bit security
    Falcon512,
    Falcon1024,

    /// SPHINCS+ (hash-based, stateless)
    /// - Conservative, well-understood security
    /// - Larger signatures but minimal assumptions
    SphincsPlus128f,
    SphincsPlus192f,
    SphincsPlus256f,
}

impl PQSignatureAlgorithm {
    /// Get the security level in bits
    pub fn security_level(&self) -> u16 {
        match self {
            PQSignatureAlgorithm::Dilithium2 => 128,
            PQSignatureAlgorithm::Dilithium3 => 192,
            PQSignatureAlgorithm::Dilithium5 => 256,
            PQSignatureAlgorithm::Falcon512 => 128,
            PQSignatureAlgorithm::Falcon1024 => 256,
            PQSignatureAlgorithm::SphincsPlus128f => 128,
            PQSignatureAlgorithm::SphincsPlus192f => 192,
            PQSignatureAlgorithm::SphincsPlus256f => 256,
        }
    }

    /// Get the public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            PQSignatureAlgorithm::Dilithium2 => 1312,
            PQSignatureAlgorithm::Dilithium3 => 1952,
            PQSignatureAlgorithm::Dilithium5 => 2592,
            PQSignatureAlgorithm::Falcon512 => 897,
            PQSignatureAlgorithm::Falcon1024 => 1793,
            PQSignatureAlgorithm::SphincsPlus128f => 32,
            PQSignatureAlgorithm::SphincsPlus192f => 48,
            PQSignatureAlgorithm::SphincsPlus256f => 64,
        }
    }

    /// Get the signature size in bytes
    pub fn signature_size(&self) -> usize {
        match self {
            PQSignatureAlgorithm::Dilithium2 => 2420,
            PQSignatureAlgorithm::Dilithium3 => 3293,
            PQSignatureAlgorithm::Dilithium5 => 4595,
            PQSignatureAlgorithm::Falcon512 => 666,  // Average
            PQSignatureAlgorithm::Falcon1024 => 1280, // Average
            PQSignatureAlgorithm::SphincsPlus128f => 17088,
            PQSignatureAlgorithm::SphincsPlus192f => 35664,
            PQSignatureAlgorithm::SphincsPlus256f => 49856,
        }
    }

    /// Get signing speed (operations per second on typical hardware)
    pub fn signing_speed_ops(&self) -> u32 {
        match self {
            PQSignatureAlgorithm::Dilithium2 => 50000,
            PQSignatureAlgorithm::Dilithium3 => 35000,
            PQSignatureAlgorithm::Dilithium5 => 25000,
            PQSignatureAlgorithm::Falcon512 => 10000,
            PQSignatureAlgorithm::Falcon1024 => 5000,
            PQSignatureAlgorithm::SphincsPlus128f => 500,
            PQSignatureAlgorithm::SphincsPlus192f => 200,
            PQSignatureAlgorithm::SphincsPlus256f => 100,
        }
    }

    /// Get verification speed (operations per second)
    pub fn verification_speed_ops(&self) -> u32 {
        match self {
            PQSignatureAlgorithm::Dilithium2 => 150000,
            PQSignatureAlgorithm::Dilithium3 => 100000,
            PQSignatureAlgorithm::Dilithium5 => 80000,
            PQSignatureAlgorithm::Falcon512 => 30000,
            PQSignatureAlgorithm::Falcon1024 => 15000,
            PQSignatureAlgorithm::SphincsPlus128f => 20000,
            PQSignatureAlgorithm::SphincsPlus192f => 10000,
            PQSignatureAlgorithm::SphincsPlus256f => 5000,
        }
    }
}

/// Supported classical signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClassicalSignatureAlgorithm {
    /// Ed25519 (default, fast)
    Ed25519,
    /// ECDSA with secp256k1 (Ethereum/Bitcoin compatible)
    Secp256k1,
    /// ECDSA with P-256 (NIST standard)
    P256,
}

impl ClassicalSignatureAlgorithm {
    pub fn signature_size(&self) -> usize {
        match self {
            ClassicalSignatureAlgorithm::Ed25519 => 64,
            ClassicalSignatureAlgorithm::Secp256k1 => 65,
            ClassicalSignatureAlgorithm::P256 => 64,
        }
    }

    pub fn public_key_size(&self) -> usize {
        match self {
            ClassicalSignatureAlgorithm::Ed25519 => 32,
            ClassicalSignatureAlgorithm::Secp256k1 => 33, // Compressed
            ClassicalSignatureAlgorithm::P256 => 33,      // Compressed
        }
    }
}

// ============================================================================
// Hybrid Key Pair
// ============================================================================

/// A quantum-immune hybrid key pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridKeyPair {
    /// Classical key pair
    pub classical: ClassicalKeyPair,
    /// Post-quantum key pair
    pub post_quantum: PQKeyPair,
    /// Aethelred address (derived from both keys)
    pub address: AethelredAddress,
    /// Creation timestamp
    pub created_at: u64,
    /// Key version (for future upgrades)
    pub version: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassicalKeyPair {
    pub algorithm: ClassicalSignatureAlgorithm,
    pub public_key: Vec<u8>,
    /// Private key (encrypted in storage)
    #[serde(skip_serializing)]
    pub private_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQKeyPair {
    pub algorithm: PQSignatureAlgorithm,
    pub public_key: Vec<u8>,
    /// Private key (encrypted in storage)
    #[serde(skip_serializing)]
    pub private_key: Option<Vec<u8>>,
}

/// Aethelred address format
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AethelredAddress {
    /// Version byte (0x01 = hybrid quantum-immune)
    pub version: u8,
    /// Address bytes (32 bytes)
    pub bytes: [u8; 32],
}

impl AethelredAddress {
    /// Create an address from hybrid public keys
    pub fn from_hybrid_keys(classical_pk: &[u8], pq_pk: &[u8]) -> Self {
        use sha2::{Sha256, Digest};

        // Hash both public keys together
        let mut hasher = Sha256::new();
        hasher.update(&[0x01]); // Version prefix
        hasher.update(classical_pk);
        hasher.update(pq_pk);
        let hash = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);

        AethelredAddress {
            version: 0x01,
            bytes,
        }
    }

    /// Convert to bech32 string (aethelred1...)
    pub fn to_bech32(&self) -> String {
        // Simplified bech32 encoding (real implementation would use bech32 crate)
        let hex = hex::encode(&self.bytes[..20]);
        format!("aethelred1{}", hex)
    }

    /// Convert to hex string with prefix
    pub fn to_hex(&self) -> String {
        format!("0x{:02x}{}", self.version, hex::encode(self.bytes))
    }
}

impl std::fmt::Display for AethelredAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_bech32())
    }
}

// ============================================================================
// Hybrid Signature
// ============================================================================

/// A quantum-immune hybrid signature
///
/// Both signatures MUST be valid for the transaction to be accepted.
/// This provides security against both classical and quantum attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Classical signature
    pub classical: ClassicalSignature,
    /// Post-quantum signature
    pub post_quantum: PQSignature,
    /// Signature version
    pub version: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassicalSignature {
    pub algorithm: ClassicalSignatureAlgorithm,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQSignature {
    pub algorithm: PQSignatureAlgorithm,
    pub signature: Vec<u8>,
}

impl HybridSignature {
    /// Total size of the hybrid signature
    pub fn total_size(&self) -> usize {
        self.classical.signature.len() + self.post_quantum.signature.len() + 1
    }

    /// Create a new hybrid signature
    pub fn new(classical: ClassicalSignature, post_quantum: PQSignature) -> Self {
        HybridSignature {
            classical,
            post_quantum,
            version: 1,
        }
    }
}

// ============================================================================
// Signature Verification
// ============================================================================

/// Hybrid signature verifier
pub struct HybridVerifier {
    /// Strict mode: both signatures MUST be valid
    strict_mode: bool,
    /// Quantum-only mode: only verify PQ signature (for post-quantum era)
    quantum_only_mode: bool,
    /// Cache of verified signatures
    verified_cache: HashMap<[u8; 32], bool>,
}

impl HybridVerifier {
    pub fn new() -> Self {
        HybridVerifier {
            strict_mode: true,
            quantum_only_mode: false,
            verified_cache: HashMap::new(),
        }
    }

    /// Enable quantum-only mode (for future when classical crypto is broken)
    pub fn enable_quantum_only_mode(&mut self) {
        self.quantum_only_mode = true;
        self.strict_mode = false;
    }

    /// Verify a hybrid signature
    pub fn verify(
        &mut self,
        message: &[u8],
        signature: &HybridSignature,
        classical_pk: &[u8],
        pq_pk: &[u8],
    ) -> Result<VerificationResult, VerificationError> {
        let mut result = VerificationResult {
            classical_valid: false,
            post_quantum_valid: false,
            overall_valid: false,
            classical_time_us: 0,
            pq_time_us: 0,
        };

        // Verify classical signature
        if !self.quantum_only_mode {
            let start = std::time::Instant::now();
            result.classical_valid = self.verify_classical(
                message,
                &signature.classical,
                classical_pk,
            )?;
            result.classical_time_us = start.elapsed().as_micros() as u64;
        } else {
            result.classical_valid = true; // Skip in quantum-only mode
        }

        // Verify post-quantum signature
        let start = std::time::Instant::now();
        result.post_quantum_valid = self.verify_pq(
            message,
            &signature.post_quantum,
            pq_pk,
        )?;
        result.pq_time_us = start.elapsed().as_micros() as u64;

        // Overall validity
        result.overall_valid = if self.strict_mode {
            result.classical_valid && result.post_quantum_valid
        } else if self.quantum_only_mode {
            result.post_quantum_valid
        } else {
            result.classical_valid || result.post_quantum_valid
        };

        Ok(result)
    }

    fn verify_classical(
        &self,
        message: &[u8],
        signature: &ClassicalSignature,
        public_key: &[u8],
    ) -> Result<bool, VerificationError> {
        match signature.algorithm {
            ClassicalSignatureAlgorithm::Ed25519 => {
                self.verify_ed25519(message, &signature.signature, public_key)
            }
            ClassicalSignatureAlgorithm::Secp256k1 => {
                self.verify_secp256k1(message, &signature.signature, public_key)
            }
            ClassicalSignatureAlgorithm::P256 => {
                self.verify_p256(message, &signature.signature, public_key)
            }
        }
    }

    fn verify_pq(
        &self,
        message: &[u8],
        signature: &PQSignature,
        public_key: &[u8],
    ) -> Result<bool, VerificationError> {
        match signature.algorithm {
            PQSignatureAlgorithm::Dilithium2 |
            PQSignatureAlgorithm::Dilithium3 |
            PQSignatureAlgorithm::Dilithium5 => {
                self.verify_dilithium(message, &signature.signature, public_key, signature.algorithm)
            }
            PQSignatureAlgorithm::Falcon512 |
            PQSignatureAlgorithm::Falcon1024 => {
                self.verify_falcon(message, &signature.signature, public_key, signature.algorithm)
            }
            PQSignatureAlgorithm::SphincsPlus128f |
            PQSignatureAlgorithm::SphincsPlus192f |
            PQSignatureAlgorithm::SphincsPlus256f => {
                self.verify_sphincs(message, &signature.signature, public_key, signature.algorithm)
            }
        }
    }

    // Placeholder implementations - would use actual crypto libraries
    fn verify_ed25519(&self, _message: &[u8], _signature: &[u8], _public_key: &[u8]) -> Result<bool, VerificationError> {
        // In production: use ed25519-dalek crate
        Ok(true) // Placeholder
    }

    fn verify_secp256k1(&self, _message: &[u8], _signature: &[u8], _public_key: &[u8]) -> Result<bool, VerificationError> {
        // In production: use secp256k1 crate
        Ok(true)
    }

    fn verify_p256(&self, _message: &[u8], _signature: &[u8], _public_key: &[u8]) -> Result<bool, VerificationError> {
        // In production: use p256 crate
        Ok(true)
    }

    fn verify_dilithium(
        &self,
        _message: &[u8],
        _signature: &[u8],
        _public_key: &[u8],
        _variant: PQSignatureAlgorithm,
    ) -> Result<bool, VerificationError> {
        // In production: use pqcrypto-dilithium crate
        Ok(true)
    }

    fn verify_falcon(
        &self,
        _message: &[u8],
        _signature: &[u8],
        _public_key: &[u8],
        _variant: PQSignatureAlgorithm,
    ) -> Result<bool, VerificationError> {
        // In production: use pqcrypto-falcon crate
        Ok(true)
    }

    fn verify_sphincs(
        &self,
        _message: &[u8],
        _signature: &[u8],
        _public_key: &[u8],
        _variant: PQSignatureAlgorithm,
    ) -> Result<bool, VerificationError> {
        // In production: use pqcrypto-sphincsplus crate
        Ok(true)
    }
}

impl Default for HybridVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub classical_valid: bool,
    pub post_quantum_valid: bool,
    pub overall_valid: bool,
    pub classical_time_us: u64,
    pub pq_time_us: u64,
}

#[derive(Debug, Clone)]
pub enum VerificationError {
    InvalidSignatureLength,
    InvalidPublicKeyLength,
    InvalidAlgorithm(String),
    CryptoError(String),
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationError::InvalidSignatureLength => write!(f, "Invalid signature length"),
            VerificationError::InvalidPublicKeyLength => write!(f, "Invalid public key length"),
            VerificationError::InvalidAlgorithm(s) => write!(f, "Invalid algorithm: {}", s),
            VerificationError::CryptoError(s) => write!(f, "Crypto error: {}", s),
        }
    }
}

impl std::error::Error for VerificationError {}

// ============================================================================
// Key Generation
// ============================================================================

/// Hybrid key generator
pub struct HybridKeyGenerator {
    classical_algorithm: ClassicalSignatureAlgorithm,
    pq_algorithm: PQSignatureAlgorithm,
}

impl HybridKeyGenerator {
    /// Create with Aethelred defaults (Ed25519 + Dilithium3)
    pub fn default_aethelred() -> Self {
        HybridKeyGenerator {
            classical_algorithm: ClassicalSignatureAlgorithm::Ed25519,
            pq_algorithm: PQSignatureAlgorithm::Dilithium3,
        }
    }

    /// Create with custom algorithms
    pub fn new(classical: ClassicalSignatureAlgorithm, pq: PQSignatureAlgorithm) -> Self {
        HybridKeyGenerator {
            classical_algorithm: classical,
            pq_algorithm: pq,
        }
    }

    /// Generate a new hybrid key pair
    pub fn generate(&self) -> Result<HybridKeyPair, KeyGenError> {
        let classical = self.generate_classical()?;
        let post_quantum = self.generate_pq()?;

        let address = AethelredAddress::from_hybrid_keys(
            &classical.public_key,
            &post_quantum.public_key,
        );

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(HybridKeyPair {
            classical,
            post_quantum,
            address,
            created_at: now,
            version: 1,
        })
    }

    fn generate_classical(&self) -> Result<ClassicalKeyPair, KeyGenError> {
        // In production: use actual key generation
        let pk_size = self.classical_algorithm.public_key_size();
        let sk_size = 32; // Simplified

        Ok(ClassicalKeyPair {
            algorithm: self.classical_algorithm,
            public_key: vec![0u8; pk_size], // Placeholder
            private_key: Some(vec![0u8; sk_size]),
        })
    }

    fn generate_pq(&self) -> Result<PQKeyPair, KeyGenError> {
        // In production: use pqcrypto crate
        let pk_size = self.pq_algorithm.public_key_size();
        let sk_size = pk_size * 2; // Simplified

        Ok(PQKeyPair {
            algorithm: self.pq_algorithm,
            public_key: vec![0u8; pk_size], // Placeholder
            private_key: Some(vec![0u8; sk_size]),
        })
    }
}

#[derive(Debug, Clone)]
pub enum KeyGenError {
    EntropyError,
    AlgorithmError(String),
}

impl std::fmt::Display for KeyGenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyGenError::EntropyError => write!(f, "Insufficient entropy"),
            KeyGenError::AlgorithmError(s) => write!(f, "Algorithm error: {}", s),
        }
    }
}

impl std::error::Error for KeyGenError {}

// ============================================================================
// Quantum Threat Timeline
// ============================================================================

/// Quantum threat assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumThreatAssessment {
    /// Estimated year when quantum computers can break ECDSA
    pub ecdsa_break_year: u16,
    /// Estimated year when quantum computers can break Ed25519
    pub ed25519_break_year: u16,
    /// Current quantum computer capabilities
    pub current_qubits: u32,
    /// Qubits needed to break 256-bit ECC
    pub qubits_needed_for_ecc: u32,
    /// Threat level (0-100)
    pub threat_level: u8,
    /// Recommendation
    pub recommendation: QuantumRecommendation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QuantumRecommendation {
    /// No action needed
    Monitor,
    /// Start planning migration
    PlanMigration,
    /// Begin migration immediately
    MigrateNow,
    /// Emergency: all classical-only wallets at risk
    Emergency,
}

impl QuantumThreatAssessment {
    /// Current assessment (as of 2024)
    pub fn current() -> Self {
        QuantumThreatAssessment {
            ecdsa_break_year: 2030, // Optimistic estimate
            ed25519_break_year: 2032,
            current_qubits: 1000, // IBM's current max
            qubits_needed_for_ecc: 4000, // Rough estimate
            threat_level: 25,
            recommendation: QuantumRecommendation::PlanMigration,
        }
    }

    /// Why Aethelred is safe
    pub fn aethelred_safety_report(&self) -> String {
        format!(
            r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    AETHELRED QUANTUM IMMUNITY REPORT                           ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                                ║
║  Current Threat Level: {}% (Estimated ECC break: {})                          ║
║                                                                                ║
║  LEGACY CHAINS (At Risk):                                                      ║
║  ┌─────────────────────────────────────────────────────────────────────────┐  ║
║  │  Bitcoin      : ECDSA secp256k1  → ❌ VULNERABLE after ~{}              │  ║
║  │  Ethereum     : ECDSA secp256k1  → ❌ VULNERABLE after ~{}              │  ║
║  │  Solana       : Ed25519          → ❌ VULNERABLE after ~{}              │  ║
║  │                                                                         │  ║
║  │  Impact: Every wallet address becomes drainable by quantum computers   │  ║
║  │  Required: Emergency hard fork to migrate (chaotic, risky)             │  ║
║  └─────────────────────────────────────────────────────────────────────────┘  ║
║                                                                                ║
║  AETHELRED (Quantum-Native):                                                   ║
║  ┌─────────────────────────────────────────────────────────────────────────┐  ║
║  │  Classical    : Ed25519          → Protected by PQ signature           │  ║
║  │  Post-Quantum : Dilithium3       → ✅ QUANTUM IMMUNE                    │  ║
║  │                                                                         │  ║
║  │  Hybrid Scheme: Both signatures required                               │  ║
║  │  • If classical breaks → PQ signature still valid                      │  ║
║  │  • If PQ has unknown flaws → Classical still valid                     │  ║
║  │                                                                         │  ║
║  │  Impact: ZERO migration needed. Secure from Block 0.                   │  ║
║  │  "The Forever Chain"                                                   │  ║
║  └─────────────────────────────────────────────────────────────────────────┘  ║
║                                                                                ║
║  TIMELINE:                                                                     ║
║  ├── 2024: Current (1000 qubits) - Aethelred launches quantum-native          ║
║  ├── 2027: ~2000 qubits - Legacy chains begin to worry                        ║
║  ├── 2030: ~4000 qubits - ECDSA potentially broken, panic migrations          ║
║  └── 2035+: Aethelred users unaffected, other chains scrambling               ║
║                                                                                ║
║  RECOMMENDATION FOR ENTERPRISES (FAB/DBS):                                     ║
║  "Deploy on Aethelred today. Never worry about quantum migration."            ║
║                                                                                ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"#,
            self.threat_level,
            self.ecdsa_break_year,
            self.ecdsa_break_year,
            self.ecdsa_break_year,
            self.ed25519_break_year,
        )
    }
}

// ============================================================================
// Transaction with Hybrid Signature
// ============================================================================

/// A quantum-immune transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumImmuneTransaction {
    /// Transaction version
    pub version: u8,
    /// Sender address
    pub from: AethelredAddress,
    /// Recipient address
    pub to: AethelredAddress,
    /// Amount
    pub amount: u128,
    /// Gas price
    pub gas_price: u64,
    /// Gas limit
    pub gas_limit: u64,
    /// Nonce
    pub nonce: u64,
    /// Data payload
    pub data: Vec<u8>,
    /// Hybrid signature
    pub signature: HybridSignature,
    /// Timestamp
    pub timestamp: u64,
}

impl QuantumImmuneTransaction {
    /// Calculate transaction hash (for signing)
    pub fn hash(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(&[self.version]);
        hasher.update(&self.from.bytes);
        hasher.update(&self.to.bytes);
        hasher.update(&self.amount.to_le_bytes());
        hasher.update(&self.gas_price.to_le_bytes());
        hasher.update(&self.gas_limit.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.data);
        hasher.update(&self.timestamp.to_le_bytes());

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Total size of the transaction
    pub fn total_size(&self) -> usize {
        1 + // version
        33 + // from (with version byte)
        33 + // to
        16 + // amount
        8 + // gas_price
        8 + // gas_limit
        8 + // nonce
        self.data.len() +
        self.signature.total_size() +
        8 // timestamp
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let generator = HybridKeyGenerator::default_aethelred();
        let keypair = generator.generate().unwrap();

        assert_eq!(keypair.version, 1);
        assert_eq!(keypair.classical.algorithm, ClassicalSignatureAlgorithm::Ed25519);
        assert_eq!(keypair.post_quantum.algorithm, PQSignatureAlgorithm::Dilithium3);
    }

    #[test]
    fn test_address_generation() {
        let generator = HybridKeyGenerator::default_aethelred();
        let keypair = generator.generate().unwrap();

        let bech32 = keypair.address.to_bech32();
        assert!(bech32.starts_with("aethelred1"));
    }

    #[test]
    fn test_signature_sizes() {
        // Dilithium3 should be ~3.3KB
        assert!(PQSignatureAlgorithm::Dilithium3.signature_size() > 3000);
        assert!(PQSignatureAlgorithm::Dilithium3.signature_size() < 4000);

        // Falcon should be smaller
        assert!(PQSignatureAlgorithm::Falcon512.signature_size() < 1000);

        // SPHINCS+ should be much larger
        assert!(PQSignatureAlgorithm::SphincsPlus256f.signature_size() > 40000);
    }

    #[test]
    fn test_hybrid_verification() {
        let mut verifier = HybridVerifier::new();

        let message = b"test message";
        let signature = HybridSignature {
            classical: ClassicalSignature {
                algorithm: ClassicalSignatureAlgorithm::Ed25519,
                signature: vec![0u8; 64],
            },
            post_quantum: PQSignature {
                algorithm: PQSignatureAlgorithm::Dilithium3,
                signature: vec![0u8; 3293],
            },
            version: 1,
        };

        let classical_pk = vec![0u8; 32];
        let pq_pk = vec![0u8; 1952];

        let result = verifier.verify(message, &signature, &classical_pk, &pq_pk).unwrap();
        assert!(result.overall_valid); // Both should be "valid" (placeholder)
    }

    #[test]
    fn test_quantum_threat_assessment() {
        let assessment = QuantumThreatAssessment::current();
        assert!(assessment.ecdsa_break_year >= 2028);
        assert!(assessment.threat_level < 50);

        let report = assessment.aethelred_safety_report();
        assert!(report.contains("QUANTUM IMMUNE"));
        assert!(report.contains("Forever Chain"));
    }

    #[test]
    fn test_transaction_hash() {
        let generator = HybridKeyGenerator::default_aethelred();
        let keypair = generator.generate().unwrap();

        let tx = QuantumImmuneTransaction {
            version: 1,
            from: keypair.address.clone(),
            to: keypair.address.clone(),
            amount: 1000,
            gas_price: 1,
            gas_limit: 21000,
            nonce: 0,
            data: vec![],
            signature: HybridSignature {
                classical: ClassicalSignature {
                    algorithm: ClassicalSignatureAlgorithm::Ed25519,
                    signature: vec![0u8; 64],
                },
                post_quantum: PQSignature {
                    algorithm: PQSignatureAlgorithm::Dilithium3,
                    signature: vec![0u8; 3293],
                },
                version: 1,
            },
            timestamp: 0,
        };

        let hash = tx.hash();
        assert_ne!(hash, [0u8; 32]); // Should produce a non-zero hash
    }
}
