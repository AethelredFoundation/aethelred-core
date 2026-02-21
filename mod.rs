//! The 8 Strategic Pillars of Aethelred
//!
//! These pillars establish Aethelred as the **successor** to current Layer 1s
//! (Solana, Ethereum, Aptos) by solving the "Trilemma" they all ignored:
//! **The Utility Gap**.
//!
//! Current chains sell "Blockspace" (commodity).
//! Aethelred sells "Trusted Compute" (premium asset).
//!
//! ## The Octagon of Value
//!
//! | Pillar | Feature (Moat) | Value Proposition |
//! |--------|----------------|-------------------|
//! | 1. Consensus | Proof of Useful Work | Turn Energy into Intelligence (ESG) |
//! | 2. Security | Native Quantum Immunity | Future-Proof Safety (Post-2030) |
//! | 3. Privacy | Sovereign TEE Enclaves | GDPR/HIPAA Compliance |
//! | 4. Speed | AI Pre-Compiles | 1000x Faster Inference Verification |
//! | 5. Economy | Congestion-Squared Burn | Deflationary Supply Shock |
//! | 6. Governance | Bi-Cameral Senate | Enterprise Stability + Decentralized Growth |
//! | 7. Bridge | Zero-Copy Data Links | Process Petabytes without Moving Them |
//! | 8. Storage | Vector-Vault | The Native Database for Global AI |

/// Pillar 1: Proof of Useful Work - Turn Energy into Intelligence
pub mod useful_work;

/// Pillar 2: Native Quantum Immunity - Future-Proof Security
pub mod quantum_immunity;

/// Pillar 3: Sovereign TEE Enclaves - The Secret Mempool
pub mod secret_mempool;

/// Pillar 4: Tensor Pre-Compiles - 1000x Faster AI Verification
pub mod tensor_precompiles;

/// Pillar 5: Congestion-Squared Deflation - Economic Value Driver
pub mod quadratic_burn;

/// Pillar 6: Bi-Cameral Governance - Enterprise Stability
pub mod bicameral_governance;

/// Pillar 7: Zero-Copy AI Bridge - Data-in-Place Processing
pub mod zero_copy_bridge;

/// Pillar 8: Vector-Vault Storage - Neural Compression
pub mod vector_vault;

// Re-exports
pub use useful_work::*;
pub use quantum_immunity::*;
pub use secret_mempool::*;
pub use tensor_precompiles::*;
pub use quadratic_burn::*;
pub use bicameral_governance::*;
pub use zero_copy_bridge::*;
pub use vector_vault::*;
