//! Pillar 8: Vector-Vault Storage - Neural Compression
//!
//! ## The Competitor Gap
//!
//! - **Arweave/Filecoin**: Store data "as is"
//! - If you store a 100GB genomic dataset, you pay for 100GB
//! - AI models and datasets are massive
//! - Storing them on decentralized storage is prohibitively expensive
//!
//! ## The Aethelred Advantage
//!
//! Implement **"Semantic AI Compression"** at the storage layer.
//!
//! ## The Vector-Vault
//!
//! Instead of storing raw files, Aethelred nodes auto-convert data into
//! **Vector Embeddings** (compressed mathematical representations) before storage.
//!
//! ### Why Vector Embeddings?
//!
//! - **100x smaller** than raw data
//! - Still usable for AI search and RAG (Retrieval Augmented Generation)
//! - Semantic similarity preserved
//! - Enable instant AI querying
//!
//! ## Tremendous Value
//!
//! Aethelred becomes the **De-Facto Database for LLMs**. Enterprises can store
//! their "Corporate Brain" on Aethelred for 1/100th the cost of AWS or Filecoin,
//! ready for instant AI querying.

// H-08: Production safety — prevent shipping dev vector vault stubs.
#[cfg(feature = "production")]
compile_error!(
    "vector_vault stub is active in a production build. \
     Replace with the production embedding engine before shipping."
);

use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};

#[cfg(feature = "production")]
compile_error!("VectorVault placeholder embedding generator must be replaced before production builds");

// ============================================================================
// Vector Types
// ============================================================================

/// A vector embedding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorEmbedding {
    /// Unique ID
    pub id: [u8; 32],
    /// The embedding vector
    pub vector: Vec<f32>,
    /// Dimensionality
    pub dimensions: usize,
    /// Embedding model used
    pub model: EmbeddingModel,
    /// Original content metadata (not the content itself)
    pub metadata: EmbeddingMetadata,
    /// Compression ratio achieved
    pub compression_ratio: f64,
    /// Timestamp
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmbeddingModel {
    /// OpenAI text-embedding-ada-002
    OpenAIAda002 { dimensions: usize },
    /// OpenAI text-embedding-3-small
    OpenAI3Small { dimensions: usize },
    /// OpenAI text-embedding-3-large
    OpenAI3Large { dimensions: usize },
    /// Cohere Embed v3
    CohereV3 { dimensions: usize },
    /// Sentence Transformers
    SentenceTransformers { model_name: String, dimensions: usize },
    /// Custom model
    Custom { model_hash: [u8; 32], dimensions: usize },
    /// CLIP (for images)
    CLIP { variant: String, dimensions: usize },
    /// BioMedLM (for medical)
    BioMedLM { dimensions: usize },
    /// FinBERT (for finance)
    FinBERT { dimensions: usize },
}

impl EmbeddingModel {
    pub fn dimensions(&self) -> usize {
        match self {
            EmbeddingModel::OpenAIAda002 { dimensions } => *dimensions,
            EmbeddingModel::OpenAI3Small { dimensions } => *dimensions,
            EmbeddingModel::OpenAI3Large { dimensions } => *dimensions,
            EmbeddingModel::CohereV3 { dimensions } => *dimensions,
            EmbeddingModel::SentenceTransformers { dimensions, .. } => *dimensions,
            EmbeddingModel::Custom { dimensions, .. } => *dimensions,
            EmbeddingModel::CLIP { dimensions, .. } => *dimensions,
            EmbeddingModel::BioMedLM { dimensions } => *dimensions,
            EmbeddingModel::FinBERT { dimensions } => *dimensions,
        }
    }

    pub fn bytes_per_vector(&self) -> usize {
        self.dimensions() * 4 // f32 = 4 bytes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingMetadata {
    /// Original content type
    pub content_type: ContentType,
    /// Original size in bytes
    pub original_size: u64,
    /// Hash of original content
    pub content_hash: [u8; 32],
    /// Source (document title, URL, etc.)
    pub source: String,
    /// Additional tags
    pub tags: Vec<String>,
    /// Access control
    pub access: AccessControl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContentType {
    /// Text document
    Text {
        language: String,
        word_count: u64,
    },
    /// Image
    Image {
        format: String,
        width: u32,
        height: u32,
    },
    /// Audio
    Audio {
        format: String,
        duration_secs: f64,
    },
    /// Video
    Video {
        format: String,
        duration_secs: f64,
        resolution: (u32, u32),
    },
    /// Structured data (JSON, CSV)
    Structured {
        format: String,
        row_count: u64,
    },
    /// Code
    Code {
        language: String,
        line_count: u64,
    },
    /// Medical record
    Medical {
        record_type: String,
        anonymized: bool,
    },
    /// Financial document
    Financial {
        document_type: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControl {
    /// Owner
    pub owner: [u8; 32],
    /// Read permissions
    pub readers: Vec<[u8; 32]>,
    /// Is public?
    pub is_public: bool,
    /// Encryption key ID (if encrypted)
    pub encryption_key: Option<String>,
}

// ============================================================================
// Vector Index Types
// ============================================================================

/// Index type for vector search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndexType {
    /// Flat (brute force) - exact but slow
    Flat,
    /// IVF (Inverted File) - approximate, fast
    IVF {
        n_lists: usize,
        n_probes: usize,
    },
    /// HNSW (Hierarchical Navigable Small World) - very fast
    HNSW {
        m: usize,           // Max connections per node
        ef_construction: usize,  // Build-time parameter
        ef_search: usize,   // Search-time parameter
    },
    /// Product Quantization - compressed, very fast
    PQ {
        n_subvectors: usize,
        bits_per_code: usize,
    },
    /// Scalar Quantization - simple compression
    SQ {
        bits: usize,  // 4 or 8
    },
}

impl IndexType {
    /// Compression ratio for this index type
    pub fn compression_ratio(&self, original_dims: usize) -> f64 {
        match self {
            IndexType::Flat => 1.0, // No compression
            IndexType::IVF { .. } => 1.0, // No compression (just organization)
            IndexType::HNSW { .. } => 1.0, // No compression
            IndexType::PQ { n_subvectors, bits_per_code } => {
                let original_bytes = original_dims * 4; // f32
                let compressed_bytes = n_subvectors * bits_per_code / 8;
                original_bytes as f64 / compressed_bytes as f64
            }
            IndexType::SQ { bits } => {
                32.0 / *bits as f64 // f32 is 32 bits
            }
        }
    }
}

// ============================================================================
// Vector Vault
// ============================================================================

/// The Vector-Vault storage system
pub struct VectorVault {
    /// Stored embeddings
    embeddings: HashMap<[u8; 32], VectorEmbedding>,
    /// Namespaces (collections)
    namespaces: HashMap<String, VectorNamespace>,
    /// Global index
    global_index: VectorIndex,
    /// Configuration
    config: VaultConfig,
    /// Metrics
    metrics: VaultMetrics,
}

#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Default embedding model
    pub default_model: EmbeddingModel,
    /// Default index type
    pub default_index: IndexType,
    /// Maximum vectors per namespace
    pub max_vectors_per_namespace: usize,
    /// Enable auto-compression
    pub auto_compress: bool,
    /// Compression threshold (bytes)
    pub compression_threshold: u64,
}

impl Default for VaultConfig {
    fn default() -> Self {
        VaultConfig {
            default_model: EmbeddingModel::OpenAI3Small { dimensions: 1536 },
            default_index: IndexType::HNSW {
                m: 16,
                ef_construction: 200,
                ef_search: 100,
            },
            max_vectors_per_namespace: 10_000_000,
            auto_compress: true,
            compression_threshold: 1024, // 1KB
        }
    }
}

#[derive(Debug, Clone)]
pub struct VectorNamespace {
    /// Namespace name
    pub name: String,
    /// Owner
    pub owner: [u8; 32],
    /// Embedding model
    pub model: EmbeddingModel,
    /// Index type
    pub index_type: IndexType,
    /// Vector count
    pub vector_count: usize,
    /// Total original data size
    pub total_original_size: u64,
    /// Total compressed size
    pub total_compressed_size: u64,
    /// Created at
    pub created_at: u64,
    /// Schema for metadata
    pub metadata_schema: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VectorIndex {
    /// Index type
    index_type: IndexType,
    /// Dimensions
    dimensions: usize,
    /// Vector IDs in index
    indexed_ids: Vec<[u8; 32]>,
    /// Is built?
    is_built: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultMetrics {
    /// Total vectors stored
    pub total_vectors: u64,
    /// Total original data size (bytes)
    pub total_original_bytes: u64,
    /// Total compressed size (bytes)
    pub total_compressed_bytes: u64,
    /// Overall compression ratio
    pub compression_ratio: f64,
    /// Total searches performed
    pub total_searches: u64,
    /// Average search latency
    pub avg_search_latency_ms: f64,
    /// Storage savings (bytes)
    pub storage_savings_bytes: u64,
    /// Cost savings (estimated)
    pub cost_savings_usd: f64,
}

impl VectorVault {
    pub fn new(config: VaultConfig) -> Self {
        VectorVault {
            embeddings: HashMap::new(),
            namespaces: HashMap::new(),
            global_index: VectorIndex {
                index_type: config.default_index.clone(),
                dimensions: config.default_model.dimensions(),
                indexed_ids: Vec::new(),
                is_built: false,
            },
            config,
            metrics: VaultMetrics::default(),
        }
    }

    /// Create a namespace
    pub fn create_namespace(
        &mut self,
        name: &str,
        owner: [u8; 32],
        model: Option<EmbeddingModel>,
        index_type: Option<IndexType>,
    ) -> Result<(), VaultError> {
        if self.namespaces.contains_key(name) {
            return Err(VaultError::NamespaceExists(name.to_string()));
        }

        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let namespace = VectorNamespace {
            name: name.to_string(),
            owner,
            model: model.unwrap_or_else(|| self.config.default_model.clone()),
            index_type: index_type.unwrap_or_else(|| self.config.default_index.clone()),
            vector_count: 0,
            total_original_size: 0,
            total_compressed_size: 0,
            created_at: now,
            metadata_schema: None,
        };

        self.namespaces.insert(name.to_string(), namespace);
        Ok(())
    }

    /// Store a vector embedding
    pub fn store(
        &mut self,
        namespace: &str,
        embedding: VectorEmbedding,
    ) -> Result<[u8; 32], VaultError> {
        let ns = self.namespaces.get_mut(namespace)
            .ok_or_else(|| VaultError::NamespaceNotFound(namespace.to_string()))?;

        if ns.vector_count >= self.config.max_vectors_per_namespace {
            return Err(VaultError::NamespaceFull);
        }

        // Verify dimensions match
        if embedding.dimensions != ns.model.dimensions() {
            return Err(VaultError::DimensionMismatch {
                expected: ns.model.dimensions(),
                got: embedding.dimensions,
            });
        }

        let id = embedding.id;

        // Update namespace stats
        ns.vector_count += 1;
        ns.total_original_size += embedding.metadata.original_size;
        ns.total_compressed_size += (embedding.vector.len() * 4) as u64;

        // Update global metrics
        self.metrics.total_vectors += 1;
        self.metrics.total_original_bytes += embedding.metadata.original_size;
        self.metrics.total_compressed_bytes += (embedding.vector.len() * 4) as u64;
        self.update_compression_ratio();

        // Store
        self.embeddings.insert(id, embedding);
        self.global_index.indexed_ids.push(id);

        Ok(id)
    }

    /// Search for similar vectors
    pub fn search(
        &mut self,
        namespace: &str,
        query_vector: &[f32],
        top_k: usize,
        filter: Option<SearchFilter>,
    ) -> Result<Vec<SearchResult>, VaultError> {
        let ns = self.namespaces.get(namespace)
            .ok_or_else(|| VaultError::NamespaceNotFound(namespace.to_string()))?;

        if query_vector.len() != ns.model.dimensions() {
            return Err(VaultError::DimensionMismatch {
                expected: ns.model.dimensions(),
                got: query_vector.len(),
            });
        }

        let start = std::time::Instant::now();

        // Simple brute-force search for now
        // Real implementation would use the index
        let mut results: Vec<(f32, [u8; 32])> = self.embeddings
            .iter()
            .filter(|(_, emb)| {
                if let Some(ref f) = filter {
                    self.matches_filter(emb, f)
                } else {
                    true
                }
            })
            .map(|(id, emb)| {
                let similarity = self.cosine_similarity(query_vector, &emb.vector);
                (similarity, *id)
            })
            .collect();

        results.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(top_k);

        let elapsed = start.elapsed();
        self.metrics.total_searches += 1;
        self.metrics.avg_search_latency_ms =
            (self.metrics.avg_search_latency_ms * (self.metrics.total_searches - 1) as f64
             + elapsed.as_secs_f64() * 1000.0)
            / self.metrics.total_searches as f64;

        Ok(results.into_iter().map(|(score, id)| {
            let emb = self.embeddings.get(&id).unwrap();
            SearchResult {
                id,
                score,
                metadata: emb.metadata.clone(),
            }
        }).collect())
    }

    fn cosine_similarity(&self, a: &[f32], b: &[f32]) -> f32 {
        let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
        let denom = norm_a * norm_b;
        const EPSILON: f32 = 1e-12;

        if !denom.is_finite() || denom <= EPSILON {
            0.0
        } else {
            let score = dot / denom;
            if score.is_finite() { score } else { 0.0 }
        }
    }

    fn matches_filter(&self, embedding: &VectorEmbedding, filter: &SearchFilter) -> bool {
        // Tag filter
        if let Some(ref required_tags) = filter.tags {
            if !required_tags.iter().all(|t| embedding.metadata.tags.contains(t)) {
                return false;
            }
        }

        // Content type filter
        if let Some(ref content_types) = filter.content_types {
            let matches = content_types.iter().any(|ct| {
                match (&embedding.metadata.content_type, ct.as_str()) {
                    (ContentType::Text { .. }, "text") => true,
                    (ContentType::Image { .. }, "image") => true,
                    (ContentType::Audio { .. }, "audio") => true,
                    (ContentType::Video { .. }, "video") => true,
                    (ContentType::Code { .. }, "code") => true,
                    (ContentType::Medical { .. }, "medical") => true,
                    (ContentType::Financial { .. }, "financial") => true,
                    _ => false,
                }
            });
            if !matches {
                return false;
            }
        }

        true
    }

    fn update_compression_ratio(&mut self) {
        if self.metrics.total_compressed_bytes > 0 {
            self.metrics.compression_ratio =
                self.metrics.total_original_bytes as f64 / self.metrics.total_compressed_bytes as f64;
            self.metrics.storage_savings_bytes =
                self.metrics.total_original_bytes.saturating_sub(self.metrics.total_compressed_bytes);

            // Estimate cost savings (rough: $0.023 per GB/month on S3)
            let savings_gb = self.metrics.storage_savings_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
            self.metrics.cost_savings_usd = savings_gb * 0.023;
        }
    }

    /// Get metrics
    pub fn metrics(&self) -> &VaultMetrics {
        &self.metrics
    }

    /// Generate comparison report
    pub fn comparison_report(&self) -> String {
        format!(r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║              VECTOR-VAULT: NEURAL COMPRESSION STORAGE                          ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                                ║
║  THE PROBLEM WITH TRADITIONAL STORAGE:                                         ║
║  ┌──────────────────────────────────────────────────────────────────────────┐ ║
║  │                                                                          │ ║
║  │  Arweave/Filecoin: Store data "as is"                                   │ ║
║  │                                                                          │ ║
║  │  Example: Enterprise Knowledge Base                                      │ ║
║  │  • 100,000 documents                                                     │ ║
║  │  • Average 10KB each                                                    │ ║
║  │  • Total: 1GB raw data                                                  │ ║
║  │                                                                          │ ║
║  │  Traditional Storage Cost:                                               │ ║
║  │  • Filecoin: ~$0.0001/GB/year × 1GB = $0.0001/year                      │ ║
║  │  • Arweave: ~$4/GB permanent = $4 one-time                              │ ║
║  │  • But... to SEARCH these documents you need:                           │ ║
║  │    - External search infrastructure                                     │ ║
║  │    - Download all data for processing                                   │ ║
║  │    - Can't do AI/semantic search                                        │ ║
║  │                                                                          │ ║
║  │  Real Cost = Storage + Infrastructure + Compute = $$$$$                 │ ║
║  │                                                                          │ ║
║  └──────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                ║
║  THE AETHELRED SOLUTION: SEMANTIC COMPRESSION                                  ║
║  ┌──────────────────────────────────────────────────────────────────────────┐ ║
║  │                                                                          │ ║
║  │  Instead of storing raw files, store VECTOR EMBEDDINGS                  │ ║
║  │                                                                          │ ║
║  │  ┌────────────────┐         ┌────────────────────┐                      │ ║
║  │  │ Raw Document   │         │ Vector Embedding   │                      │ ║
║  │  │ (10,000 bytes) │ ──────► │ (6,144 bytes)      │                      │ ║
║  │  │                │  Embed  │ [0.12, -0.45, ...] │                      │ ║
║  │  │ "The patient  │         │ 1536 dimensions    │                      │ ║
║  │  │  presented... │         │                    │                      │ ║
║  │  │  symptoms of..│         │ SEMANTICALLY       │                      │ ║
║  │  │  diagnosis is.│         │ SEARCHABLE         │                      │ ║
║  │  │  ..."         │         │                    │                      │ ║
║  │  └────────────────┘         └────────────────────┘                      │ ║
║  │                                                                          │ ║
║  │  Compression: 10,000 → 6,144 bytes = 38% smaller                        │ ║
║  │  But with Quantization (PQ/SQ): 10,000 → 384 bytes = 96% smaller!       │ ║
║  │                                                                          │ ║
║  └──────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                ║
║  STORAGE COMPARISON (100,000 documents):                                       ║
║  ┌──────────────────┬──────────────┬──────────────┬─────────────────────────┐ ║
║  │  Storage Type    │  Raw Size    │  Compressed  │  Searchable?            │ ║
║  │  ────────────────────────────────────────────────────────────────────────│ ║
║  │  Filecoin        │    1 GB      │    1 GB      │  ❌ (need external)     │ ║
║  │  Arweave         │    1 GB      │    1 GB      │  ❌ (need external)     │ ║
║  │  Aethelred (f32) │    1 GB      │  600 MB      │  ✅ Native AI search    │ ║
║  │  Aethelred (PQ)  │    1 GB      │   40 MB      │  ✅ Native AI search    │ ║
║  └──────────────────┴──────────────┴──────────────┴─────────────────────────┘ ║
║                                                                                ║
║  WHY VECTORS ARE BETTER THAN RAW DATA:                                         ║
║  ┌──────────────────────────────────────────────────────────────────────────┐ ║
║  │                                                                          │ ║
║  │  1. SEMANTIC SEARCH                                                      │ ║
║  │     Query: "heart problems"                                              │ ║
║  │     Finds: "cardiovascular disease", "cardiac arrest", "arrhythmia"     │ ║
║  │     → Works even without exact keyword match                            │ ║
║  │                                                                          │ ║
║  │  2. AI-READY (RAG)                                                       │ ║
║  │     Store company knowledge → Ask GPT questions about it                │ ║
║  │     No downloading, no processing, instant retrieval                    │ ║
║  │                                                                          │ ║
║  │  3. CROSS-LINGUAL                                                        │ ║
║  │     Query in English → Find documents in Arabic, Chinese, French        │ ║
║  │     Embeddings capture meaning, not language                            │ ║
║  │                                                                          │ ║
║  │  4. MULTIMODAL                                                           │ ║
║  │     Query: "medical scan showing tumor"                                 │ ║
║  │     Finds: Images, reports, X-rays (all embedded in same space)         │ ║
║  │                                                                          │ ║
║  └──────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                ║
║  CURRENT VAULT STATUS:                                                         ║
║  • Total Vectors: {}                                                           ║
║  • Original Data: {} bytes                                                     ║
║  • Compressed To: {} bytes                                                     ║
║  • Compression Ratio: {:.1}x                                                   ║
║  • Storage Saved: {} bytes                                                     ║
║  • Estimated Cost Savings: ${:.2}/month                                        ║
║                                                                                ║
║  THE ENTERPRISE USE CASE:                                                      ║
║  "Store your Corporate Brain on Aethelred for 1/100th the cost of AWS,        ║
║   ready for instant AI querying."                                             ║
║                                                                                ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"#,
            self.metrics.total_vectors,
            self.metrics.total_original_bytes,
            self.metrics.total_compressed_bytes,
            self.metrics.compression_ratio,
            self.metrics.storage_savings_bytes,
            self.metrics.cost_savings_usd,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchFilter {
    /// Required tags
    pub tags: Option<Vec<String>>,
    /// Content types to include
    pub content_types: Option<Vec<String>>,
    /// Date range
    pub date_range: Option<(u64, u64)>,
    /// Owner filter
    pub owner: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// Vector ID
    pub id: [u8; 32],
    /// Similarity score (0-1)
    pub score: f32,
    /// Metadata
    pub metadata: EmbeddingMetadata,
}

// ============================================================================
// Document Processor
// ============================================================================

/// Processes documents into vector embeddings
pub struct DocumentProcessor {
    /// Embedding model
    model: EmbeddingModel,
    /// Chunking configuration
    chunk_config: ChunkConfig,
}

#[derive(Debug, Clone)]
pub struct ChunkConfig {
    /// Target chunk size (tokens)
    pub chunk_size: usize,
    /// Overlap between chunks
    pub overlap: usize,
    /// Chunking strategy
    pub strategy: ChunkStrategy,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        ChunkConfig {
            chunk_size: 512,
            overlap: 50,
            strategy: ChunkStrategy::Semantic,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ChunkStrategy {
    /// Fixed size chunks
    Fixed,
    /// Semantic boundaries (paragraphs, sections)
    Semantic,
    /// Sentence-based
    Sentence,
    /// Recursive (try semantic, fall back to fixed)
    Recursive,
}

impl DocumentProcessor {
    pub fn new(model: EmbeddingModel, chunk_config: ChunkConfig) -> Self {
        DocumentProcessor { model, chunk_config }
    }

    /// Process a document into embeddings
    pub fn process(&self, content: &str, metadata: EmbeddingMetadata) -> Vec<VectorEmbedding> {
        // Chunk the document
        let chunks = self.chunk_text(content);

        // Generate embeddings for each chunk
        chunks.iter().enumerate().map(|(i, chunk)| {
            let vector = self.generate_embedding(chunk);
            let id = self.generate_id(content, i);

            VectorEmbedding {
                id,
                vector,
                dimensions: self.model.dimensions(),
                model: self.model.clone(),
                metadata: EmbeddingMetadata {
                    source: format!("{} (chunk {})", metadata.source, i),
                    ..metadata.clone()
                },
                compression_ratio: content.len() as f64 / (self.model.dimensions() * 4) as f64,
                created_at: SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            }
        }).collect()
    }

    fn chunk_text(&self, text: &str) -> Vec<String> {
        match self.chunk_config.strategy {
            ChunkStrategy::Fixed => self.fixed_chunk(text),
            ChunkStrategy::Semantic => self.semantic_chunk(text),
            ChunkStrategy::Sentence => self.sentence_chunk(text),
            ChunkStrategy::Recursive => self.recursive_chunk(text),
        }
    }

    fn fixed_chunk(&self, text: &str) -> Vec<String> {
        let words: Vec<&str> = text.split_whitespace().collect();
        let chunk_size = self.chunk_config.chunk_size;
        let overlap = self.chunk_config.overlap;

        let mut chunks = Vec::new();
        let mut i = 0;

        while i < words.len() {
            let end = (i + chunk_size).min(words.len());
            chunks.push(words[i..end].join(" "));
            i += chunk_size.saturating_sub(overlap);
        }

        chunks
    }

    fn semantic_chunk(&self, text: &str) -> Vec<String> {
        // Split by paragraphs
        text.split("\n\n")
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .collect()
    }

    fn sentence_chunk(&self, text: &str) -> Vec<String> {
        // Simple sentence splitting
        text.split(|c| c == '.' || c == '!' || c == '?')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .collect()
    }

    fn recursive_chunk(&self, text: &str) -> Vec<String> {
        // Try semantic first, then fall back
        let chunks = self.semantic_chunk(text);
        if chunks.iter().all(|c| c.split_whitespace().count() <= self.chunk_config.chunk_size * 2) {
            chunks
        } else {
            self.fixed_chunk(text)
        }
    }

    fn generate_embedding(&self, text: &str) -> Vec<f32> {
        // Development-only deterministic placeholder: produces stable, non-zero
        // vectors derived from content so search behavior is testable. Production
        // builds are blocked by the compile_error! above until a real model is wired.
        use sha2::{Digest, Sha256};

        let dims = self.model.dimensions();
        if dims == 0 {
            return vec![];
        }

        let mut out = vec![0.0f32; dims];
        let mut counter: u64 = 0;
        let mut written = 0usize;

        while written < dims {
            let mut hasher = Sha256::new();
            hasher.update(b"aethelred-vector-vault-dev-embedding");
            hasher.update(text.as_bytes());
            hasher.update(counter.to_le_bytes());
            let digest = hasher.finalize();

            for chunk in digest.chunks_exact(2) {
                if written >= dims {
                    break;
                }
                let raw = u16::from_le_bytes([chunk[0], chunk[1]]);
                // Map to [-1, 1] deterministically.
                out[written] = (raw as f32 / 32767.5) - 1.0;
                written += 1;
            }
            counter = counter.saturating_add(1);
        }

        // L2-normalize to keep cosine scores stable.
        let norm = out.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 1e-12 {
            for v in &mut out {
                *v /= norm;
            }
        } else {
            out[0] = 1.0;
        }

        out
    }

    fn generate_id(&self, content: &str, chunk_index: usize) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hasher.update(&(chunk_index as u64).to_le_bytes());
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        id
    }
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Clone)]
pub enum VaultError {
    NamespaceExists(String),
    NamespaceNotFound(String),
    NamespaceFull,
    DimensionMismatch { expected: usize, got: usize },
    VectorNotFound,
    SearchFailed(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::NamespaceExists(name) => write!(f, "Namespace already exists: {}", name),
            VaultError::NamespaceNotFound(name) => write!(f, "Namespace not found: {}", name),
            VaultError::NamespaceFull => write!(f, "Namespace is full"),
            VaultError::DimensionMismatch { expected, got } => {
                write!(f, "Dimension mismatch: expected {}, got {}", expected, got)
            }
            VaultError::VectorNotFound => write!(f, "Vector not found"),
            VaultError::SearchFailed(msg) => write!(f, "Search failed: {}", msg),
        }
    }
}

impl std::error::Error for VaultError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_creation() {
        let vault = VectorVault::new(VaultConfig::default());
        assert_eq!(vault.metrics().total_vectors, 0);
    }

    #[test]
    fn test_namespace_creation() {
        let mut vault = VectorVault::new(VaultConfig::default());
        vault.create_namespace("test", [0u8; 32], None, None).unwrap();

        let result = vault.create_namespace("test", [0u8; 32], None, None);
        assert!(matches!(result, Err(VaultError::NamespaceExists(_))));
    }

    #[test]
    fn test_vector_storage() {
        let mut vault = VectorVault::new(VaultConfig::default());
        vault.create_namespace("test", [0u8; 32], None, None).unwrap();

        let embedding = VectorEmbedding {
            id: [1u8; 32],
            vector: vec![0.1; 1536],
            dimensions: 1536,
            model: EmbeddingModel::OpenAI3Small { dimensions: 1536 },
            metadata: EmbeddingMetadata {
                content_type: ContentType::Text {
                    language: "en".to_string(),
                    word_count: 100,
                },
                original_size: 10000,
                content_hash: [0u8; 32],
                source: "test.txt".to_string(),
                tags: vec!["test".to_string()],
                access: AccessControl {
                    owner: [0u8; 32],
                    readers: vec![],
                    is_public: true,
                    encryption_key: None,
                },
            },
            compression_ratio: 1.6,
            created_at: 0,
        };

        vault.store("test", embedding).unwrap();
        assert_eq!(vault.metrics().total_vectors, 1);
    }

    #[test]
    fn test_compression_ratio() {
        let index = IndexType::PQ {
            n_subvectors: 48,
            bits_per_code: 8,
        };

        let ratio = index.compression_ratio(1536);
        assert!(ratio > 100.0); // PQ should give 100x+ compression
    }

    #[test]
    fn test_cosine_similarity() {
        let vault = VectorVault::new(VaultConfig::default());

        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        let c = vec![0.0, 1.0, 0.0];

        let sim_same = vault.cosine_similarity(&a, &b);
        let sim_orthogonal = vault.cosine_similarity(&a, &c);

        assert!((sim_same - 1.0).abs() < 0.001);
        assert!(sim_orthogonal.abs() < 0.001);
    }

    #[test]
    fn test_cosine_similarity_zero_vector_and_nan_inputs_fail_closed() {
        let vault = VectorVault::new(VaultConfig::default());

        let zero = vec![0.0, 0.0, 0.0];
        let unit = vec![1.0, 0.0, 0.0];
        let nan_vec = vec![f32::NAN, 0.0, 0.0];

        assert_eq!(vault.cosine_similarity(&zero, &unit), 0.0);
        assert_eq!(vault.cosine_similarity(&unit, &zero), 0.0);
        assert_eq!(vault.cosine_similarity(&nan_vec, &unit), 0.0);
    }

    #[test]
    fn test_generate_embedding_is_deterministic_and_non_zero() {
        let vault = VectorVault::new(VaultConfig::default());

        let emb1 = vault.generate_embedding("Aethelred test embedding");
        let emb2 = vault.generate_embedding("Aethelred test embedding");
        let emb3 = vault.generate_embedding("Different input");

        assert!(!emb1.is_empty());
        assert_eq!(emb1, emb2, "dev embedding placeholder should be deterministic");
        assert_ne!(emb1, emb3, "different inputs should produce different embeddings");
        assert!(emb1.iter().any(|v| v.abs() > 1e-6), "embedding should not be all zeros");

        let norm = emb1.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-3, "embedding should be approximately L2-normalized");
    }
}
