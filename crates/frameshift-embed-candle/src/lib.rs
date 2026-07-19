//! Real semantic embeddings for persona selection, powered by candle.
//!
//! This is Phase 2 of the semantic-selection arc: a concrete [`Embedder`]
//! backed by a small sentence-transformer (`all-MiniLM-L6-v2`, ~23 MB of
//! safetensors) running on pure-Rust candle. The model is downloaded on first
//! use through `hf-hub` into its standard local cache and memory-mapped on
//! subsequent loads, so no network access happens after the first run.
//!
//! Everything here is optional: the workspace only compiles this crate behind
//! the `embeddings` cargo feature of its consumers, and every failure path
//! (no network, corrupt cache, tokenizer errors) degrades to "no embedder",
//! which the selection engine treats as a zero semantic signal.

use std::path::Path;

use candle_core::{Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config, DTYPE};
use hf_hub::api::sync::Api;
use hf_hub::{Repo, RepoType};
use tokenizers::Tokenizer;

use frameshift_orchestrator::Embedder;

/// The default sentence-embedding model: small, permissively licensed, and the
/// de-facto standard for lightweight sentence similarity.
pub const DEFAULT_MODEL_ID: &str = "sentence-transformers/all-MiniLM-L6-v2";

/// BERT's positional-embedding window; longer inputs are truncated by the
/// tokenizer rather than erroring at the tensor layer.
const MAX_TOKENS: usize = 512;

/// Errors constructing or loading a [`CandleEmbedder`].
///
/// Kept deliberately coarse: callers only branch on "embedder available or
/// not", so each variant just preserves the failing layer for diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum EmbedError {
    /// Downloading model artifacts from the hub failed (offline, DNS, 404).
    #[error("model download failed: {0}")]
    Download(String),

    /// Reading or parsing a model artifact from disk failed.
    #[error("model artifact unreadable: {0}")]
    Artifact(String),

    /// Building the tokenizer from tokenizer.json failed.
    #[error("tokenizer load failed: {0}")]
    Tokenizer(String),

    /// Constructing the BERT model from its weights failed.
    #[error("model load failed: {0}")]
    Model(String),
}

/// A sentence embedder backed by a candle BERT model.
///
/// Construction is the expensive step (download on first use, then an mmap
/// load); [`Embedder::embed`] calls are cheap enough for selection-time use.
/// The struct is immutable after construction, so `&self` embedding calls are
/// safe to share across threads.
pub struct CandleEmbedder {
    /// The loaded BERT encoder.
    model: BertModel,
    /// WordPiece tokenizer configured to truncate at [`MAX_TOKENS`].
    tokenizer: Tokenizer,
    /// Inference device; always CPU -- selection is low-frequency and small.
    device: Device,
}

impl CandleEmbedder {
    /// Load the default model ([`DEFAULT_MODEL_ID`]), downloading it into the
    /// hf-hub cache on first use.
    pub fn from_hub() -> Result<Self, EmbedError> {
        Self::from_hub_model(DEFAULT_MODEL_ID)
    }

    /// Load `model_id` from the hub cache, downloading on first use.
    ///
    /// The model must ship `config.json`, `tokenizer.json`, and
    /// `model.safetensors` (the standard sentence-transformers layout).
    pub fn from_hub_model(model_id: &str) -> Result<Self, EmbedError> {
        let api = Api::new().map_err(|e| EmbedError::Download(e.to_string()))?;
        let repo = api.repo(Repo::new(model_id.to_string(), RepoType::Model));
        let config = repo
            .get("config.json")
            .map_err(|e| EmbedError::Download(e.to_string()))?;
        let tokenizer = repo
            .get("tokenizer.json")
            .map_err(|e| EmbedError::Download(e.to_string()))?;
        let weights = repo
            .get("model.safetensors")
            .map_err(|e| EmbedError::Download(e.to_string()))?;
        Self::from_files(&config, &tokenizer, &weights)
    }

    /// Build an embedder from already-downloaded artifact files.
    ///
    /// Useful for bundled distributions (desktop app) and offline tests; no
    /// network access is attempted.
    pub fn from_files(
        config_path: &Path,
        tokenizer_path: &Path,
        weights_path: &Path,
    ) -> Result<Self, EmbedError> {
        let config_raw = std::fs::read_to_string(config_path)
            .map_err(|e| EmbedError::Artifact(format!("{}: {e}", config_path.display())))?;
        let config: Config =
            serde_json::from_str(&config_raw).map_err(|e| EmbedError::Artifact(e.to_string()))?;

        let mut tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(|e| EmbedError::Tokenizer(e.to_string()))?;
        // Truncate at the model's positional window so arbitrarily long task
        // hints embed instead of erroring; no padding needed for single texts.
        let truncation = tokenizers::TruncationParams {
            max_length: MAX_TOKENS,
            ..Default::default()
        };
        tokenizer
            .with_truncation(Some(truncation))
            .map_err(|e| EmbedError::Tokenizer(e.to_string()))?;

        let device = Device::Cpu;
        // SAFETY: mmap of the safetensors file; the file comes from the local
        // cache we just resolved and is not mutated while mapped.
        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(&[weights_path], DTYPE, &device)
                .map_err(|e| EmbedError::Model(e.to_string()))?
        };
        let model = BertModel::load(vb, &config).map_err(|e| EmbedError::Model(e.to_string()))?;

        Ok(CandleEmbedder {
            model,
            tokenizer,
            device,
        })
    }

    /// Tokenize, run the encoder, mean-pool over the sequence, and
    /// L2-normalize into a unit vector.
    fn embed_inner(&self, text: &str) -> Result<Vec<f32>, candle_core::Error> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| candle_core::Error::Msg(e.to_string()))?;
        let ids = encoding.get_ids();
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        let token_ids = Tensor::new(ids, &self.device)?.unsqueeze(0)?;
        let token_type_ids = token_ids.zeros_like()?;
        // Single unpadded sequence: a None attention mask means "attend to
        // everything", which is exactly right without padding tokens.
        let hidden = self.model.forward(&token_ids, &token_type_ids, None)?;

        // Mean-pool the (1, seq, hidden) activations over the sequence axis.
        let (_batch, seq_len, _hidden) = hidden.dims3()?;
        let pooled = (hidden.sum(1)? / (seq_len as f64))?;
        let vector = pooled.squeeze(0)?.to_vec1::<f32>()?;
        Ok(l2_normalized(vector))
    }
}

impl Embedder for CandleEmbedder {
    /// Embed `text` into a unit vector; degenerate inputs and inference
    /// failures return an empty vector, which the scorer reads as "no
    /// semantic signal" rather than an error.
    fn embed(&self, text: &str) -> Vec<f32> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }
        match self.embed_inner(trimmed) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "semantic embedding failed; returning no signal");
                Vec::new()
            }
        }
    }
}

/// L2-normalize `v` in plain Rust, returning the unit vector.
///
/// A zero (or effectively zero) norm returns the input unchanged rather than
/// dividing by zero; cosine similarity downstream already treats such vectors
/// as no-signal.
fn l2_normalized(mut v: Vec<f32>) -> Vec<f32> {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > f32::EPSILON {
        for x in &mut v {
            *x /= norm;
        }
    }
    v
}

/// Default on-disk location for a [`frameshift_orchestrator::CachedEmbedder`]
/// cache file scoped to `model_id`.
///
/// Resolves `$XDG_CACHE_HOME/frameshift/` (falling back to `~/.cache/` and,
/// as a last resort, the current directory) and derives the filename from the
/// model id with path separators flattened, so distinct models never share a
/// cache file: mixing models would serve vectors from the wrong geometry.
pub fn default_cache_path(model_id: &str) -> std::path::PathBuf {
    let cache_root = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let file = format!("embed-cache-{}.json", model_id.replace(['/', '\\'], "--"));
    cache_root.join("frameshift").join(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A normalized vector has unit length.
    #[test]
    fn l2_normalized_produces_unit_vector() {
        let v = l2_normalized(vec![3.0, 4.0]);
        assert!((v[0] - 0.6).abs() < 1e-6);
        assert!((v[1] - 0.8).abs() < 1e-6);
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-6);
    }

    /// A zero vector passes through unchanged instead of dividing by zero.
    #[test]
    fn l2_normalized_zero_vector_is_unchanged() {
        let v = l2_normalized(vec![0.0, 0.0, 0.0]);
        assert_eq!(v, vec![0.0, 0.0, 0.0]);
        assert!(v.iter().all(|x| x.is_finite()));
    }

    /// An empty vector stays empty.
    #[test]
    fn l2_normalized_empty_is_empty() {
        assert!(l2_normalized(Vec::new()).is_empty());
    }

    /// End-to-end embedding sanity: related texts score above unrelated ones.
    ///
    /// Ignored by default because it downloads the model on first run; run
    /// explicitly with `cargo test -p frameshift-embed-candle -- --ignored`.
    #[test]
    #[ignore = "downloads the ~23MB model on first run"]
    fn embeds_and_ranks_related_text_higher() {
        let embedder = CandleEmbedder::from_hub().expect("model load");
        let task = embedder.embed("fix a memory safety bug in the borrow checker");
        let related = embedder.embed("debug rust ownership and lifetime errors");
        let unrelated = embedder.embed("bake a chocolate cake with vanilla frosting");
        assert_eq!(task.len(), 384, "MiniLM-L6 has 384-dim embeddings");

        let sim = |a: &[f32], b: &[f32]| -> f32 { a.iter().zip(b).map(|(x, y)| x * y).sum() };
        assert!(
            sim(&task, &related) > sim(&task, &unrelated),
            "related text must out-score unrelated text"
        );
    }
}
