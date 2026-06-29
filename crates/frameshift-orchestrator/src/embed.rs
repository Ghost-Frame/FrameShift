//! Semantic embedding abstraction for meaning-based persona matching.
//!
//! This is the dependency-free Phase 1 scaffolding for semantic selection: it
//! defines the [`Embedder`] trait and the cosine-similarity math the policy
//! scorer uses, but ships no concrete embedding engine. A real embedder (a
//! pure-Rust `candle` model, or `fastembed`/`ort`, plus model distribution) is
//! Phase 2 and is gated on an explicit decision because it adds a heavy ML
//! dependency to an otherwise lean workspace.
//!
//! Because no production caller supplies an [`Embedder`] yet, the semantic
//! channel contributes `0.0` everywhere and selection behavior is unchanged.

/// Produces a dense vector embedding for a piece of text.
///
/// Implementations map natural-language text to a fixed-dimensional vector
/// whose geometry encodes meaning, so that related texts have a high cosine
/// similarity. The trait is object-safe (`&dyn Embedder`) so the scorer can
/// accept an optional embedder without being generic over its type. Two calls
/// with equal input should return equal output (determinism), and all vectors
/// from a given embedder should share one dimensionality.
pub trait Embedder {
    /// Return the embedding vector for `text`.
    fn embed(&self, text: &str) -> Vec<f32>;
}

/// Cosine similarity between two equal-length vectors, clamped to `[0.0, 1.0]`.
///
/// Returns `0.0` (a safe no-signal value) rather than panicking or producing
/// `NaN` when the inputs are degenerate: empty vectors, vectors of differing
/// length, or a vector whose L2 norm is effectively zero. Negative cosine
/// (anti-correlated vectors) is clamped to `0.0` because the scorer treats this
/// as an additive similarity bonus, never a penalty.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.is_empty() || a.len() != b.len() {
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm_a <= f32::EPSILON || norm_b <= f32::EPSILON {
        return 0.0;
    }
    (dot / (norm_a * norm_b)).clamp(0.0, 1.0)
}

/// Embed both texts with `embedder` and return their cosine similarity in
/// `[0.0, 1.0]`.
///
/// Convenience wrapper over [`cosine_similarity`]. Inherits its degenerate-case
/// handling, so an embedder that returns empty or mismatched-length vectors
/// yields `0.0` rather than an error.
pub fn semantic_similarity(embedder: &dyn Embedder, a: &str, b: &str) -> f32 {
    let va = embedder.embed(a);
    let vb = embedder.embed(b);
    cosine_similarity(&va, &vb)
}

/// A deterministic bag-of-words embedder used only by tests.
///
/// Hashes each whitespace-separated, lowercased word into a fixed-width bucket
/// and counts occurrences. It is order-insensitive and dependency-free, so two
/// texts that share words have overlapping nonzero buckets and therefore a
/// positive cosine similarity -- enough to exercise the semantic channel
/// without a real embedding model.
#[cfg(test)]
pub(crate) struct BagOfWordsEmbedder;

#[cfg(test)]
impl Embedder for BagOfWordsEmbedder {
    /// Embed `text` as a 64-dimensional word-occurrence histogram.
    fn embed(&self, text: &str) -> Vec<f32> {
        const DIM: usize = 64;
        let mut v = vec![0.0f32; DIM];
        for word in text.split_whitespace() {
            let lowered = word.to_lowercase();
            // FNV-1a hash -> bucket index. Stable across runs (no randomness).
            let mut h: u64 = 0xcbf29ce484222325;
            for byte in lowered.bytes() {
                h ^= byte as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            v[(h as usize) % DIM] += 1.0;
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Identical vectors have cosine similarity 1.0.
    #[test]
    fn identical_vectors_are_maximally_similar() {
        let v = vec![1.0, 2.0, 3.0];
        assert!((cosine_similarity(&v, &v) - 1.0).abs() < 1e-6);
    }

    /// Orthogonal vectors have cosine similarity 0.0.
    #[test]
    fn orthogonal_vectors_are_dissimilar() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        assert_eq!(cosine_similarity(&a, &b), 0.0);
    }

    /// Anti-correlated vectors clamp to 0.0 (no negative bonus).
    #[test]
    fn anti_correlated_clamps_to_zero() {
        let a = vec![1.0, 0.0];
        let b = vec![-1.0, 0.0];
        assert_eq!(cosine_similarity(&a, &b), 0.0);
    }

    /// Empty, mismatched-length, and zero-norm inputs yield 0.0 (no panic, no NaN).
    #[test]
    fn degenerate_inputs_yield_zero() {
        assert_eq!(cosine_similarity(&[], &[]), 0.0);
        assert_eq!(cosine_similarity(&[1.0, 2.0], &[1.0]), 0.0);
        assert_eq!(cosine_similarity(&[0.0, 0.0], &[1.0, 1.0]), 0.0);
    }

    /// The mock embedder gives a high similarity to identical text and a
    /// positive-but-lower similarity to text that merely shares words.
    #[test]
    fn mock_embedder_reflects_word_overlap() {
        let emb = BagOfWordsEmbedder;
        let same = semantic_similarity(&emb, "rust cargo clippy", "rust cargo clippy");
        let related = semantic_similarity(&emb, "rust cargo clippy", "rust cargo ownership");
        let unrelated = semantic_similarity(&emb, "rust cargo clippy", "tacos");

        assert!((same - 1.0).abs() < 1e-6, "identical text -> 1.0");
        assert!(related > 0.0, "shared words -> positive similarity");
        assert!(related < same, "partial overlap < full overlap");
        assert!(unrelated < related, "no shared words -> least similar");
    }
}
