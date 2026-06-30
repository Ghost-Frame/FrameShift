use serde::{Deserialize, Serialize};

/// A single conformance test case: a prompt fed to the runner plus an
/// expectation describing the desired response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TestCase {
    pub id: String,
    pub prompt: String,
    pub expected: ExpectedBehavior,
    pub scorer: ScorerKind,
}

/// How the response is expected to look. Variants pair with [`ScorerKind`].
///
/// Uses struct variants with the `kind` tag so TOML serialization round-trips
/// (TOML cannot represent internally-tagged newtype variants over scalars).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExpectedBehavior {
    /// Response must contain this substring (Unicode-naive, case-sensitive).
    Contains { value: String },
    /// Response must match this regex (compiled via the `regex` crate at scoring time).
    Matches { pattern: String },
    /// Response must parse as JSON whose shape matches this template.
    JsonShape { shape: serde_json::Value },
    /// Opaque scorer ID resolved by the caller (e.g. an LLM-judge plugin).
    Custom { id: String },
}

/// Selects the scoring strategy applied to a response.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScorerKind {
    Substring,
    Regex,
    ExactJson,
    Caller,
}
