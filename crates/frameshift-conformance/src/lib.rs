//! Conformance harness for frameshift personas.
//!
//! Owns:
//! - Test bundle schema ([`bundle`], [`case`])
//! - Runner trait ([`runner`])
//! - Scoring ([`score`])
//! - Upgrade-regression gate ([`gate`])
//!
//! The runtime invokes a [`Runner`] for each [`TestCase`] in a [`TestBundle`],
//! produces a [`Score`], and feeds it to the [`RegressionGate`] during upgrades.

pub mod bundle;
pub mod caller;
pub mod case;
#[cfg(feature = "cli-runner")]
pub mod cli_runner;
pub mod error;
pub mod gate;
pub mod runner;
pub mod score;

pub use bundle::{bundle_hash, load_from_dir, TestBundle};
pub use caller::{score_bundle_with_caller, CallerScorer};
pub use case::{ExpectedBehavior, ScorerKind, TestCase};
pub use error::ConformanceError;
pub use gate::{GateDecision, RegressionGate};
pub use runner::{MockRunner, Runner};
pub use score::{bundle_score, score_test, Score};
