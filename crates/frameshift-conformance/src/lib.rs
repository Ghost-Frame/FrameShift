//! Conformance harness for frameshift personas.
//!
//! Owns:
//! - Test bundle schema ([`bundle`], [`case`])
//! - Runner trait ([`runner`])
//! - Scoring ([`score`])
//! - Upgrade-regression gate ([`gate`])
//!
//! The runtime invokes a [`Runner`] for each [`TestCase`] in a [`TestBundle`],
//! produces a [`Score`], and can feed it to [`RegressionGate::evaluate_upgrade`]
//! during upgrades. Separately, [`RegressionGate::evaluate_cross_version`]
//! compares two packs' already-*shipped* baselines directly (no test run
//! required) and is wired into `frameshift_client::Client::install`'s
//! install-over-existing-version path as a warn-only, non-blocking check.

pub mod bundle;
pub mod caller;
pub mod case;
#[cfg(feature = "cli-runner")]
pub mod cli_runner;
#[cfg(feature = "cli-runner")]
pub use cli_runner::CliRunner;
pub mod error;
pub mod gate;
pub mod runner;
pub mod score;

pub use bundle::{bundle_hash, load_from_dir, TestBundle};
pub use caller::{score_bundle_with_caller, CallerScorer};
pub use case::{ExpectedBehavior, ScorerKind, TestCase};
pub use error::ConformanceError;
pub use gate::{CrossVersionDecision, GateDecision, RegressionGate};
pub use runner::{MockRunner, Runner};
pub use score::{bundle_score, score_test, Score};
