//! Structured persona source.
//!
//! Persona source is a typed TOML schema. It can be split across
//! `persona.toml`, `rules.toml`, `skills.toml`, and `patterns.toml`, or carried
//! inline in a pack's `pack.toml`. Markdown is a *render target* produced from
//! this typed source -- agents and CLIs operate on typed fields, never on
//! string-replace-in-markdown.
//!
//! This crate owns:
//! - the TOML schema for each file (`persona`, `rules`, `skills`, `patterns`)
//! - the composite `PersonaSource` with split-file and inline-pack loading
//! - deterministic markdown projection (`render`)
//! - typed patch operations (`patch`)
//! - semantic diff between two `PersonaSource` snapshots (`diff`)
//!
//! Schema serde round-trip, the load/write split, markdown projection, typed
//! patch operations, and semantic diff are all implemented; this module is
//! past its M1 scaffolding stage.

pub mod diff;
pub mod error;
pub mod patch;
pub mod patterns;
pub mod persona;
pub mod prompt_policy;
pub mod render;
pub mod rules;
pub mod security;
pub mod skills;
pub mod source;
pub mod validate;

pub use diff::{diff, SemanticDiff};
pub use error::SourceError;
pub use patch::{apply_patch, AnchorPosition, PatchError, PatchOp};
pub use patterns::{AntiPattern, CodeExample, GeneralPattern, PatternSet, StackCategory};
pub use persona::{
    AmbiguityQuestion, Anchor, Aspect, Author, CapabilityManifest, CascadeAnchor,
    ClassificationTier, ConflictResolution, ConformanceConfig, DefaultQuestion, GrowthConfig,
    Persona, ReferenceGroup, SafetyLayer, SelfEvalStep, Voice, VoiceQuestion,
};
pub use prompt_policy::{
    validate_rendered_prompt, PromptPolicyFinding, PromptPolicyReport, PromptPolicySeverity,
    PROMPT_POLICY_VERSION,
};
pub use render::{render_to_markdown, RenderTarget};
pub use rules::{Layer, Rule, RuleSet};
pub use security::{
    audit_manifest, is_growth_file, CapabilitySummary, GrowthFilePermissions, KeyPinCheck,
    ManifestAspect, ManifestAudit, ManifestFinding, ManifestSeverity, PinnedKey, RevocationCheck,
    RevocationEntry, TrustLevel, TrustSummary,
};
pub use skills::{Skill, SkillSet};
pub use source::PersonaSource;
pub use validate::{validate_content, ContentWarning, Severity, WarningCategory};
