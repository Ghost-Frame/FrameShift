//! [`CapabilityManifest`] -- a subset of pack-level capability declarations
//! that the runtime inspects.
//!
//! The full pack capability surface is defined in `frameshift-pack`. This type
//! captures only the memory-related fields that the runtime needs to enforce
//! hard memory requirements at launch time.  Enforcement of other capabilities
//! (tool access, network, etc.) is the responsibility of a future crate.

use frameshift_memory::{MemoryOp, MemoryRequirement};

/// A subset of pack-level declarations that the runtime uses when checking
/// whether the configured memory adapter satisfies the persona's requirements.
///
/// Construct this via [`Default`] (no requirements) or fill the fields
/// manually from a parsed pack manifest.
#[derive(Debug, Clone, Default)]
pub struct CapabilityManifest {
    /// Whether the persona requires a memory adapter and how strictly.
    ///
    /// - [`MemoryRequirement::None`] -- no memory adapter needed (default).
    /// - [`MemoryRequirement::Soft`] -- adapter is optional; the persona
    ///   degrades gracefully without one.
    /// - [`MemoryRequirement::Hard`] -- the persona cannot operate without
    ///   a memory adapter; [`Runtime::check_memory_capability`] returns
    ///   [`RuntimeError::MemoryUnconfigured`] when none is set.
    pub memory_required: Option<MemoryRequirement>,

    /// The specific [`MemoryOp`] variants that the persona pack calls.
    ///
    /// An empty `Vec` means no memory operations are declared.
    pub memory_required_ops: Vec<MemoryOp>,
}
