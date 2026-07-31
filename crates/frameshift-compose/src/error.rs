use frameshift_source::SourceError;

#[derive(Debug, thiserror::Error)]
pub enum ComposeError {
    #[error("source error: {0}")]
    Source(#[from] SourceError),

    #[error("could not resolve persona spec '{spec}': {reason}")]
    Unresolved { spec: String, reason: String },

    #[error("invalid persona spec '{0}' -- expected '<name>' or '<name>@<version>'")]
    InvalidSpec(String),

    #[error("composition conflict(s) detected: {count}")]
    Conflicted { count: usize },

    /// A mixin or the root persona (without `override_inherited = true`) attempted
    /// to override an L1 rule from the base persona. Per threat model SD6, only
    /// the root persona can override inherited L1 rules, and only with the
    /// explicit opt-in flag set.
    #[error("L1 rule '{rule_id}' from {base_layer} cannot be overridden by {mixin_layer}")]
    L1Override {
        /// The `id` of the L1 rule that was targeted.
        rule_id: String,
        /// Human-readable description of the layer that owns the L1 rule.
        base_layer: String,
        /// Human-readable description of the layer that attempted the override.
        mixin_layer: String,
    },

    /// The composition stack passed to `merge_layers` violates the structural
    /// invariant that at most one `Layer::Base` may be present, and it must be
    /// the first element. This is enforced up front so a `Layer::Base` can
    /// never appear mid-stack or duplicated, which would otherwise let it
    /// silently defeat L1 protection (SD6) for a rule owned by an earlier base.
    #[error("invalid composition layer stack: {reason}")]
    InvalidLayerStack {
        /// Human-readable description of the structural violation.
        reason: String,
    },
}
