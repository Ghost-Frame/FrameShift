//! Support for resolving `extends`/`mixin` persona specs against the
//! content-addressed pack cache during render-time composition.
//!
//! The resolver here is deliberately cache-backed rather than sibling-dir
//! backed: at the point composition runs (inside the per-persona loop in
//! `materialize_project_state`), the cache is fully populated for every
//! locked persona, but the `personas/<name>/` output directories are being
//! written one at a time in the same loop -- resolving from a sibling
//! `personas/` dir would race on install order.

use std::collections::BTreeMap;
use std::path::Path;

use frameshift_compose::{ComposeError, SourceResolver};
use frameshift_source::PersonaSource;

use crate::model::Lockfile;
use crate::validate_persona_name;

/// Resolves `extends`/`mixin` specs (`<name>` or `<name>@<version>`) to a
/// `PersonaSource` loaded from the content-addressed cache, using the
/// project's lockfile to map persona name -> canonical hash.
///
/// Version qualifiers in the spec are ignored at lookup time: no semver
/// matcher exists in this workspace, and the lockfile already pins exactly
/// one hash per installed persona name.
pub(crate) struct CacheResolver<'a> {
    /// Root of the content-addressed pack cache (`data_root/cache`).
    cache_dir: &'a Path,
    /// Persona name -> canonical hash, built from the project's lockfile.
    by_name: BTreeMap<&'a str, &'a str>,
}

impl<'a> CacheResolver<'a> {
    /// Builds a resolver from every persona currently locked for the project.
    /// Later entries win on duplicate names (the lockfile itself is kept
    /// unique by name via `upsert_locked_persona`, so this is defensive).
    pub(crate) fn new(cache_dir: &'a Path, lockfile: &'a Lockfile) -> Self {
        let by_name = lockfile
            .personas
            .iter()
            .map(|p| (p.name.as_str(), p.hash.as_str()))
            .collect();
        Self {
            cache_dir,
            by_name,
        }
    }
}

impl SourceResolver for CacheResolver<'_> {
    /// Resolves `spec` to a `PersonaSource` loaded from the cache entry for
    /// the name portion of `spec` (the part before an optional `@version`).
    fn resolve(&self, spec: &str) -> Result<PersonaSource, ComposeError> {
        let name = spec.split_once('@').map(|(n, _)| n).unwrap_or(spec);

        validate_persona_name(name).map_err(|_| ComposeError::Unresolved {
            spec: spec.to_string(),
            reason: "base/mixin persona name is not a valid persona name".to_string(),
        })?;

        let hash = self
            .by_name
            .get(name)
            .ok_or_else(|| ComposeError::Unresolved {
                spec: spec.to_string(),
                reason: "base/mixin persona is not installed in this project".to_string(),
            })?;

        let source = PersonaSource::load_from_dir(&self.cache_dir.join(hash))?;
        Ok(source)
    }
}
