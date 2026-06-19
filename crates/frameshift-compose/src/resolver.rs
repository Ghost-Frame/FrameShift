use std::path::{Path, PathBuf};

use frameshift_source::PersonaSource;

use crate::error::ComposeError;

/// Resolves a persona spec (`<name>` or `<name>@<version>`) to a loaded
/// `PersonaSource`. Implementations decide where sources come from -- local
/// disk, content-addressed cache, marketplace, etc.
pub trait SourceResolver {
    fn resolve(&self, spec: &str) -> Result<PersonaSource, ComposeError>;
}

/// Resolves persona specs against a local base directory: each spec maps to
/// `<base_dir>/<name>/` and is loaded via `PersonaSource::load_from_dir`.
///
/// Version qualifiers in the spec (`<name>@<version>`) are currently ignored
/// at lookup time -- the base directory is assumed to host one version per
/// persona. Version pinning is the resolver's contract to enforce; here we
/// defer that to higher layers.
pub struct LocalResolver {
    base_dir: PathBuf,
}

impl LocalResolver {
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}

fn split_spec(spec: &str) -> Result<(&str, Option<&str>), ComposeError> {
    if spec.is_empty() {
        return Err(ComposeError::InvalidSpec(spec.to_string()));
    }
    match spec.split_once('@') {
        Some((name, version)) if !name.is_empty() && !version.is_empty() => {
            Ok((name, Some(version)))
        }
        Some(_) => Err(ComposeError::InvalidSpec(spec.to_string())),
        None => Ok((spec, None)),
    }
}

impl SourceResolver for LocalResolver {
    fn resolve(&self, spec: &str) -> Result<PersonaSource, ComposeError> {
        let (name, _version) = split_spec(spec)?;
        // Reject names that would escape base_dir before joining. `extends`/
        // `mixins` spec strings come from persona TOML and are untrusted; a name
        // like `../../etc` must not load PersonaSource from outside base_dir.
        if name.is_empty()
            || name.starts_with('.')
            || name.contains('/')
            || name.contains('\\')
            || name.contains("..")
            || name.chars().any(char::is_control)
        {
            return Err(ComposeError::InvalidSpec(spec.to_string()));
        }
        let dir = self.base_dir.join(name);
        if !dir.is_dir() {
            return Err(ComposeError::Unresolved {
                spec: spec.to_string(),
                reason: format!("directory not found: {}", dir.display()),
            });
        }
        let source = PersonaSource::load_from_dir(&dir)?;
        Ok(source)
    }
}
