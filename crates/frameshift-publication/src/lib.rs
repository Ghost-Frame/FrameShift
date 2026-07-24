//! Fail-closed validation for directories crossing the public pack boundary.
//!
//! The report is versioned and deterministic so CLI, MCP, desktop, and server
//! callers can present the same findings and compare the same inventory.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};

use frameshift_pack::{FilesystemScope, PackManifest};
use frameshift_source::{is_growth_file, render_to_markdown, PersonaSource, RenderTarget};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

/// Current schema version for serialized [`PublicationReport`] values.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// Files that are valid at the root of a published pack.
const ROOT_ALLOWLIST: &[&str] = &[
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    "README.md",
    "pack.template.toml",
    "pack.toml",
    "patterns.toml",
    "persona.toml",
    "rules.toml",
    "skills.toml",
    "vars.toml",
];

/// Root render candidates accepted by the documented pack contract.
const RENDER_CANDIDATES: &[&str] = &["AGENTS.md", "CLAUDE.md", "GEMINI.md", "README.md"];

/// A deterministic, machine-readable result of validating a pack directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationReport {
    /// Version of this serialized report contract.
    pub schema_version: u32,
    /// Whether no blocking finding was emitted.
    pub valid: bool,
    /// SHA-256 over the deterministic inventory metadata.
    pub inventory_hash: String,
    /// Sorted public files that would be signed and uploaded.
    pub inventory: Vec<InventoryEntry>,
    /// Stable, sorted findings suitable for machines and people.
    pub findings: Vec<PublicationFinding>,
}

/// One file in the exact public inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryEntry {
    /// NFC-normalized relative path using `/` separators.
    pub path: String,
    /// File size in bytes.
    pub size: u64,
    /// SHA-256 of the exact file bytes.
    pub sha256: String,
}

/// One policy or schema finding in a publication report.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PublicationFinding {
    /// Stable code for programmatic handling.
    pub code: String,
    /// Whether the finding blocks publication.
    pub severity: FindingSeverity,
    /// Optional normalized path associated with the finding.
    pub path: Option<String>,
    /// Human-readable explanation with no private absolute paths.
    pub message: String,
}

/// Severity of a publication finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    /// Advisory information that does not block publication.
    Warning,
    /// A failed invariant that blocks publication.
    Error,
}

/// An operating-system failure while building a publication report.
#[derive(Debug, thiserror::Error)]
pub enum PublicationIoError {
    /// The supplied publication root could not be inspected.
    #[error("publication directory could not be inspected: {0}")]
    Root(#[source] std::io::Error),
    /// A bounded relative entry could not be inspected or read.
    #[error("publication entry {path:?} could not be read: {source}")]
    Entry {
        /// Normalized relative entry path.
        path: String,
        /// Underlying filesystem error.
        #[source]
        source: std::io::Error,
    },
}

/// Validate a directory and return its deterministic public-boundary report.
///
/// `signature.sig` is intentionally ignored because publish transports the
/// freshly generated signature separately and never includes this local file.
pub fn validate_directory(root: &Path) -> Result<PublicationReport, PublicationIoError> {
    let root_metadata = fs::metadata(root).map_err(PublicationIoError::Root)?;
    if !root_metadata.is_dir() {
        return Err(PublicationIoError::Root(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "publication root is not a directory",
        )));
    }

    let mut inventory = Vec::new();
    let mut findings = Vec::new();
    collect_directory(root, root, &mut inventory, &mut findings)?;
    inventory.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));

    validate_required_content(&inventory, &mut findings);
    validate_manifest(root, &inventory, &mut findings);
    validate_typed_source(root, &inventory, &mut findings);
    validate_template_manifest(root, &inventory, &mut findings);
    findings.sort();

    let valid = !findings
        .iter()
        .any(|finding| finding.severity == FindingSeverity::Error);
    Ok(PublicationReport {
        schema_version: REPORT_SCHEMA_VERSION,
        valid,
        inventory_hash: hash_inventory(&inventory),
        inventory,
        findings,
    })
}

/// Recursively collect exact public files while rejecting unsafe entry types.
fn collect_directory(
    root: &Path,
    current: &Path,
    inventory: &mut Vec<InventoryEntry>,
    findings: &mut Vec<PublicationFinding>,
) -> Result<(), PublicationIoError> {
    let entries = fs::read_dir(current).map_err(|source| PublicationIoError::Entry {
        path: relative_path(root, current),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| PublicationIoError::Entry {
            path: relative_path(root, current),
            source,
        })?;
        let path = entry.path();
        let relative = relative_path(root, &path);
        let file_type = entry
            .file_type()
            .map_err(|source| PublicationIoError::Entry {
                path: relative.clone(),
                source,
            })?;

        if file_type.is_symlink() {
            push_error(
                findings,
                "entry.symlink",
                Some(relative),
                "symbolic links are not publishable",
            );
            continue;
        }
        if file_type.is_dir() {
            collect_directory(root, &path, inventory, findings)?;
            continue;
        }
        if !file_type.is_file() {
            push_error(
                findings,
                "entry.non_regular",
                Some(relative),
                "only regular files are publishable",
            );
            continue;
        }
        if relative == "signature.sig" {
            continue;
        }

        if let Some(code) = forbidden_local_code(&relative) {
            push_error(
                findings,
                code,
                Some(relative.clone()),
                "local or private state must never enter a public pack",
            );
        } else if !is_allowed_path(&relative) {
            push_error(
                findings,
                "path.not_allowed",
                Some(relative.clone()),
                "path is not part of the documented public pack format",
            );
        }

        let bytes = fs::read(&path).map_err(|source| PublicationIoError::Entry {
            path: relative.clone(),
            source,
        })?;
        inventory.push(InventoryEntry {
            path: relative,
            size: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
        });
    }
    Ok(())
}

/// Validate that the inventory contains a manifest and supported behavior.
fn validate_required_content(inventory: &[InventoryEntry], findings: &mut Vec<PublicationFinding>) {
    let paths = inventory_paths(inventory);
    if !paths.contains("pack.toml") {
        push_error(
            findings,
            "manifest.missing",
            Some("pack.toml".to_string()),
            "pack.toml is required",
        );
    }

    let has_render = RENDER_CANDIDATES
        .iter()
        .any(|candidate| paths.contains(*candidate));
    if !has_render && !paths.contains("persona.toml") {
        push_error(
            findings,
            "content.missing",
            None,
            "pack must contain a documented markdown body or typed persona.toml",
        );
    }
}

/// Parse and validate manifest-level publication invariants.
fn validate_manifest(
    root: &Path,
    inventory: &[InventoryEntry],
    findings: &mut Vec<PublicationFinding>,
) {
    if !inventory.iter().any(|entry| entry.path == "pack.toml") {
        return;
    }
    let raw = match fs::read_to_string(root.join("pack.toml")) {
        Ok(raw) => raw,
        Err(_) => {
            push_error(
                findings,
                "manifest.utf8",
                Some("pack.toml".to_string()),
                "pack.toml must be valid UTF-8",
            );
            return;
        }
    };
    let manifest = match toml::from_str::<PackManifest>(&raw) {
        Ok(manifest) => manifest,
        Err(error) => {
            push_error(
                findings,
                "manifest.invalid",
                Some("pack.toml".to_string()),
                format!("pack.toml does not match the shared schema: {error}"),
            );
            return;
        }
    };

    if manifest.schema_version != 1 {
        push_error(
            findings,
            "manifest.schema_version",
            Some("pack.toml".to_string()),
            format!(
                "unsupported pack schema version {}",
                manifest.schema_version
            ),
        );
    }
    if manifest.is_local_unsigned() {
        push_error(
            findings,
            "manifest.local_unsigned",
            Some("pack.toml".to_string()),
            "public packs require a real Ed25519 author key",
        );
    }
    if manifest
        .capability_manifest
        .as_ref()
        .is_some_and(|capabilities| capabilities.filesystem_scope == FilesystemScope::System)
    {
        push_error(
            findings,
            "capability.system_filesystem",
            Some("pack.toml".to_string()),
            "system-wide filesystem access is not publishable",
        );
    }

    validate_conformance(root, &manifest, inventory, findings);
}

/// Validate the claimed conformance baseline against the shipped bundle.
fn validate_conformance(
    root: &Path,
    manifest: &PackManifest,
    inventory: &[InventoryEntry],
    findings: &mut Vec<PublicationFinding>,
) {
    let has_bundle = inventory
        .iter()
        .any(|entry| entry.path == "conformance/bundle.toml");
    let Some(baseline) = &manifest.conformance_baseline else {
        if has_bundle {
            push_warning(
                findings,
                "conformance.unclaimed_bundle",
                Some("conformance/bundle.toml".to_string()),
                "bundle is shipped without a conformance baseline",
            );
        }
        return;
    };

    if !baseline.score.is_finite() || !(0.0..=1.0).contains(&baseline.score) {
        push_error(
            findings,
            "conformance.invalid_score",
            Some("pack.toml".to_string()),
            "conformance score must be finite and within 0.0..=1.0",
        );
    }
    if !has_bundle {
        push_error(
            findings,
            "conformance.bundle_missing",
            Some("conformance/bundle.toml".to_string()),
            "conformance baseline requires a shipped bundle",
        );
        return;
    }

    match frameshift_conformance::load_from_dir(&root.join("conformance"))
        .and_then(|bundle| frameshift_conformance::bundle_hash(&bundle))
    {
        Ok(actual) if actual == baseline.bundle_hash => {}
        Ok(_) => push_error(
            findings,
            "conformance.hash_mismatch",
            Some("conformance/bundle.toml".to_string()),
            "conformance bundle hash does not match the manifest baseline",
        ),
        Err(error) => push_error(
            findings,
            "conformance.bundle_invalid",
            Some("conformance/bundle.toml".to_string()),
            format!("conformance bundle is invalid: {error}"),
        ),
    }
}

/// Parse typed persona source and prove its generic render is deterministic.
fn validate_typed_source(
    root: &Path,
    inventory: &[InventoryEntry],
    findings: &mut Vec<PublicationFinding>,
) {
    if !inventory.iter().any(|entry| entry.path == "persona.toml") {
        return;
    }
    let source = match PersonaSource::load_from_dir(root) {
        Ok(source) => source,
        Err(error) => {
            push_error(
                findings,
                "source.invalid",
                Some("persona.toml".to_string()),
                format!("typed persona source is invalid: {error}"),
            );
            return;
        }
    };
    let first = render_to_markdown(&source, RenderTarget::Generic);
    let second = render_to_markdown(&source, RenderTarget::Generic);
    if first != second {
        push_error(
            findings,
            "source.nondeterministic_render",
            Some("persona.toml".to_string()),
            "typed source did not render deterministically",
        );
    }
    if inventory.iter().any(|entry| entry.path == "AGENTS.md") {
        match fs::read_to_string(root.join("AGENTS.md")) {
            Ok(shipped) if shipped == first => {}
            Ok(_) => push_error(
                findings,
                "source.render_mismatch",
                Some("AGENTS.md".to_string()),
                "AGENTS.md does not match the deterministic generic typed-source render",
            ),
            Err(_) => push_error(
                findings,
                "source.render_utf8",
                Some("AGENTS.md".to_string()),
                "AGENTS.md must be valid UTF-8",
            ),
        }
    }
}

/// Parse an optional template manifest with the shared template schema.
fn validate_template_manifest(
    root: &Path,
    inventory: &[InventoryEntry],
    findings: &mut Vec<PublicationFinding>,
) {
    if !inventory
        .iter()
        .any(|entry| entry.path == "pack.template.toml")
    {
        return;
    }
    match fs::read_to_string(root.join("pack.template.toml"))
        .ok()
        .and_then(|raw| frameshift_template::TemplateManifest::from_toml(&raw).ok())
    {
        Some(_) => {}
        None => push_error(
            findings,
            "template.invalid",
            Some("pack.template.toml".to_string()),
            "pack.template.toml does not match the shared template schema",
        ),
    }
}

/// Return whether a normalized relative path is publicly allowed.
fn is_allowed_path(path: &str) -> bool {
    if ROOT_ALLOWLIST.contains(&path) || path == "conformance/bundle.toml" {
        return true;
    }
    path.strip_prefix("overlays/")
        .is_some_and(|rest| !rest.is_empty() && rest.ends_with(".md"))
}

/// Classify local-only filenames before the general allowlist check.
fn forbidden_local_code(path: &str) -> Option<&'static str> {
    let filename = path.rsplit('/').next().unwrap_or(path);
    let lower_path = path.to_lowercase();
    let lower_filename = filename.to_lowercase();
    if is_growth_file(filename) {
        return Some("path.growth_state");
    }
    if lower_filename == ".env" || lower_filename.starts_with(".env.") {
        return Some("path.secret_state");
    }
    if lower_filename.starts_with('.') {
        return Some("path.hidden");
    }
    if lower_path.contains("vault")
        || lower_path.contains("recovery")
        || lower_path.contains("private-source")
        || lower_path.contains("private_source")
    {
        return Some("path.private_state");
    }
    None
}

/// Normalize a relative filesystem path without exposing the absolute root.
fn relative_path(root: &Path, path: &Path) -> String {
    let stripped = path.strip_prefix(root).unwrap_or(path);
    let mut parts = Vec::new();
    for component in stripped.components() {
        if let Component::Normal(part) = component {
            parts.push(part.to_string_lossy().nfc().collect::<String>());
        }
    }
    parts.join("/")
}

/// Build a borrowed set of inventory paths for membership checks.
fn inventory_paths(inventory: &[InventoryEntry]) -> BTreeSet<&str> {
    inventory.iter().map(|entry| entry.path.as_str()).collect()
}

/// Hash deterministic inventory metadata without depending on JSON formatting.
fn hash_inventory(inventory: &[InventoryEntry]) -> String {
    let mut hasher = Sha256::new();
    for entry in inventory {
        hasher.update(entry.path.as_bytes());
        hasher.update(b"\0");
        hasher.update(entry.size.to_string().as_bytes());
        hasher.update(b"\0");
        hasher.update(entry.sha256.as_bytes());
        hasher.update(b"\0");
    }
    hex::encode(hasher.finalize())
}

/// Append a blocking finding with stable fields.
fn push_error(
    findings: &mut Vec<PublicationFinding>,
    code: impl Into<String>,
    path: Option<String>,
    message: impl Into<String>,
) {
    findings.push(PublicationFinding {
        code: code.into(),
        severity: FindingSeverity::Error,
        path,
        message: message.into(),
    });
}

/// Append a non-blocking finding with stable fields.
fn push_warning(
    findings: &mut Vec<PublicationFinding>,
    code: impl Into<String>,
    path: Option<String>,
    message: impl Into<String>,
) {
    findings.push(PublicationFinding {
        code: code.into(),
        severity: FindingSeverity::Warning,
        path,
        message: message.into(),
    });
}

#[cfg(test)]
/// Publication policy and deterministic-report tests.
mod tests {
    use super::*;
    use frameshift_conformance::{bundle_hash, TestBundle};
    use std::io::Write as _;

    /// Canonical test author key accepted by the pack schema.
    const TEST_KEY: &str = "0707070707070707070707070707070707070707070707070707070707070707";

    /// Write a minimal valid freeform test pack.
    fn write_freeform_pack(root: &Path) {
        fs::write(
            root.join("pack.toml"),
            format!(
                "schema_version = 1\nname = \"fixture\"\nauthor_handle = \"alice\"\n\
                 author_pubkey = \"{TEST_KEY}\"\nversion = \"0.1.0\"\n"
            ),
        )
        .expect("write manifest");
        fs::write(root.join("AGENTS.md"), "# Fixture\n").expect("write body");
    }

    /// Return whether a report contains a stable finding code.
    fn has_code(report: &PublicationReport, code: &str) -> bool {
        report.findings.iter().any(|finding| finding.code == code)
    }

    /// A documented freeform pack produces a stable valid report.
    #[test]
    fn freeform_report_is_valid_and_deterministic() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_freeform_pack(dir.path());

        let first = validate_directory(dir.path()).expect("first report");
        let second = validate_directory(dir.path()).expect("second report");
        assert!(first.valid);
        assert_eq!(first, second);
        assert_eq!(first.schema_version, REPORT_SCHEMA_VERSION);
        assert_eq!(
            first
                .inventory
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            vec!["AGENTS.md", "pack.toml"]
        );
    }

    /// Unknown and local growth files are independently classified and blocked.
    #[test]
    fn unknown_and_growth_files_fail_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_freeform_pack(dir.path());
        fs::write(dir.path().join("notes.txt"), "no").expect("unknown");
        fs::write(dir.path().join("GROWTH.md"), "private").expect("growth");

        let report = validate_directory(dir.path()).expect("report");
        assert!(!report.valid);
        assert!(has_code(&report, "path.not_allowed"));
        assert!(has_code(&report, "path.growth_state"));
    }

    /// Malformed shared TOML schemas block publication with typed finding codes.
    #[test]
    fn malformed_manifest_and_template_fail_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("pack.toml"), "not = [valid").expect("manifest");
        fs::write(dir.path().join("AGENTS.md"), "# Fixture\n").expect("body");
        fs::write(dir.path().join("pack.template.toml"), "[tokens.bad\n").expect("template");

        let report = validate_directory(dir.path()).expect("report");
        assert!(has_code(&report, "manifest.invalid"));
        assert!(has_code(&report, "template.invalid"));
    }

    /// System-wide filesystem capability declarations are not publishable.
    #[test]
    fn system_filesystem_capability_is_blocked() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_freeform_pack(dir.path());
        let mut manifest = fs::read_to_string(dir.path().join("pack.toml")).expect("read");
        manifest.push_str("\n[capability_manifest]\nfilesystem_scope = \"system\"\n");
        fs::write(dir.path().join("pack.toml"), manifest).expect("write");

        let report = validate_directory(dir.path()).expect("report");
        assert!(has_code(&report, "capability.system_filesystem"));
    }

    /// A mismatched conformance baseline cannot cross the public boundary.
    #[test]
    fn conformance_hash_mismatch_is_blocked() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_freeform_pack(dir.path());
        fs::create_dir(dir.path().join("conformance")).expect("conformance dir");
        fs::write(
            dir.path().join("conformance/bundle.toml"),
            "name = \"fixture\"\nversion = \"1\"\ntests = []\n",
        )
        .expect("bundle");
        let mut manifest = fs::read_to_string(dir.path().join("pack.toml")).expect("read");
        manifest.push_str(
            "\n[conformance_baseline]\nscore = 1.0\nbundle_hash = \"0000000000000000000000000000000000000000000000000000000000000000\"\n",
        );
        fs::write(dir.path().join("pack.toml"), manifest).expect("write");

        let report = validate_directory(dir.path()).expect("report");
        assert!(has_code(&report, "conformance.hash_mismatch"));
    }

    /// A matching typed source body and conformance bundle validate together.
    #[test]
    fn typed_pack_and_matching_conformance_are_valid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let persona = r#"schema_version = 1
name = "fixture"
version = "0.1.0"

[voice]
tone = "precise"
"#;
        fs::write(dir.path().join("persona.toml"), persona).expect("persona");
        let source = PersonaSource::load_from_dir(dir.path()).expect("source");
        fs::write(
            dir.path().join("AGENTS.md"),
            render_to_markdown(&source, RenderTarget::Generic),
        )
        .expect("render");

        let bundle = TestBundle {
            name: "fixture".to_string(),
            version: "1".to_string(),
            tests: Vec::new(),
        };
        fs::create_dir(dir.path().join("conformance")).expect("conformance");
        fs::write(
            dir.path().join("conformance/bundle.toml"),
            toml::to_string(&bundle).expect("serialize bundle"),
        )
        .expect("write bundle");
        let bundle_hash = bundle_hash(&bundle).expect("bundle hash");
        fs::write(
            dir.path().join("pack.toml"),
            format!(
                "schema_version = 1\nname = \"fixture\"\nauthor_handle = \"alice\"\n\
                 author_pubkey = \"{TEST_KEY}\"\nversion = \"0.1.0\"\n\
                 [conformance_baseline]\nscore = 1.0\nbundle_hash = \"{bundle_hash}\"\n"
            ),
        )
        .expect("manifest");

        let report = validate_directory(dir.path()).expect("report");
        assert!(report.valid, "{:?}", report.findings);
    }

    /// A typed pack cannot ship a stale generated AGENTS.md.
    #[test]
    fn typed_render_mismatch_is_blocked() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_freeform_pack(dir.path());
        fs::write(
            dir.path().join("persona.toml"),
            "schema_version = 1\nname = \"fixture\"\n[voice]\ntone = \"precise\"\n",
        )
        .expect("persona");

        let report = validate_directory(dir.path()).expect("report");
        assert!(has_code(&report, "source.render_mismatch"));
    }

    /// Symlinks are reported and never dereferenced.
    #[cfg(unix)]
    #[test]
    fn symlink_is_blocked_without_dereference() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        write_freeform_pack(dir.path());
        symlink("/etc/passwd", dir.path().join("leak.md")).expect("symlink");

        let report = validate_directory(dir.path()).expect("report");
        assert!(has_code(&report, "entry.symlink"));
        assert!(!report.inventory.iter().any(|entry| entry.path == "leak.md"));
    }

    /// Local signature files are intentionally outside the public inventory.
    #[test]
    fn local_signature_is_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_freeform_pack(dir.path());
        let mut file = fs::File::create(dir.path().join("signature.sig")).expect("signature");
        file.write_all(&[1u8; 64]).expect("signature bytes");

        let report = validate_directory(dir.path()).expect("report");
        assert!(report.valid);
        assert!(!report
            .inventory
            .iter()
            .any(|entry| entry.path == "signature.sig"));
    }
}
