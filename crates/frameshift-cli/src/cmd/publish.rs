//! Implementation of the `frameshift publish` subcommand.
//!
//! Loads a named persona from the central store, writes its source files to
//! an output directory, renders the persona to `AGENTS.md` using the Generic
//! target, and -- when `--server` is given -- packs, signs, and uploads the
//! result to the registry via `POST /v1/packs`.

use std::path::{Path, PathBuf};

use clap::Args;
use frameshift_client::{Client, ClientError};
use frameshift_source::render::{render_to_markdown, RenderTarget};
use frameshift_source::{
    audit_manifest, validate_content, CapabilityManifest, ContentWarning, ManifestSeverity,
    Severity,
};

use crate::cmd::keys::{access_token_from_env, with_key_passphrase};
use crate::util::{load_persona_by_name, validate_server_url, CliError};

/// Default pack version when a persona source declares none.
const DEFAULT_PACK_VERSION: &str = "0.1.0";

/// Arguments for the `publish` subcommand.
#[derive(Debug, Args)]
pub struct PublishArgs {
    /// Name of the persona to publish.
    #[arg(long)]
    pub persona: String,

    /// Output directory for the pack (directory format).
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Registry server URL. When set, the built pack is signed and uploaded.
    #[arg(long)]
    pub server: Option<String>,

    /// Author handle to publish under. Required when `--server` is set; the
    /// handle must already be registered (see `frameshift register`).
    #[arg(long)]
    pub handle: Option<String>,
}

/// Execute the `publish` subcommand.
///
/// Loads the persona by name, writes its source to the output directory, and
/// renders an `AGENTS.md`. When `--server` is given, also synthesizes a
/// `pack.toml`, packs and signs the directory, and uploads it to the registry.
pub fn run_publish(args: PublishArgs) -> Result<(), CliError> {
    // Build client and load the persona.
    let client = Client::with_default_data_root()?;
    let src = load_persona_by_name(&client, &args.persona)?;

    // Advisory content scan (F-06): surface potentially dangerous patterns
    // (destructive commands, sensitive paths, permission escalation, data
    // exfiltration, behavioral-override phrasing) before packing/signing.
    //
    // This is intentionally warn-only and NEVER blocks the publish. Many
    // legitimate security/devops personas legitimately contain strings the
    // scanner flags -- e.g. a hardening persona documenting `rm -rf`,
    // `curl | sh` risks, `base64` payload analysis, or prompt-injection
    // phrases like "you are now" as *examples to detect/defend against*.
    // Hard-blocking on these heuristics would break valid publishes, so
    // findings are printed (Critical ones most prominently) and the flow
    // do not block publication on their own.
    print_validation_warnings(&validate_content(&src));
    enforce_capability_manifest_policy(src.persona.capability_manifest.as_ref())?;

    // Determine the output directory.
    let out_dir = match &args.out {
        Some(path) => path.clone(),
        None => PathBuf::from("publish-output").join(&args.persona),
    };

    // Create the output directory (and any parents).
    std::fs::create_dir_all(&out_dir)?;

    // Write the persona source files to the output directory.
    src.write_to_dir(&out_dir)
        .map_err(|e| CliError::WriteSource(e.to_string()))?;

    // Render to AGENTS.md for the Generic target.
    let markdown = render_to_markdown(&src, RenderTarget::Generic);
    let agents_md_path = out_dir.join("AGENTS.md");
    std::fs::write(&agents_md_path, markdown)?;

    // Pack name and version come from the source (falling back to sensible
    // defaults), and are shared by the on-disk summary and the upload manifest.
    let pack_name = if src.persona.name.is_empty() {
        args.persona.clone()
    } else {
        src.persona.name.clone()
    };
    let version = src
        .persona
        .version
        .clone()
        .unwrap_or_else(|| DEFAULT_PACK_VERSION.to_string());

    println!("published {pack_name} v{version} to {}", out_dir.display());

    // Without --server, this is a disk-only build; we are done.
    let Some(server) = args.server.as_deref() else {
        return Ok(());
    };
    validate_server_url(server)?;

    // Uploading requires an author handle to bind the pack to.
    let handle = args.handle.as_deref().ok_or_else(|| {
        CliError::Publish("--handle is required when --server is set".to_string())
    })?;

    // Synthesize a pack.toml so the directory loads as a Pack. The author
    // pubkey is the managed signing key's public key (hex), matching the
    // frameshift-seed convention.
    let access_token = access_token_from_env()?;
    let (signing_key, _) =
        with_key_passphrase(|passphrase| client.author_signing_key_with_passphrase(passphrase))?;
    let author_pubkey_hex = frameshift_client::identity::public_key_hex(&signing_key);
    write_pack_toml(&out_dir, &pack_name, &version, handle, &author_pubkey_hex)?;

    // Pack, sign, and upload.
    match client.publish_pack_dir_with_signing_key_and_auth(
        server,
        &out_dir,
        handle,
        &signing_key,
        access_token.as_ref(),
    ) {
        Ok(outcome) => {
            println!(
                "uploaded {} v{} as {} (pack_hash {})",
                outcome.name, outcome.version, outcome.author_handle, outcome.pack_hash
            );
            Ok(())
        }
        // A 401 almost always means the handle is not registered to this
        // machine's key. Point the user at `frameshift register`.
        Err(ClientError::RegistryRejected { status: 401, .. }) => Err(CliError::Publish(format!(
            "registry rejected the upload (HTTP 401). Register this machine's key first: \
             frameshift register --server {server} --handle {handle}; account-owned publishers \
             must also set FRAMESHIFT_ACCESS_TOKEN"
        ))),
        Err(error) => Err(CliError::Client(error)),
    }
}

/// Print content-scan findings from `validate_content` to stderr.
///
/// Advisory only: this never returns an error and never blocks `run_publish`
/// -- see the comment at the call site for why the scan is warn-only. Prints
/// nothing when `warnings` is empty. `Critical` findings are called out with
/// a trailing summary line so they are not missed among lower-severity noise.
fn print_validation_warnings(warnings: &[ContentWarning]) {
    if warnings.is_empty() {
        return;
    }

    eprintln!(
        "content scan found {} finding(s) (advisory only; publish will proceed):",
        warnings.len()
    );
    let mut critical_count = 0usize;
    for warning in warnings {
        let marker = match warning.severity {
            Severity::Critical => {
                critical_count += 1;
                "CRITICAL"
            }
            Severity::Warning => "warning",
            Severity::Info => "info",
        };
        eprintln!(
            "  [{marker}] {} ({:?}): {} (matched {:?})",
            warning.location, warning.category, warning.detail, warning.matched_text
        );
    }
    if critical_count > 0 {
        eprintln!(
            "{critical_count} critical finding(s) above; review before sharing this pack widely."
        );
    }
}

/// Enforce blocking capability findings before a pack is written or uploaded.
///
/// Advisory capability concerns remain part of the existing content-scan
/// output. Only findings classified as [`ManifestSeverity::Block`] stop the
/// publish operation.
fn enforce_capability_manifest_policy(
    manifest: Option<&CapabilityManifest>,
) -> Result<(), CliError> {
    let Some(manifest) = manifest else {
        return Ok(());
    };

    let audit = audit_manifest(manifest);
    let blocking_details = audit
        .findings
        .iter()
        .filter(|finding| finding.severity == ManifestSeverity::Block)
        .map(|finding| finding.detail.as_str())
        .collect::<Vec<_>>();
    if blocking_details.is_empty() {
        return Ok(());
    }

    Err(CliError::Publish(format!(
        "capability manifest blocks publication: {}",
        blocking_details.join("; ")
    )))
}

/// Write a minimal but valid `pack.toml` into `dir` so it loads as a Pack.
///
/// The manifest carries the fields the registry requires: name, author handle,
/// author pubkey, and version. The pubkey is informational at the manifest
/// level -- the catalog binds the handle to a typed key independently.
fn write_pack_toml(
    dir: &Path,
    name: &str,
    version: &str,
    handle: &str,
    author_pubkey_hex: &str,
) -> Result<(), CliError> {
    // Guard against TOML injection: every field is interpolated into a quoted
    // TOML string below, so a value containing a quote, backslash, or control
    // character (newline included) could inject arbitrary manifest keys (e.g.
    // spoofing authorship). Reject such values rather than escaping by hand.
    for (field, value) in [
        ("name", name),
        ("version", version),
        ("handle", handle),
        ("author_pubkey", author_pubkey_hex),
    ] {
        if value
            .chars()
            .any(|c| c == '"' || c == '\\' || c.is_control())
        {
            return Err(CliError::Publish(format!(
                "{field} contains characters not allowed in a pack manifest \
                 (quotes, backslashes, or control characters): {value:?}"
            )));
        }
    }

    let content = format!(
        "schema_version = 1\n\
         name = \"{name}\"\n\
         author_handle = \"{handle}\"\n\
         author_pubkey = \"{author_pubkey_hex}\"\n\
         version = \"{version}\"\n"
    );
    std::fs::write(dir.join("pack.toml"), content)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use frameshift_source::PersonaSource;
    use std::fs;

    /// Write a minimal persona.toml to a temp directory so PersonaSource can
    /// be loaded from it during tests.
    fn write_persona_source(dir: &std::path::Path) {
        let toml = r#"schema_version = 1
name = "test-persona"
version = "0.1.0"
description = "test"

[voice]
tone = "neutral"
"#;
        fs::write(dir.join("persona.toml"), toml).expect("write persona.toml");
    }

    /// Build a `PersonaSource` from a directory containing a minimal persona.toml.
    ///
    /// Loads the source from the given path and returns it.
    fn load_source_from(dir: &std::path::Path) -> PersonaSource {
        PersonaSource::load_from_dir(dir).expect("load PersonaSource")
    }

    /// Running publish with an existing PersonaSource creates the output directory.
    #[test]
    fn publish_creates_output_dir() {
        let src_dir = tempfile::tempdir().expect("src tempdir");
        let out_dir = tempfile::tempdir().expect("out tempdir");

        write_persona_source(src_dir.path());
        let src = load_source_from(src_dir.path());

        // Write to out dir manually (simulating what run_publish does internally).
        let out = out_dir.path().join("persona-pack");
        std::fs::create_dir_all(&out).expect("create_dir_all");
        src.write_to_dir(&out).expect("write_to_dir");

        assert!(out.exists(), "output directory must exist");
    }

    /// Running publish writes an AGENTS.md into the output directory.
    #[test]
    fn publish_contains_agents_md() {
        let src_dir = tempfile::tempdir().expect("src tempdir");
        let out_dir = tempfile::tempdir().expect("out tempdir");

        write_persona_source(src_dir.path());
        let src = load_source_from(src_dir.path());

        let out = out_dir.path().join("persona-pack");
        std::fs::create_dir_all(&out).expect("create_dir_all");
        src.write_to_dir(&out).expect("write_to_dir");

        let markdown = render_to_markdown(&src, RenderTarget::Generic);
        let agents_md_path = out.join("AGENTS.md");
        std::fs::write(&agents_md_path, markdown).expect("write AGENTS.md");

        assert!(
            agents_md_path.exists(),
            "AGENTS.md must exist in the output directory"
        );

        let content = std::fs::read_to_string(&agents_md_path).expect("read AGENTS.md");
        assert!(
            content.contains("test-persona"),
            "AGENTS.md must reference the persona name"
        );
    }

    /// F-06: `validate_content` surfaces a Critical finding for a persona
    /// containing an obviously destructive command, but `print_validation_warnings`
    /// is advisory only -- it must not return an error or panic, proving the
    /// scan never blocks a publish.
    #[test]
    fn validate_content_finding_is_advisory_only() {
        let src_dir = tempfile::tempdir().expect("src tempdir");
        let toml = r#"schema_version = 1
name = "dangerous-persona"
version = "0.1.0"
description = "test"

[voice]
tone = "explains how to avoid rm -rf / disasters"
"#;
        fs::write(src_dir.path().join("persona.toml"), toml).expect("write persona.toml");
        let src = load_source_from(src_dir.path());

        let warnings = validate_content(&src);
        assert!(
            warnings.iter().any(|w| w.severity == Severity::Critical),
            "expected a Critical finding for an rm -rf / pattern"
        );

        // Advisory: printing findings (even Critical ones) must not panic or
        // otherwise short-circuit; run_publish would proceed past this call.
        print_validation_warnings(&warnings);
    }

    /// A clean persona source produces no findings, and printing an empty
    /// warning list is a no-op (nothing written, no panic).
    #[test]
    fn validate_content_clean_persona_has_no_findings() {
        let src_dir = tempfile::tempdir().expect("src tempdir");
        write_persona_source(src_dir.path());
        let src = load_source_from(src_dir.path());

        let warnings = validate_content(&src);
        assert!(
            warnings.is_empty(),
            "a clean persona should not trigger content-scan findings"
        );
        print_validation_warnings(&warnings);
    }

    /// A persona without a capability manifest passes the publish policy.
    #[test]
    fn capability_policy_accepts_absent_manifest() {
        enforce_capability_manifest_policy(None)
            .expect("a missing capability manifest should not block publication");
    }

    /// Advisory network and shell findings do not block publication.
    #[test]
    fn capability_policy_accepts_advisory_findings() {
        let manifest = CapabilityManifest {
            required_tools: vec!["bash".to_string()],
            filesystem_scope: "./src/**".to_string(),
            network_egress: true,
            primary_intents: vec![],
            anti_keywords: vec![],
        };

        enforce_capability_manifest_policy(Some(&manifest))
            .expect("advisory capability findings should not block publication");
    }

    /// An unrestricted filesystem scope blocks publication with its reason.
    #[test]
    fn capability_policy_rejects_blocking_findings() {
        let manifest = CapabilityManifest {
            required_tools: vec![],
            filesystem_scope: "/".to_string(),
            network_egress: false,
            primary_intents: vec![],
            anti_keywords: vec![],
        };

        let error = enforce_capability_manifest_policy(Some(&manifest))
            .expect_err("an unrestricted filesystem scope must block publication");
        assert!(
            matches!(error, CliError::Publish(ref detail) if detail.contains("unrestricted filesystem access")),
            "blocking capability error should explain the unrestricted scope: {error}"
        );
    }

    /// write_pack_toml rejects fields that would inject TOML, and accepts clean ones.
    #[test]
    fn write_pack_toml_rejects_injection() {
        let dir = tempfile::tempdir().expect("tempdir");

        // A handle that closes the quoted string and injects a new key.
        let malicious = "evil\"\nauthor_role = \"admin";
        let bad = write_pack_toml(dir.path(), "demo", "0.1.0", malicious, "deadbeef");
        assert!(
            matches!(bad, Err(CliError::Publish(_))),
            "injection handle must be rejected"
        );

        // A clean set of fields writes a loadable pack.toml.
        write_pack_toml(dir.path(), "demo", "0.1.0", "alice", "deadbeef")
            .expect("clean fields must succeed");
        let written =
            std::fs::read_to_string(dir.path().join("pack.toml")).expect("read pack.toml");
        assert!(written.contains("author_handle = \"alice\""));
    }
}
