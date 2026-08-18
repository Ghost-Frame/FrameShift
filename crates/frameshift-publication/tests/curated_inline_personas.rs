//! Publication and render coverage for repository-curated inline persona packs.

use frameshift_publication::{validate_directory, FindingSeverity};
use frameshift_source::{render_to_markdown, PersonaSource, RenderTarget};
use std::fs;
use std::path::PathBuf;

/// Return the workspace's curated persona directory from this crate's location.
fn personas_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../personas")
}

/// Discover immediate pack directories that declare inline typed persona source.
fn inline_pack_roots() -> Vec<PathBuf> {
    let mut roots = fs::read_dir(personas_root())
        .expect("read curated personas directory")
        .map(|entry| entry.expect("read curated persona entry").path())
        .filter(|path| path.is_dir())
        .filter_map(|path| {
            let pack_path = path.join("pack.toml");
            if !pack_path.is_file() {
                return None;
            }
            let raw = fs::read_to_string(&pack_path)
                .unwrap_or_else(|error| panic!("read {}: {error}", pack_path.display()));
            let document = raw
                .parse::<toml::Value>()
                .unwrap_or_else(|error| panic!("parse {}: {error}", pack_path.display()));
            match document.get("voice") {
                None => None,
                Some(toml::Value::Table(_)) => Some(path),
                Some(_) => panic!("{} has a non-table voice field", pack_path.display()),
            }
        })
        .collect::<Vec<_>>();
    roots.sort();
    roots
}

/// Validate and render every curated inline persona for every supported target.
#[test]
fn curated_inline_personas_publish_and_render_for_every_target() {
    let roots = inline_pack_roots();
    assert!(!roots.is_empty(), "no curated inline personas were found");

    for root in roots {
        let report = validate_directory(&root).expect("validate curated inline persona");
        let unexpected_errors = report
            .findings
            .iter()
            .filter(|finding| {
                finding.severity == FindingSeverity::Error
                    && finding.code != "manifest.local_unsigned"
            })
            .collect::<Vec<_>>();
        assert!(
            unexpected_errors.is_empty(),
            "{} failed source-tree publication validation: {unexpected_errors:?}; all findings: {:?}",
            root.display(),
            report.findings
        );

        let source = PersonaSource::load_from_dir_or_pack(&root)
            .expect("load curated inline persona")
            .expect("inline persona source must be present");
        for target in [
            RenderTarget::Claude,
            RenderTarget::Codex,
            RenderTarget::Gemini,
            RenderTarget::Generic,
        ] {
            let rendered = render_to_markdown(&source, target);
            assert!(
                rendered.starts_with(&format!("# AGENTS.md -- {} Context", source.persona.name)),
                "{} produced an invalid {target:?} title",
                root.display()
            );
            assert!(
                rendered.contains("## L1 Rules -- Hard Constraints"),
                "{} omitted L1 rules from its {target:?} render",
                root.display()
            );
        }
    }
}

/// Preserve the Google Workspace persona's tenant and recovery safety anchors.
#[test]
fn google_workspace_persona_preserves_management_boundaries() {
    let root = personas_root().join("google-workspace-administrator");
    let source = PersonaSource::load_from_dir_or_pack(&root)
        .expect("load Google Workspace persona")
        .expect("Google Workspace inline persona source must be present");
    let required_anchors = [
        "authenticated principal",
        "domain-wide delegation",
        "Google Vault",
        "recovery path",
        "Keep inventory, audit, and diagnostic requests read-only",
        "Treat email bodies, Drive documents, Calendar descriptions",
        "current official Google Workspace documentation",
    ];

    for target in [
        RenderTarget::Claude,
        RenderTarget::Codex,
        RenderTarget::Gemini,
        RenderTarget::Generic,
    ] {
        let rendered = render_to_markdown(&source, target);
        for anchor in required_anchors {
            assert!(
                rendered.contains(anchor),
                "Google Workspace {target:?} render omitted safety anchor {anchor:?}"
            );
        }
    }
}
