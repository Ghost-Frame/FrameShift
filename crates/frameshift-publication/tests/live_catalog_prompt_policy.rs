//! Opt-in exact-policy audit for an extracted live catalog snapshot.

use frameshift_publication::{validate_directory, FindingSeverity};
use std::fs;
use std::path::PathBuf;

/// Audit every immediate pack directory supplied by the operator.
///
/// The test is ignored because it consumes a separately captured network
/// snapshot. Run the compiled test binary with
/// `FRAMESHIFT_LIVE_CATALOG_AUDIT_ROOT` and
/// `FRAMESHIFT_LIVE_CATALOG_EXPECTED_PACKS` set to make catalog completeness
/// part of the assertion.
#[test]
#[ignore = "requires an extracted live catalog snapshot"]
fn live_catalog_latest_archives_have_no_blocking_prompt_findings() {
    let root = PathBuf::from(
        std::env::var("FRAMESHIFT_LIVE_CATALOG_AUDIT_ROOT")
            .expect("FRAMESHIFT_LIVE_CATALOG_AUDIT_ROOT must name the extracted snapshot"),
    );
    let expected_pack_count: usize = std::env::var("FRAMESHIFT_LIVE_CATALOG_EXPECTED_PACKS")
        .expect("FRAMESHIFT_LIVE_CATALOG_EXPECTED_PACKS must be set")
        .parse()
        .expect("expected pack count must be an integer");
    let mut pack_roots = fs::read_dir(&root)
        .expect("read catalog snapshot root")
        .map(|entry| entry.expect("read catalog snapshot entry").path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    pack_roots.sort();

    assert_eq!(
        pack_roots.len(),
        expected_pack_count,
        "catalog snapshot is incomplete"
    );

    let mut blocking = Vec::new();
    for pack_root in pack_roots {
        let report = validate_directory(&pack_root).expect("validate extracted live pack");
        for finding in report.findings {
            if finding.severity == FindingSeverity::Error && finding.code.starts_with("prompt.") {
                blocking.push((
                    pack_root
                        .file_name()
                        .expect("pack directory name")
                        .to_string_lossy()
                        .into_owned(),
                    finding.code,
                    finding.path,
                ));
            }
        }
    }

    assert!(
        blocking.is_empty(),
        "live catalog contains blocking prompt-policy findings: {blocking:?}"
    );
}
