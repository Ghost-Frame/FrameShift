//! CLI handler for the `frameshift grow <append|log|summary>` subcommand.
//!
//! `append` writes to the persona's growth log (both the legacy markdown file
//! and the structured JSONL file, via `frameshift_growth::append`). `log` and
//! `summary` are the read surfaces over the structured JSONL data, backed by
//! `frameshift_growth::recent_entries` and `frameshift_growth::summarize`
//! respectively.

use crate::util::CliError;
use clap::Args;
use frameshift_growth::Scope;

/// Arguments for the grow subcommand.
#[derive(Debug, Args)]
pub struct GrowArgs {
    /// Growth action to perform.
    #[command(subcommand)]
    pub action: GrowAction,
}

/// Growth actions.
#[derive(Debug, clap::Subcommand)]
pub enum GrowAction {
    /// Append a growth entry for a persona.
    Append(AppendArgs),

    /// Show the most recent structured growth entries for a persona.
    Log(LogArgs),

    /// Print an algorithmic summary of a persona's growth entries.
    Summary(SummaryArgs),
}

/// Arguments for grow append.
#[derive(Debug, Args)]
pub struct AppendArgs {
    /// Name of the persona to append growth to.
    #[arg(long)]
    pub persona: String,

    /// Text content to append.
    #[arg(long)]
    pub text: String,

    /// Write a structured global-scope entry instead of a project-scope one.
    ///
    /// When set, this writes ONLY a structured `Scope::Global` entry via
    /// `frameshift_growth::append_global` to the persona's global
    /// growth.jsonl (`<data_root>/personas/<name>/growth.jsonl`). The legacy
    /// markdown growth.md append stays project-scoped and is skipped
    /// entirely in this mode -- there is no global markdown growth file.
    #[arg(long)]
    pub global: bool,
}

/// Arguments for grow log.
#[derive(Debug, Args)]
pub struct LogArgs {
    /// Name of the persona whose growth log to read.
    #[arg(long)]
    pub persona: String,

    /// Maximum number of entries to print, most recent first.
    #[arg(long, default_value_t = 10)]
    pub limit: usize,
}

/// Arguments for grow summary.
#[derive(Debug, Args)]
pub struct SummaryArgs {
    /// Name of the persona whose growth log to summarize.
    #[arg(long)]
    pub persona: String,

    /// Scope of entries to summarize.
    #[arg(long, value_enum, default_value = "project")]
    pub scope: ScopeArg,
}

/// CLI-facing mirror of `frameshift_growth::Scope` so `clap::ValueEnum` can
/// be derived without adding a `clap` dependency to the growth crate.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ScopeArg {
    /// Learning specific to the current project.
    Project,
    /// Universal learning applicable across projects.
    Global,
}

impl From<ScopeArg> for Scope {
    /// Convert the CLI-facing scope argument into the growth crate's `Scope`.
    fn from(arg: ScopeArg) -> Self {
        match arg {
            ScopeArg::Project => Scope::Project,
            ScopeArg::Global => Scope::Global,
        }
    }
}

/// Execute the grow subcommand.
pub fn run(args: GrowArgs) -> Result<(), CliError> {
    match args.action {
        GrowAction::Append(append_args) => run_append(append_args),
        GrowAction::Log(log_args) => run_log(log_args),
        GrowAction::Summary(summary_args) => run_summary(summary_args),
    }
}

/// Execute grow append.
///
/// Default (no `--global`): writes a timestamped entry to the persona's
/// growth.md and structured growth.jsonl (via `frameshift_growth::append`'s
/// dual-write), both project-scoped.
///
/// With `--global`: writes ONLY a structured `Scope::Global` entry via
/// `frameshift_growth::append_global`. The legacy markdown append is skipped
/// entirely -- there is no global markdown growth file.
fn run_append(args: AppendArgs) -> Result<(), CliError> {
    let client = frameshift_client::Client::with_default_data_root()?;
    let project_root = std::env::current_dir()
        .map_err(|e| CliError::Growth(format!("cannot determine current directory: {}", e)))?;
    let project_id = client.project_id(&project_root)?;

    if args.global {
        frameshift_growth::append_global(
            client.data_root(),
            &project_id,
            &args.persona,
            &args.text,
        )
        .map_err(|e| CliError::Growth(e.to_string()))?;
        println!(
            "Global growth entry appended for persona '{}'.",
            args.persona
        );
    } else {
        frameshift_growth::append(client.data_root(), &project_id, &args.persona, &args.text)
            .map_err(|e| CliError::Growth(e.to_string()))?;
        println!("Growth entry appended for persona '{}'.", args.persona);
    }
    Ok(())
}

/// Execute grow log -- print the persona's most recent structured growth
/// entries (project and global scope combined, newest first).
fn run_log(args: LogArgs) -> Result<(), CliError> {
    let client = frameshift_client::Client::with_default_data_root()?;
    let project_root = std::env::current_dir()
        .map_err(|e| CliError::Growth(format!("cannot determine current directory: {}", e)))?;
    let project_id = client.project_id(&project_root)?;

    let entries = frameshift_growth::recent_entries(
        client.data_root(),
        &project_id,
        &args.persona,
        args.limit,
    )
    .map_err(|e| CliError::Growth(e.to_string()))?;

    print_entries(&args.persona, &entries);
    Ok(())
}

/// Print a human-readable rendering of `entries` for `persona`, or a
/// "no entries" message when the log is empty.
fn print_entries(persona: &str, entries: &[frameshift_growth::GrowthEntry]) {
    if entries.is_empty() {
        println!("no growth entries recorded for persona '{persona}'.");
        return;
    }

    for entry in entries {
        let scope = match entry.scope {
            Scope::Project => "project",
            Scope::Global => "global",
        };
        let mut tags = vec![scope.to_string()];
        if entry.auto_selected {
            tags.push("auto-selected".to_string());
        }
        if let Some(intent) = &entry.intent {
            tags.push(format!("intent={intent}"));
        }
        println!("{} [{}]", entry.ts, tags.join(", "));
        println!("  {}", entry.text);
    }
}

/// Execute grow summary -- print the algorithmic summary of a persona's
/// growth entries for the requested scope.
fn run_summary(args: SummaryArgs) -> Result<(), CliError> {
    let client = frameshift_client::Client::with_default_data_root()?;
    let project_root = std::env::current_dir()
        .map_err(|e| CliError::Growth(format!("cannot determine current directory: {}", e)))?;
    let project_id = client.project_id(&project_root)?;

    let summary = frameshift_growth::summarize(
        client.data_root(),
        &project_id,
        &args.persona,
        args.scope.into(),
    )
    .map_err(|e| CliError::Growth(e.to_string()))?;

    if summary.is_empty() {
        println!(
            "no growth entries to summarize for persona '{}'.",
            args.persona
        );
    } else {
        println!("{summary}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use frameshift_growth::GrowthEntry;

    /// Helper command that hosts `GrowAction` so clap can parse a full
    /// `frameshift grow <action> ...` invocation without depending on the
    /// real top-level `Command` enum.
    #[derive(Debug, Parser)]
    #[command(name = "frameshift", no_binary_name = true)]
    struct TestCli {
        #[command(subcommand)]
        action: GrowAction,
    }

    /// `grow append --persona <p> --text <t>` parses both required flags,
    /// leaving `--global` at its default of `false`.
    #[test]
    fn parse_append_with_persona_and_text() {
        let parsed = TestCli::try_parse_from(["append", "--persona", "rust", "--text", "hi"])
            .expect("append should parse");
        match parsed.action {
            GrowAction::Append(args) => {
                assert_eq!(args.persona, "rust");
                assert_eq!(args.text, "hi");
                assert!(!args.global);
            }
            other => panic!("expected Append, got {other:?}"),
        }
    }

    /// `grow append --persona <p> --text <t> --global` sets the `global` flag.
    #[test]
    fn parse_append_with_global_flag() {
        let parsed =
            TestCli::try_parse_from(["append", "--persona", "rust", "--text", "hi", "--global"])
                .expect("append --global should parse");
        match parsed.action {
            GrowAction::Append(args) => assert!(args.global),
            other => panic!("expected Append, got {other:?}"),
        }
    }

    /// `grow log --persona <p>` parses with the default limit of 10.
    #[test]
    fn parse_log_defaults_limit_to_ten() {
        let parsed =
            TestCli::try_parse_from(["log", "--persona", "rust"]).expect("log should parse");
        match parsed.action {
            GrowAction::Log(args) => {
                assert_eq!(args.persona, "rust");
                assert_eq!(args.limit, 10);
            }
            other => panic!("expected Log, got {other:?}"),
        }
    }

    /// `grow log --persona <p> --limit <n>` overrides the default limit.
    #[test]
    fn parse_log_with_explicit_limit() {
        let parsed = TestCli::try_parse_from(["log", "--persona", "rust", "--limit", "3"])
            .expect("log should parse");
        match parsed.action {
            GrowAction::Log(args) => assert_eq!(args.limit, 3),
            other => panic!("expected Log, got {other:?}"),
        }
    }

    /// `grow summary --persona <p>` parses with the default scope of project.
    #[test]
    fn parse_summary_defaults_scope_to_project() {
        let parsed = TestCli::try_parse_from(["summary", "--persona", "rust"])
            .expect("summary should parse");
        match parsed.action {
            GrowAction::Summary(args) => assert!(matches!(args.scope, ScopeArg::Project)),
            other => panic!("expected Summary, got {other:?}"),
        }
    }

    /// `grow summary --persona <p> --scope global` selects the global scope.
    #[test]
    fn parse_summary_with_explicit_global_scope() {
        let parsed = TestCli::try_parse_from(["summary", "--persona", "rust", "--scope", "global"])
            .expect("summary should parse");
        match parsed.action {
            GrowAction::Summary(args) => assert!(matches!(args.scope, ScopeArg::Global)),
            other => panic!("expected Summary, got {other:?}"),
        }
    }

    /// `print_entries` reports a friendly message when there are no entries.
    #[test]
    fn print_entries_handles_empty_list() {
        // No stdout capture available in this harness; this exercises the
        // empty branch without panicking, which is the behavior under test.
        print_entries("rust", &[]);
    }

    /// `print_entries` does not panic on a populated entry list covering
    /// every optional field (auto_selected, intent, both scopes).
    #[test]
    fn print_entries_handles_populated_list() {
        let entries = vec![
            GrowthEntry {
                ts: "2026-01-01T00:00:00Z".to_string(),
                session: "1".to_string(),
                project_id: "p".to_string(),
                persona: "rust".to_string(),
                auto_selected: true,
                task: Some("fix bug".to_string()),
                intent: Some("debugging".to_string()),
                text: "learned something".to_string(),
                scope: Scope::Project,
            },
            GrowthEntry {
                ts: "2026-01-02T00:00:00Z".to_string(),
                session: "2".to_string(),
                project_id: "p".to_string(),
                persona: "rust".to_string(),
                auto_selected: false,
                task: None,
                intent: None,
                text: "a universal lesson".to_string(),
                scope: Scope::Global,
            },
        ];
        print_entries("rust", &entries);
    }
}
