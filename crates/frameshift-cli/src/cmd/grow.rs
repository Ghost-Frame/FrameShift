//! CLI handler for the `grow append` subcommand.

use crate::util::CliError;
use clap::Args;

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
}

/// Execute the grow subcommand.
pub fn run(args: GrowArgs) -> Result<(), CliError> {
    match args.action {
        GrowAction::Append(append_args) => run_append(append_args),
    }
}

/// Execute grow append -- write a timestamped entry to the persona's growth.md.
fn run_append(args: AppendArgs) -> Result<(), CliError> {
    let client = frameshift_client::Client::with_default_data_root()?;
    let project_root = std::env::current_dir()
        .map_err(|e| CliError::Growth(format!("cannot determine current directory: {}", e)))?;
    let project_id = client.project_id(&project_root)?;

    frameshift_growth::append(client.data_root(), &project_id, &args.persona, &args.text)
        .map_err(|e| CliError::Growth(e.to_string()))?;

    println!("Growth entry appended for persona '{}'.", args.persona);
    Ok(())
}
