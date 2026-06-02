//! CLI handler for telemetry subcommands.

use clap::{Args, Subcommand};

use crate::util::CliError;

/// Arguments for the telemetry subcommand group.
#[derive(Debug, Args)]
pub struct TelemetryArgs {
    /// Telemetry action to perform.
    #[command(subcommand)]
    pub action: TelemetryAction,
}

/// Telemetry actions.
#[derive(Debug, Subcommand)]
pub enum TelemetryAction {
    /// Flush one persona's opt-in telemetry to the registry.
    Flush(FlushArgs),
}

/// Arguments for `telemetry flush`.
#[derive(Debug, Args)]
pub struct FlushArgs {
    /// Persona name whose telemetry should be sent.
    #[arg(long)]
    pub persona: String,
}

/// Execute the telemetry subcommand group.
pub fn run(args: TelemetryArgs) -> Result<(), CliError> {
    match args.action {
        TelemetryAction::Flush(args) => run_flush(args),
    }
}

/// Flush one persona's telemetry when the project has opted in.
fn run_flush(args: FlushArgs) -> Result<(), CliError> {
    let client = frameshift_client::Client::with_default_data_root()?;
    let project_root = std::env::current_dir().map_err(|error| {
        CliError::Growth(format!("cannot determine current directory: {error}"))
    })?;
    let config = client.project_config(&project_root)?;
    if !config.telemetry_opt_in {
        println!("telemetry disabled (opt-in off)");
        return Ok(());
    }

    let session = std::env::var("FRAMESHIFT_SESSION")
        .map_err(|_| CliError::Growth("FRAMESHIFT_SESSION not set".to_string()))?;
    let sent = client
        .send_telemetry_for_persona(&project_root, &args.persona, &session)
        .map_err(CliError::Client)?;
    println!("sent {sent} telemetry signal(s) for {}", args.persona);
    Ok(())
}
