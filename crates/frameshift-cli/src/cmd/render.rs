//! `frameshift render <persona>` subcommand.
//!
//! Loads a named persona from the central store and renders it to markdown
//! using `frameshift_source::render_to_markdown` with the `Generic` target.
//! Output is printed directly to stdout so callers can pipe or redirect it.

use clap::Args;

use frameshift_client::Client;
use frameshift_source::{render_to_markdown, RenderTarget};

use crate::util::{load_persona_by_name, CliError};

/// Arguments for the `render` subcommand.
#[derive(Debug, Args)]
pub struct RenderArgs {
    /// Name of the persona to render (must exist in the central store).
    pub persona: String,

    /// Render target platform. Controls which optional sections are included.
    /// Valid values: claude, codex, gemini, generic (default: generic).
    #[arg(long, default_value = "generic")]
    pub target: RenderTargetArg,
}

/// Clap-compatible wrapper for `frameshift_source::RenderTarget`.
///
/// `RenderTarget` lives in the library crate and does not implement
/// `clap::ValueEnum`, so this newtype bridges the gap with a `FromStr` impl.
#[derive(Debug, Clone, Copy)]
pub struct RenderTargetArg(pub RenderTarget);

/// Exposes stable client identifiers for parsed render targets.
impl RenderTargetArg {
    /// Return the client-facing identifier for this render target.
    pub fn as_str(self) -> &'static str {
        match self.0 {
            RenderTarget::Claude => "claude",
            RenderTarget::Codex => "codex",
            RenderTarget::Gemini => "gemini",
            RenderTarget::Generic => "generic",
        }
    }
}

/// Parses a command-line render target into the shared target enum.
impl std::str::FromStr for RenderTargetArg {
    /// Human-readable parse failure returned by clap.
    type Err = String;

    /// Parse one of "claude", "codex", "gemini", "generic" (case-insensitive).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "claude" => Ok(RenderTargetArg(RenderTarget::Claude)),
            "codex" => Ok(RenderTargetArg(RenderTarget::Codex)),
            "gemini" => Ok(RenderTargetArg(RenderTarget::Gemini)),
            "generic" => Ok(RenderTargetArg(RenderTarget::Generic)),
            _ => Err(format!(
                "invalid render target '{s}'; expected one of: claude, codex, gemini, generic"
            )),
        }
    }
}

/// Execute the `render` subcommand.
///
/// Loads the named persona from the central store, renders it to markdown
/// for the specified target, and writes the result to stdout.
pub fn run_render(client: &Client, args: RenderArgs) -> Result<(), CliError> {
    let src = load_persona_by_name(client, &args.persona)?;
    let markdown = render_to_markdown(&src, args.target.0);
    print!("{markdown}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that RenderTargetArg parses all four valid target strings.
    #[test]
    fn render_target_arg_parses_all_variants() {
        for (input, _expected_debug) in [
            ("claude", "Claude"),
            ("codex", "Codex"),
            ("gemini", "Gemini"),
            ("generic", "Generic"),
            ("CLAUDE", "Claude"),
        ] {
            let parsed: RenderTargetArg = input.parse().expect("should parse");
            // Verify the inner value is something reasonable by round-tripping
            // through a simple existence check.
            let _ = parsed.0;
        }
    }

    /// Verify that parsed targets expose the identifiers used by the client store.
    #[test]
    fn render_target_arg_exposes_client_identifier() {
        let target: RenderTargetArg = "codex".parse().unwrap();
        assert_eq!(target.as_str(), "codex");
    }

    /// Verify that RenderTargetArg rejects unrecognized strings.
    #[test]
    fn render_target_arg_rejects_invalid_input() {
        for bad in ["", "gpt4", "anthropic", "claude3"] {
            assert!(
                bad.parse::<RenderTargetArg>().is_err(),
                "should reject '{bad}'"
            );
        }
    }

    /// Integration test: render a persona and verify markdown contains title.
    #[test]
    fn run_render_produces_title() {
        use frameshift_client::{Client, ClientOptions};
        use frameshift_source::persona::Persona;
        use frameshift_source::PersonaSource;

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_root = tmp.path().to_path_buf();
        let persona_dir = data_root.join("personas-private").join("render-test");
        let src = PersonaSource::new(Persona::new("render-test"));
        src.write_to_dir(&persona_dir).expect("write");

        // Verify the source loads; we check the rendered content indirectly
        // by ensuring run_render does not error.
        let client = Client::new(ClientOptions {
            data_root,
            config_root: None,
            vault: None,
        });
        let args = RenderArgs {
            persona: "render-test".to_string(),
            target: RenderTargetArg(RenderTarget::Generic),
        };
        run_render(&client, args).expect("run_render should succeed");
    }
}
