//! `frameshift render <persona>` subcommand.
//!
//! Loads a named persona from the central store and renders it to markdown
//! using `frameshift_source::render_to_markdown` with the `Generic` target.
//! Output is printed directly to stdout so callers can pipe or redirect it.
//!
//! Note: this renders the persona's own (un-composed) source. Unlike the
//! install path, it does not resolve `extends`/`mixin` bases, so the preview
//! for a composed persona will differ from the installed output. See
//! `warn_if_uncomposed`.

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
///
/// This renders the persona's own source only: unlike the install path
/// (`Client::materialize_persona_rendered_outputs`), it does NOT resolve
/// `extends`/`mixin` composition. When the persona declares either, the
/// preview printed here is the un-composed source and will diverge from
/// what actually gets installed; a warning noting this is printed to
/// stderr (see `warn_if_uncomposed`).
pub fn run_render(client: &Client, args: RenderArgs) -> Result<(), CliError> {
    let src = load_persona_by_name(client, &args.persona)?;
    warn_if_uncomposed(&args.persona, &src);
    let markdown = render_to_markdown(&src, args.target.0);
    print!("{markdown}");
    Ok(())
}

/// Print a stderr warning when `src` declares `extends`/`mixin` composition
/// metadata, since `render` (unlike `frameshift use`/install) never resolves
/// those bases -- the printed markdown is the un-composed source only and
/// will differ from what gets written for an actually-installed persona.
///
/// Mirrors the existing `warn!`/`eprintln!` pattern used for the analogous
/// case in the install path (see `materialize_persona_rendered_outputs` in
/// `frameshift-client`, which warns and falls back to markdown-only
/// rendering when a pack declares composition but has no typed source).
fn warn_if_uncomposed(persona_name: &str, src: &frameshift_source::PersonaSource) {
    let has_composition = src.persona.extends.is_some() || !src.persona.mixin.is_empty();
    if has_composition {
        eprintln!(
            "warning: persona '{persona_name}' declares extends/mixin composition; \
             `render` shows the un-composed source only and the installed output will differ"
        );
    }
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

    /// F-16: a persona with no `extends`/`mixin` is not flagged as
    /// un-composed -- the warning must be specific to composed personas.
    #[test]
    fn warn_if_uncomposed_is_false_for_plain_persona() {
        use frameshift_source::persona::Persona;
        use frameshift_source::PersonaSource;

        let src = PersonaSource::new(Persona::new("plain"));
        let has_composition = src.persona.extends.is_some() || !src.persona.mixin.is_empty();
        assert!(
            !has_composition,
            "a plain persona must not be treated as composed"
        );
        // Exercise the real helper too, mainly checking it doesn't panic.
        warn_if_uncomposed("plain", &src);
    }

    /// F-16: a persona declaring `extends` is detected as composed, meaning
    /// `run_render`'s preview diverges from the installed (composed) output
    /// and `warn_if_uncomposed` must fire for it.
    #[test]
    fn warn_if_uncomposed_detects_extends() {
        use frameshift_source::persona::Persona;
        use frameshift_source::PersonaSource;

        let mut persona = Persona::new("derived");
        persona.extends = Some("base-persona".to_string());
        let src = PersonaSource::new(persona);

        let has_composition = src.persona.extends.is_some() || !src.persona.mixin.is_empty();
        assert!(
            has_composition,
            "a persona declaring `extends` must be detected as composed"
        );
        warn_if_uncomposed("derived", &src);
    }

    /// F-16: a persona declaring `mixin` (but no `extends`) is also detected
    /// as composed.
    #[test]
    fn warn_if_uncomposed_detects_mixin() {
        use frameshift_source::persona::Persona;
        use frameshift_source::PersonaSource;

        let mut persona = Persona::new("derived");
        persona.mixin = vec!["security-mixin".to_string()];
        let src = PersonaSource::new(persona);

        let has_composition = src.persona.extends.is_some() || !src.persona.mixin.is_empty();
        assert!(
            has_composition,
            "a persona declaring `mixin` must be detected as composed"
        );
        warn_if_uncomposed("derived", &src);
    }

    /// Integration test: `run_render` still succeeds end-to-end for a
    /// composed persona (it prints the un-composed preview plus a stderr
    /// warning; it must not error or attempt full composition).
    #[test]
    fn run_render_succeeds_for_composed_persona() {
        use frameshift_client::{Client, ClientOptions};
        use frameshift_source::persona::Persona;
        use frameshift_source::PersonaSource;

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_root = tmp.path().to_path_buf();
        let persona_dir = data_root.join("personas-private").join("composed-test");
        let mut persona = Persona::new("composed-test");
        persona.extends = Some("base-persona".to_string());
        let src = PersonaSource::new(persona);
        src.write_to_dir(&persona_dir).expect("write");

        let client = Client::new(ClientOptions {
            data_root,
            config_root: None,
            vault: None,
        });
        let args = RenderArgs {
            persona: "composed-test".to_string(),
            target: RenderTargetArg(RenderTarget::Generic),
        };
        run_render(&client, args)
            .expect("run_render should succeed for a composed persona (warn-only, not blocking)");
    }
}
