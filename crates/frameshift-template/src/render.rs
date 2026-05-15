//! Template rendering: walks a parsed [`Template`]'s segments and produces a `String`.

use std::collections::BTreeMap;

use crate::parse::{Segment, Template};

/// Render a [`Template`] to a `String`.
///
/// - `variables`: token name → replacement value. Tokens absent from the map
///   are emitted as `{{name}}` so they remain visible for debugging.
/// - `overlays`: section ID → replacement content. Sections absent from the
///   map keep their default content. Section markers are always preserved in
///   the output.
pub(crate) fn render(
    template: &Template,
    variables: &BTreeMap<String, String>,
    overlays: &BTreeMap<String, String>,
) -> String {
    let mut output = String::new();

    for segment in &template.segments {
        match segment {
            Segment::Literal(text) => {
                output.push_str(text);
            }

            Segment::Token(name) => {
                match variables.get(name.as_str()) {
                    Some(value) => output.push_str(value),
                    None => {
                        // Leave unreplaced tokens visible for debugging.
                        output.push_str("{{");
                        output.push_str(name);
                        output.push_str("}}");
                    }
                }
            }

            Segment::Section {
                id,
                default_content,
            } => {
                // The section open marker has already been emitted as a
                // preceding Literal segment by the parser. We emit only the
                // content here. The close marker will arrive as the following
                // Literal segment.
                match overlays.get(id.as_str()) {
                    Some(replacement) => output.push_str(replacement),
                    None => output.push_str(default_content),
                }
            }
        }
    }

    output
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::Template;

    fn vars(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn overlays(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        vars(pairs)
    }

    #[test]
    fn all_tokens_substituted() {
        let tmpl = Template::parse("Hello {{name}}, you are {{role}}.\n").unwrap();
        let out = tmpl.render(
            &vars(&[("name", "Alice"), ("role", "admin")]),
            &overlays(&[]),
        );
        assert_eq!(out, "Hello Alice, you are admin.\n");
    }

    #[test]
    fn missing_tokens_left_as_placeholder() {
        let tmpl = Template::parse("Hi {{name}} and {{other}}.\n").unwrap();
        let out = tmpl.render(&vars(&[("name", "Bob")]), &overlays(&[]));
        assert_eq!(out, "Hi Bob and {{other}}.\n");
    }

    #[test]
    fn section_overlay_replaces_default() {
        let input = "<!-- section:intro -->\nDefault content.\n<!-- /section -->\n";
        let tmpl = Template::parse(input).unwrap();
        let out = tmpl.render(&vars(&[]), &overlays(&[("intro", "Custom content.\n")]));
        assert_eq!(
            out,
            "<!-- section:intro -->\nCustom content.\n<!-- /section -->\n"
        );
    }

    #[test]
    fn section_without_overlay_keeps_default() {
        let input = "<!-- section:intro -->\nDefault content.\n<!-- /section -->\n";
        let tmpl = Template::parse(input).unwrap();
        let out = tmpl.render(&vars(&[]), &overlays(&[]));
        assert_eq!(out, input);
    }

    #[test]
    fn tokens_and_sections_combined() {
        let input =
            "Author: {{name}}\n<!-- section:bio -->\nDefault bio.\n<!-- /section -->\nEnd.\n";
        let tmpl = Template::parse(input).unwrap();
        let out = tmpl.render(
            &vars(&[("name", "Zara")]),
            &overlays(&[("bio", "Custom bio.\n")]),
        );
        assert_eq!(
            out,
            "Author: Zara\n<!-- section:bio -->\nCustom bio.\n<!-- /section -->\nEnd.\n"
        );
    }

    #[test]
    fn empty_variables_and_overlays_round_trip() {
        let input = "Plain text, no tokens.\n";
        let tmpl = Template::parse(input).unwrap();
        assert_eq!(tmpl.render(&vars(&[]), &overlays(&[])), input);
    }
}
