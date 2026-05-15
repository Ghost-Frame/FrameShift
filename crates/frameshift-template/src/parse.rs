//! Template parsing: converts raw text into a [`Template`] composed of [`Segment`]s.

use std::collections::BTreeMap;

use crate::error::TemplateError;

// ── Regex-like constants for marker detection ───────────────────────────────

/// Prefix that opens a section marker, e.g. `<!-- section:`.
const SECTION_OPEN_PREFIX: &str = "<!-- section:";
/// The closing portion of a section open marker.
const SECTION_OPEN_SUFFIX: &str = " -->";
/// The exact text (trimmed) that closes a section.
const SECTION_CLOSE_MARKER: &str = "<!-- /section -->";

// ── Segment ─────────────────────────────────────────────────────────────────

/// One parsed unit of a template document.
///
/// A template is a flat sequence of segments. The renderer walks this sequence
/// and emits output for each segment in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Segment {
    /// A verbatim run of text with no placeholders.
    Literal(String),

    /// A `{{name}}` token placeholder. The inner `String` is the trimmed name.
    Token(String),

    /// A `<!-- section:ID --> ... <!-- /section -->` block.
    Section {
        /// The section identifier.
        id: String,
        /// The default content between the section markers, **including** the
        /// trailing newline that precedes `<!-- /section -->`, if any.
        default_content: String,
    },
}

// ── Template ─────────────────────────────────────────────────────────────────

/// A parsed template document ready for rendering.
///
/// Templates are immutable after parsing. To obtain a rendered string call
/// [`Template::render`].
#[derive(Debug, Clone)]
pub struct Template {
    /// The ordered list of segments that make up the template.
    pub(crate) segments: Vec<Segment>,
}

impl Template {
    /// Parse a raw template string into a [`Template`].
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError`] when the template is structurally invalid:
    /// unclosed sections, nested sections, unmatched close markers, empty token
    /// names, or invalid token names.
    pub fn parse(content: &str) -> Result<Self, TemplateError> {
        let segments = parse_segments(content)?;
        Ok(Self { segments })
    }

    /// Return the names of all token placeholders found in this template.
    ///
    /// Each name appears once per unique occurrence. Order is document order,
    /// and duplicates are deduplicated.
    pub fn tokens(&self) -> Vec<&str> {
        let mut seen = std::collections::BTreeSet::new();
        let mut result = Vec::new();
        for seg in &self.segments {
            if let Segment::Token(name) = seg {
                if seen.insert(name.as_str()) {
                    result.push(name.as_str());
                }
            }
        }
        result
    }

    /// Return the IDs of all sections found in this template.
    ///
    /// Order is document order. Each ID appears at most once.
    pub fn sections(&self) -> Vec<&str> {
        let mut seen = std::collections::BTreeSet::new();
        let mut result = Vec::new();
        for seg in &self.segments {
            if let Segment::Section { id, .. } = seg {
                if seen.insert(id.as_str()) {
                    result.push(id.as_str());
                }
            }
        }
        result
    }

    /// Return `true` if a token with `name` appears anywhere in the template.
    pub fn has_token(&self, name: &str) -> bool {
        self.segments
            .iter()
            .any(|s| matches!(s, Segment::Token(n) if n == name))
    }

    /// Return `true` if a section with `id` appears anywhere in the template.
    pub fn has_section(&self, id: &str) -> bool {
        self.segments
            .iter()
            .any(|s| matches!(s, Segment::Section { id: i, .. } if i == id))
    }

    /// Render this template to a `String`.
    ///
    /// - `variables`: map of token name → replacement value. Tokens with no
    ///   entry in the map are left as `{{name}}` in the output.
    /// - `overlays`: map of section ID → replacement content. Sections with no
    ///   entry in the map keep their default content.
    ///
    /// Section markers (`<!-- section:ID -->` / `<!-- /section -->`) are always
    /// preserved in the output regardless of overlays.
    pub fn render(
        &self,
        variables: &BTreeMap<String, String>,
        overlays: &BTreeMap<String, String>,
    ) -> String {
        crate::render::render(self, variables, overlays)
    }
}

// ── Parsing implementation ───────────────────────────────────────────────────

/// Return `true` if the trimmed line is a section-open marker and extract the ID.
fn try_parse_section_open(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.starts_with(SECTION_OPEN_PREFIX) && trimmed.ends_with(SECTION_OPEN_SUFFIX) {
        let after_prefix = &trimmed[SECTION_OPEN_PREFIX.len()..];
        let id = &after_prefix[..after_prefix.len() - SECTION_OPEN_SUFFIX.len()];
        if !id.is_empty() {
            return Some(id);
        }
    }
    None
}

/// Return `true` if the trimmed line is the section-close marker.
fn is_section_close(line: &str) -> bool {
    line.trim() == SECTION_CLOSE_MARKER
}

/// Validate a token name.
///
/// Valid names match `[a-zA-Z_][a-zA-Z0-9_]*`.
fn is_valid_token_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        None => false,
        Some(first) => {
            (first.is_ascii_alphabetic() || first == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
    }
}

/// Core parsing state machine.
///
/// Returns a flat `Vec<Segment>`. Tokens inside section default content are
/// stored as raw text (not parsed as `Token` segments) because the section
/// content is kept verbatim; token substitution within section content is not
/// supported at this layer -- the overlay replaces the entire content block.
fn parse_segments(content: &str) -> Result<Vec<Segment>, TemplateError> {
    let mut segments: Vec<Segment> = Vec::new();

    /// Transient parser state while accumulating a line-by-line scan.
    enum State {
        /// Currently in top-level (non-section) content.
        TopLevel,
        /// Inside a `<!-- section:ID -->` block.
        InSection {
            id: String,
            open_line: usize,
            content: String,
        },
    }

    let mut state = State::TopLevel;

    // We iterate line by line so that section markers (which must appear on
    // their own line) can be detected cleanly. We use a line-number-aware
    // iterator; note that `lines()` strips line endings, so we manually
    // reconstruct newlines when accumulating content.
    //
    // To correctly handle tokens we work at the character level within
    // top-level lines. For section content we accumulate raw lines so that
    // the overlay mechanism can replace them wholesale.

    let total_lines: Vec<&str> = content.lines().collect();
    let line_count = total_lines.len();

    for (idx, raw_line) in total_lines.iter().enumerate() {
        let line_no = idx + 1; // 1-based

        match &mut state {
            State::TopLevel => {
                if let Some(id) = try_parse_section_open(raw_line) {
                    // Flush any pending literal into segments before switching.
                    // (No pending literal to flush at line granularity -- tokens
                    // are processed per-character below; here we process whole lines.)
                    //
                    // Emit the opening marker as a literal segment so it appears
                    // in output.
                    segments.push(Segment::Literal(format!("{raw_line}\n")));
                    state = State::InSection {
                        id: id.to_owned(),
                        open_line: line_no,
                        content: String::new(),
                    };
                } else if is_section_close(raw_line) {
                    return Err(TemplateError::UnmatchedClose { line: line_no });
                } else {
                    // Parse tokens within this line.
                    let mut line_segs = parse_tokens_in_text(raw_line, line_no)?;
                    segments.append(&mut line_segs);
                    // Restore the newline that `lines()` stripped, unless this
                    // is the last line and the original content did not end with
                    // a newline.
                    let is_last = idx == line_count - 1;
                    if !is_last || content.ends_with('\n') {
                        // Append newline to the last literal if present, or
                        // push a new literal.
                        append_newline_to_segments(&mut segments);
                    }
                }
            }

            State::InSection {
                id,
                open_line: _,
                content: sec_content,
            } => {
                if let Some(inner_id) = try_parse_section_open(raw_line) {
                    return Err(TemplateError::NestedSection {
                        outer: id.clone(),
                        inner: inner_id.to_owned(),
                        line: line_no,
                    });
                } else if is_section_close(raw_line) {
                    // Transition back to top-level. The close marker is emitted
                    // as a literal AFTER the Section segment (so it appears in
                    // output after the section content).
                    let section_id = std::mem::take(id);
                    let default = std::mem::take(sec_content);
                    segments.push(Segment::Section {
                        id: section_id,
                        default_content: default,
                    });
                    // Emit the close marker as a literal.
                    let is_last = idx == line_count - 1;
                    if !is_last || content.ends_with('\n') {
                        segments.push(Segment::Literal(format!("{raw_line}\n")));
                    } else {
                        segments.push(Segment::Literal(raw_line.to_string()));
                    }
                    state = State::TopLevel;
                } else {
                    // Accumulate this line into the section's default content.
                    sec_content.push_str(raw_line);
                    let is_last = idx == line_count - 1;
                    if !is_last || content.ends_with('\n') {
                        sec_content.push('\n');
                    }
                }
            }
        }
    }

    // After scanning all lines, check for unclosed sections.
    if let State::InSection { id, open_line, .. } = state {
        return Err(TemplateError::UnclosedSection {
            id,
            line: open_line,
        });
    }

    // Merge consecutive Literal segments for cleanliness.
    Ok(coalesce_literals(segments))
}

/// Append a newline character to the last `Literal` segment if it exists,
/// otherwise push a new `Literal("\n")`.
fn append_newline_to_segments(segments: &mut Vec<Segment>) {
    match segments.last_mut() {
        Some(Segment::Literal(s)) => s.push('\n'),
        _ => segments.push(Segment::Literal("\n".to_owned())),
    }
}

/// Merge consecutive [`Segment::Literal`] entries into a single segment.
fn coalesce_literals(segments: Vec<Segment>) -> Vec<Segment> {
    let mut out: Vec<Segment> = Vec::with_capacity(segments.len());
    for seg in segments {
        match seg {
            Segment::Literal(s) => {
                if let Some(Segment::Literal(prev)) = out.last_mut() {
                    prev.push_str(&s);
                } else {
                    out.push(Segment::Literal(s));
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// Parse a single line of text, extracting `{{token}}` placeholders.
///
/// Returns a list of `Segment::Literal` and `Segment::Token` values in order.
/// Does **not** add trailing newlines -- callers are responsible for that.
fn parse_tokens_in_text(text: &str, line_no: usize) -> Result<Vec<Segment>, TemplateError> {
    let mut segments = Vec::new();
    let mut remaining = text;

    while let Some(open_pos) = remaining.find("{{") {
        // Emit everything before `{{` as a literal.
        if open_pos > 0 {
            segments.push(Segment::Literal(remaining[..open_pos].to_owned()));
        }
        remaining = &remaining[open_pos + 2..]; // skip past `{{`

        // Find closing `}}`.
        match remaining.find("}}") {
            None => {
                // No close found: treat `{{` as literal text.
                segments.push(Segment::Literal("{{".to_owned()));
                // remaining already advanced past `{{`; continue scanning.
            }
            Some(close_pos) => {
                let raw_name = &remaining[..close_pos];
                let name = raw_name.trim();

                if name.is_empty() {
                    return Err(TemplateError::EmptyTokenName { line: line_no });
                }

                if !is_valid_token_name(name) {
                    return Err(TemplateError::InvalidTokenName {
                        name: name.to_owned(),
                        line: line_no,
                    });
                }

                segments.push(Segment::Token(name.to_owned()));
                remaining = &remaining[close_pos + 2..]; // skip past `}}`
            }
        }
    }

    // Emit any trailing text.
    if !remaining.is_empty() {
        segments.push(Segment::Literal(remaining.to_owned()));
    }

    Ok(segments)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Vec<Segment>, TemplateError> {
        Template::parse(s).map(|t| t.segments)
    }

    #[test]
    fn no_tokens_no_sections_gives_single_literal() {
        let segs = parse("Hello world\n").unwrap();
        assert_eq!(segs, vec![Segment::Literal("Hello world\n".to_owned())]);
    }

    #[test]
    fn single_token_replaced() {
        let segs = parse("Hi {{name}}!\n").unwrap();
        assert_eq!(
            segs,
            vec![
                Segment::Literal("Hi ".to_owned()),
                Segment::Token("name".to_owned()),
                Segment::Literal("!\n".to_owned()),
            ]
        );
    }

    #[test]
    fn whitespace_trimmed_in_token() {
        let segs = parse("{{ principal_name }}").unwrap();
        assert!(segs.contains(&Segment::Token("principal_name".to_owned())));
    }

    #[test]
    fn section_parsed_with_default_content() {
        let tmpl = "<!-- section:intro -->\nDefault text.\n<!-- /section -->\n";
        let segs = parse(tmpl).unwrap();
        // First segment: open marker literal
        assert!(matches!(&segs[0], Segment::Literal(s) if s.contains("<!-- section:intro -->")));
        // Second: Section
        assert!(
            matches!(&segs[1], Segment::Section { id, default_content } if id == "intro" && default_content == "Default text.\n")
        );
        // Third: close marker literal
        assert!(matches!(&segs[2], Segment::Literal(s) if s.contains("<!-- /section -->")));
    }

    #[test]
    fn unclosed_section_returns_error() {
        let tmpl = "<!-- section:foo -->\nNo close.\n";
        let err = parse(tmpl).unwrap_err();
        assert!(matches!(err, TemplateError::UnclosedSection { id, .. } if id == "foo"));
    }

    #[test]
    fn nested_section_returns_error() {
        let tmpl =
            "<!-- section:outer -->\n<!-- section:inner -->\ntext\n<!-- /section -->\n<!-- /section -->\n";
        let err = parse(tmpl).unwrap_err();
        assert!(
            matches!(err, TemplateError::NestedSection { outer, inner, .. } if outer == "outer" && inner == "inner")
        );
    }

    #[test]
    fn unmatched_close_returns_error() {
        let tmpl = "some text\n<!-- /section -->\n";
        let err = parse(tmpl).unwrap_err();
        assert!(matches!(err, TemplateError::UnmatchedClose { .. }));
    }

    #[test]
    fn empty_token_name_returns_error() {
        let err = parse("{{ }}").unwrap_err();
        assert!(matches!(err, TemplateError::EmptyTokenName { .. }));
    }

    #[test]
    fn invalid_token_name_returns_error() {
        let err = parse("{{123abc}}").unwrap_err();
        assert!(matches!(err, TemplateError::InvalidTokenName { name, .. } if name == "123abc"));
    }

    #[test]
    fn tokens_returns_unique_names_in_order() {
        let tmpl = Template::parse("{{a}} {{b}} {{a}}\n").unwrap();
        assert_eq!(tmpl.tokens(), vec!["a", "b"]);
    }

    #[test]
    fn sections_returns_ids_in_order() {
        let tmpl = Template::parse(
            "<!-- section:first -->\nA\n<!-- /section -->\n<!-- section:second -->\nB\n<!-- /section -->\n",
        )
        .unwrap();
        assert_eq!(tmpl.sections(), vec!["first", "second"]);
    }

    #[test]
    fn has_token_and_has_section() {
        let tmpl =
            Template::parse("{{tok}}\n<!-- section:sec -->\ndefault\n<!-- /section -->\n").unwrap();
        assert!(tmpl.has_token("tok"));
        assert!(!tmpl.has_token("missing"));
        assert!(tmpl.has_section("sec"));
        assert!(!tmpl.has_section("nope"));
    }
}
