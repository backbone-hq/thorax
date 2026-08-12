//! The user-facing secret-selector grammar, shared by every frontend so the CLI, `run` injector,
//! and TUI accept and print selectors identically.
//!
//! A **concrete selector** names one secret: a slash tuple plus an optional label section,
//! query-string style — `@` opens it, `&` separates `key=value` pairs
//! (`app/prod/db`, `app/prod/db@env=prod&tier=web`). The **whole selector** — tuple *and*
//! labels — is the secret's identity: `app/db@env=dev` and `app/db@env=prod` are distinct
//! secrets. On writes the labels given are part of the key written; on reads they select
//! which secret (a label given but absent on a live record means a different key, so the
//! lookup misses). Labels are sorted by key on parse and duplicate keys are refused — one
//! key, one spelling.
//!
//! A **selection query** (`thorax run`) widens the grammar to the same matcher access grants use
//! ([`KeyspaceSelectorV1`]): the tuple selects itself and everything under it (`*`, `.` or `/`
//! select the whole vault), and labels can require a value (`@env=prod`), presence (`@env`), or
//! absence (`@!env`), ANDed together (`app@env=prod&!deprecated`).
//!
//! ## Quoting
//!
//! `@`, `&`, `=` (and `!`, `*`, `.`, `/` in queries) are structural, so a segment, label key, or
//! label value that needs one of them literally must escape it — shell style, applied uniformly
//! in every position:
//!
//! - a backslash `\` escapes the next character anywhere (`app\/prod/db` is the two-segment
//!   tuple `["app/prod", "db"]`, `\"` is a literal quote);
//! - double quotes `"…"` take a run literally (`"app/prod"/db` is the same tuple); structural
//!   characters inside the run are ordinary text, and quotes may be adjacent to unquoted text
//!   (`a"b"c` is `abc`).
//!
//! A literal `"` is therefore always written `\"`, and a literal `\` always `\\`. Empty segments
//! and empty label keys/values remain rejected even when written as `""`, so the no-empty-segment
//! invariant holds regardless of spelling. [`selector_string`] and [`escape_segment`] render the
//! canonical inverse: a field is printed bare when it contains no structural character, and quoted
//! (with `"` and `\` backslash-escaped) otherwise, so parse∘render and render∘parse are stable.

use thorax_ops::{
    KeyspaceLabelMatcherV1, KeyspaceSelectorV1, LabelMatcherV1, SecretLabelV1, SecretSelectorV1,
    TupleMatcherV1,
};

use crate::FrontendError;

/// Characters that are structural in some position and so force a field to be quoted when it
/// contains one. A superset across concrete selectors and queries: rendering a concrete value
/// that happens to contain `!` quotes it too, which is harmless and keeps one canonical spelling.
const STRUCTURAL: &[char] = &['/', '@', '&', '=', '!', '"', '\\'];

pub fn parse_secret_selector(value: &str) -> Result<SecretSelectorV1, FrontendError> {
    let (path, label_section) = split_label_section(value);
    let tuple = parse_tuple_path(value, path)?;
    let mut labels = Vec::new();
    for label in label_section.into_iter().flatten() {
        let Some((key, label_value)) = split_once_unquoted(label, '=') else {
            return Err(FrontendError::InvalidSelector {
                selector: value.to_string(),
                reason: "secret labels are @key=value pairs separated by &",
            });
        };
        let key = decode_field(key, value)?;
        let label_value = decode_field(label_value, value)?;
        if key.is_empty() || label_value.is_empty() {
            return Err(FrontendError::InvalidSelector {
                selector: value.to_string(),
                reason: "label keys and values must not be empty",
            });
        }
        labels.push(SecretLabelV1 {
            key,
            value: label_value,
        });
    }
    labels.sort();
    if labels.windows(2).any(|pair| pair[0].key == pair[1].key) {
        return Err(FrontendError::InvalidSelector {
            selector: value.to_string(),
            reason: "a label key may appear only once",
        });
    }
    Ok(SecretSelectorV1 { tuple, labels })
}

/// Parse a `thorax run` selection query into the grant matcher.
pub fn parse_secret_query(value: &str) -> Result<KeyspaceSelectorV1, FrontendError> {
    let (path, label_section) = split_label_section(value);
    // The whole-vault spellings mirror `grant`'s keyspace argument and are recognised only when
    // written bare; `"*"`, `\*`, etc. fall through to a one-segment literal tuple. A bare empty
    // string is refused rather than treated as select-all: exposing everything must be said out
    // loud.
    let tuple = match path {
        "*" | "." | "/" => TupleMatcherV1::Any,
        "" if label_section.is_some() => TupleMatcherV1::Any,
        _ => TupleMatcherV1::Prefix(parse_tuple_path(value, path)?),
    };
    let mut labels: Vec<KeyspaceLabelMatcherV1> = Vec::new();
    for label in label_section.into_iter().flatten() {
        // `!` is the absence marker only as a literal leading character; `\!x` and `"!x"` are the
        // ordinary key `!x`.
        let (key, matcher) = if let Some(rest) = label.strip_prefix('!') {
            (decode_field(rest, value)?, LabelMatcherV1::Absent)
        } else if let Some((key, label_value)) = split_once_unquoted(label, '=') {
            let label_value = decode_field(label_value, value)?;
            if label_value.is_empty() {
                return Err(FrontendError::InvalidSelector {
                    selector: value.to_string(),
                    reason: "label values must not be empty",
                });
            }
            (
                decode_field(key, value)?,
                LabelMatcherV1::Equals(label_value),
            )
        } else {
            (decode_field(label, value)?, LabelMatcherV1::Any)
        };
        if key.is_empty() {
            return Err(FrontendError::InvalidSelector {
                selector: value.to_string(),
                reason: "label keys must not be empty",
            });
        }
        if labels.iter().any(|existing| existing.key == key) {
            return Err(FrontendError::InvalidSelector {
                selector: value.to_string(),
                reason: "a label key may appear only once",
            });
        }
        labels.push(KeyspaceLabelMatcherV1 { key, matcher });
    }
    Ok(KeyspaceSelectorV1 { tuple, labels })
}

/// Split a selector into its tuple path and label section: the first *unquoted* `@` opens the
/// labels, unquoted `&` separates them (query-string style). `None` when there is no `@` at all.
fn split_label_section(value: &str) -> (&str, Option<Vec<&str>>) {
    match split_once_unquoted(value, '@') {
        Some((path, section)) => (path, Some(split_unquoted(section, '&'))),
        None => (value, None),
    }
}

fn parse_tuple_path(whole: &str, path: &str) -> Result<Vec<String>, FrontendError> {
    if path.is_empty() {
        return Err(FrontendError::InvalidSelector {
            selector: whole.to_string(),
            reason: "selector must not be empty",
        });
    }
    let mut parts = Vec::new();
    for raw in split_unquoted(path, '/') {
        let segment = decode_field(raw, whole)?;
        if segment.is_empty() {
            return Err(FrontendError::InvalidSelector {
                selector: whole.to_string(),
                reason: "selector path must not contain empty segments",
            });
        }
        parts.push(segment);
    }
    Ok(parts)
}

/// Split `s` on every top-level `delim` — one that is neither inside a `"…"` run nor backslash
/// escaped. Fields are returned still encoded; [`decode_field`] removes the quoting.
fn split_unquoted(s: &str, delim: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quote = false;
    let mut escaped = false;
    for (index, ch) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => in_quote = !in_quote,
            _ if ch == delim && !in_quote => {
                parts.push(&s[start..index]);
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

/// Like [`split_unquoted`] but stops at the first top-level `delim`, returning the halves around
/// it (the delimiter consumed). `None` when no unquoted `delim` is present.
fn split_once_unquoted(s: &str, delim: char) -> Option<(&str, &str)> {
    let mut in_quote = false;
    let mut escaped = false;
    for (index, ch) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => in_quote = !in_quote,
            _ if ch == delim && !in_quote => {
                return Some((&s[..index], &s[index + ch.len_utf8()..]));
            }
            _ => {}
        }
    }
    None
}

/// Decode one field (segment, label key, or label value) to its literal value: drop the quoting
/// `"` runs and `\` escapes, keep everything else. Errors on an unterminated quote or trailing
/// backslash. Callers reject the empty result where an empty field is not allowed.
fn decode_field(raw: &str, whole: &str) -> Result<String, FrontendError> {
    let mut out = String::with_capacity(raw.len());
    let mut in_quote = false;
    let mut escaped = false;
    for ch in raw.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => in_quote = !in_quote,
            _ => out.push(ch),
        }
    }
    if escaped {
        return Err(FrontendError::InvalidSelector {
            selector: whole.to_string(),
            reason: "selector ends with a dangling backslash escape",
        });
    }
    if in_quote {
        return Err(FrontendError::InvalidSelector {
            selector: whole.to_string(),
            reason: "selector has an unterminated quote",
        });
    }
    Ok(out)
}

/// Render one field to its canonical spelling: bare when it holds no structural character,
/// otherwise a single `"…"` run with `"` and `\` backslash-escaped. The inverse of
/// `decode_field`, so parsing the result reproduces `value`.
pub fn escape_segment(value: &str) -> String {
    if !value.is_empty() && !value.chars().any(|ch| STRUCTURAL.contains(&ch)) {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        if ch == '"' || ch == '\\' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

/// Render a `/`-joined tuple with each segment in its canonical (quoted-when-structural) spelling,
/// so the result round-trips through the tuple grammar. The one place tuple rendering lives — every
/// frontend (CLI keyspace, TUI tree/grant, merge view, selector strings) joins through here so a
/// segment printed by one re-parses in another.
pub fn escape_tuple<S: AsRef<str>>(parts: &[S]) -> String {
    parts
        .iter()
        .map(|segment| escape_segment(segment.as_ref()))
        .collect::<Vec<_>>()
        .join("/")
}

pub fn selector_string(selector: &SecretSelectorV1) -> String {
    let mut rendered = escape_tuple(&selector.tuple);
    for (index, label) in selector.labels.iter().enumerate() {
        rendered.push(if index == 0 { '@' } else { '&' });
        rendered.push_str(&escape_segment(&label.key));
        rendered.push('=');
        rendered.push_str(&escape_segment(&label.value));
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concrete_labels_parse_and_render_canonically() {
        // Labels sort by key on parse, so spelling order does not change identity or rendering.
        let selector = parse_secret_selector("app/db@tier=web&env=prod").unwrap();
        assert_eq!(selector_string(&selector), "app/db@env=prod&tier=web");
        assert_eq!(
            selector,
            parse_secret_selector("app/db@env=prod&tier=web").unwrap()
        );
        assert!(parse_secret_selector("app/db").unwrap().labels.is_empty());
    }

    #[test]
    fn concrete_labels_must_be_unique_nonempty_pairs() {
        for invalid in [
            "app/db@env",         // bare key: matchers belong to queries, not secrets
            "app/db@env=",        // empty value
            "app/db@=prod",       // empty key
            "app/db@env=a&env=b", // duplicate key
            "app/db@",            // empty label section
        ] {
            assert!(
                matches!(
                    parse_secret_selector(invalid),
                    Err(FrontendError::InvalidSelector { .. })
                ),
                "expected InvalidSelector for {invalid:?}"
            );
        }
    }

    #[test]
    fn quoting_lets_segments_carry_structural_characters() {
        // Both quoting and backslash escaping reach the same tuple.
        let quoted = parse_secret_selector("\"app/prod\"/db").unwrap();
        let escaped = parse_secret_selector("app\\/prod/db").unwrap();
        assert_eq!(quoted.tuple, vec!["app/prod".to_string(), "db".to_string()]);
        assert_eq!(quoted, escaped);

        // `@`, `&`, `=` survive inside segments and label values.
        let selector = parse_secret_selector("\"a@b\"/db@team=\"x&y=z\"").unwrap();
        assert_eq!(selector.tuple, vec!["a@b".to_string(), "db".to_string()]);
        assert_eq!(selector.labels.len(), 1);
        assert_eq!(selector.labels[0].key, "team");
        assert_eq!(selector.labels[0].value, "x&y=z");

        // Adjacent quoted and bare runs concatenate; a literal quote is `\"`.
        assert_eq!(
            parse_secret_selector("a\"b\"c").unwrap().tuple,
            vec!["abc".to_string()]
        );
        assert_eq!(
            parse_secret_selector("a\\\"b").unwrap().tuple,
            vec!["a\"b".to_string()]
        );
    }

    #[test]
    fn render_round_trips_structural_and_quote_characters() {
        for tuple in [
            vec!["app/prod".to_string(), "db".to_string()],
            vec!["a@b&c=d".to_string()],
            vec!["he said \"hi\"".to_string()],
            vec!["back\\slash".to_string()],
            vec!["plain".to_string(), "with spaces".to_string()],
        ] {
            let selector = SecretSelectorV1 {
                tuple,
                labels: vec![SecretLabelV1 {
                    key: "weird/key".to_string(),
                    value: "v=1&v=2".to_string(),
                }],
            };
            let rendered = selector_string(&selector);
            assert_eq!(
                parse_secret_selector(&rendered).unwrap(),
                selector,
                "round-trip failed for {rendered:?}"
            );
            // Rendering is canonical: rendering the re-parsed value is stable.
            assert_eq!(
                selector_string(&parse_secret_selector(&rendered).unwrap()),
                rendered
            );
        }
    }

    #[test]
    fn escape_segment_is_bare_when_unambiguous() {
        assert_eq!(escape_segment("plain"), "plain");
        assert_eq!(escape_segment("with spaces"), "with spaces");
        assert_eq!(escape_segment("a/b"), "\"a/b\"");
        assert_eq!(escape_segment("a\"b"), "\"a\\\"b\"");
        assert_eq!(escape_segment("a\\b"), "\"a\\\\b\"");
    }

    #[test]
    fn malformed_quoting_is_rejected() {
        for invalid in [
            "app/\"db", // unterminated quote
            "app/db\\", // dangling escape
            "\"a/b",    // unterminated quote spanning a delimiter
        ] {
            assert!(
                matches!(
                    parse_secret_selector(invalid),
                    Err(FrontendError::InvalidSelector { .. })
                ),
                "expected InvalidSelector for {invalid:?}"
            );
        }
    }

    #[test]
    fn quoted_empty_segments_are_still_rejected() {
        for invalid in ["\"\"/db", "app/\"\"", "app/db@\"\"=v", "app/db@k=\"\""] {
            assert!(
                matches!(
                    parse_secret_selector(invalid),
                    Err(FrontendError::InvalidSelector { .. })
                ),
                "expected InvalidSelector for {invalid:?}"
            );
        }
    }

    #[test]
    fn queries_combine_tuple_prefix_and_label_matchers() {
        let query = parse_secret_query("app/prod@env=prod&region&!deprecated").unwrap();
        assert_eq!(
            query.tuple,
            TupleMatcherV1::Prefix(vec!["app".into(), "prod".into()])
        );
        assert_eq!(query.labels.len(), 3);
        assert_eq!(
            query.labels[0].matcher,
            LabelMatcherV1::Equals("prod".into())
        );
        assert_eq!(query.labels[1].matcher, LabelMatcherV1::Any);
        assert_eq!(query.labels[2].matcher, LabelMatcherV1::Absent);

        assert_eq!(
            parse_secret_query("@env=prod").unwrap().tuple,
            TupleMatcherV1::Any
        );
        assert_eq!(parse_secret_query("*").unwrap().tuple, TupleMatcherV1::Any);
        assert!(parse_secret_query("").is_err());
        assert!(parse_secret_query("app@env=a&env=b").is_err());
    }

    #[test]
    fn queries_quote_structural_characters_and_the_absence_marker() {
        // A quoted `*` is a literal one-segment prefix, not select-all.
        assert_eq!(
            parse_secret_query("\"*\"").unwrap().tuple,
            TupleMatcherV1::Prefix(vec!["*".into()])
        );
        // A literal leading `!` in a key is quoted; the absence marker is the bare `!`.
        let query = parse_secret_query("app@\"!real\"=v").unwrap();
        assert_eq!(query.labels.len(), 1);
        assert_eq!(query.labels[0].key, "!real");
        assert_eq!(query.labels[0].matcher, LabelMatcherV1::Equals("v".into()));
    }
}
