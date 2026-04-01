use may_i_core::doc::{Doc, DocF};

use crate::annotation::Ann;

pub(super) fn collect_annotations(doc: &Doc<Option<Ann>>) -> Vec<(String, String)> {
    let mut result = Vec::new();
    collect_annotations_inner(doc, &mut result);
    result
}

fn collect_annotations_inner(doc: &Doc<Option<Ann>>, out: &mut Vec<(String, String)>) {
    if let Some(ann) = &doc.ann {
        if let Ann::ArgMatch {
            search_tokens,
            arg_set,
            matched,
        } = ann
        {
            if search_tokens.is_empty() && !arg_set.is_empty() {
                let positional = extract_positional_args(arg_set);
                collect_positional_annotations(doc, &positional, out);
            }
            if !search_tokens.is_empty() {
                let quoted_set = quote_arg_set(arg_set);
                let is_forbidden = is_forbidden_pattern(doc);
                if is_forbidden {
                    if *matched {
                        for token in search_tokens {
                            let arrow = "→ no";
                            out.push((
                                token.clone(),
                                format!("{token} ∈ {{{quoted_set}}} {arrow}"),
                            ));
                        }
                    } else {
                        for token in search_tokens {
                            let found = arg_set.iter().any(|a| {
                                let unquoted = token.trim_matches('"');
                                a == unquoted
                            });
                            if found {
                                out.push((
                                    token.clone(),
                                    format!("{token} ∈ {{{quoted_set}}} → yes"),
                                ));
                                break;
                            }
                        }
                    }
                } else if *matched {
                    let first_token = &search_tokens[0];
                    let arrow = "→ yes";
                    out.push((
                        first_token.clone(),
                        format!("{first_token} ∈ {{{quoted_set}}} {arrow}"),
                    ));
                } else {
                    for token in search_tokens {
                        let arrow = "→ no";
                        out.push((token.clone(), format!("{token} ∈ {{{quoted_set}}} {arrow}")));
                    }
                }
                return;
            }
        }
        if let Some(pair) = format_annotation(doc, ann) {
            out.push(pair);
        }
    }
    if let DocF::List(children) = &doc.node {
        for child in children {
            collect_annotations_inner(child, out);
        }
    }
}

fn format_annotation(doc: &Doc<Option<Ann>>, ann: &Ann) -> Option<(String, String)> {
    match ann {
        Ann::CommandMatch { matched } => {
            if !matched && matches!(doc.node, DocF::Atom(_)) {
                let needle = node_text(doc);
                Some((needle, verdict(false)))
            } else {
                None
            }
        }
        Ann::RuleMatch { .. } => None,
        Ann::Combinator { .. } => None,

        Ann::MayI {
            inner_command,
            decision,
            reason,
        } => {
            let keyword = format!(":{decision}");
            let right = match reason {
                Some(r) => format!("`{inner_command}` → {keyword} \"{r}\""),
                None => format!("`{inner_command}` → {keyword}"),
            };
            Some((node_text(doc), right))
        }

        Ann::BindMatch { key, value } => {
            let right = match value {
                Some(v) => format!("facts += {key} \"{v}\""),
                None => format!("{key} — no match"),
            };
            Some((node_text(doc), right))
        }

        Ann::RegexMatch {
            pattern,
            actual,
            matched,
        } => {
            let arrow = if *matched { "→ yes" } else { "→ no" };
            let right = format!("\"{actual}\" ~ (regex \"{pattern}\") {arrow}");
            Some((node_text(doc), right))
        }

        Ann::EffectDecision { decision, reason } => {
            let keyword = format!(":{decision}");
            let right = match reason {
                Some(r) => format!("→ {keyword} \"{r}\""),
                None => format!("→ {keyword}"),
            };
            Some((node_text(doc), right))
        }

        Ann::ArgMatch { .. } | Ann::PositionalMatch { .. } => None,

        Ann::FactQuery {
            query_source: _,
            matched,
            observed,
            failure_reason: _,
        } => {
            let needle = node_text(doc);
            match observed {
                Some(values) if !values.is_empty() => {
                    let observed_str = render_observed_value(&values[0]);
                    let arrow = if *matched { "yes" } else { "no" };
                    Some((needle, format!("{observed_str} → {arrow}")))
                }
                _ => Some((needle, verdict(*matched))),
            }
        }
    }
}

fn verdict(matched: bool) -> String {
    if matched { "yes".into() } else { "no".into() }
}

fn render_observed_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other => escaped.push(other),
        }
    }
    escaped.push('"');

    let char_count = escaped.chars().count();
    if char_count <= 40 {
        escaped
    } else {
        let inner = escaped.chars().skip(1).take(35).collect::<String>();
        let mut truncated = String::from("\"");
        truncated.push_str(&inner);
        truncated.push('…');
        truncated.push('"');
        truncated
    }
}

pub(super) fn node_text(doc: &Doc<Option<Ann>>) -> String {
    doc.fold(&|node, _ann: &Option<Ann>| match node {
        DocF::Atom(s) => s,
        DocF::List(cs) => format!("({})", cs.join(" ")),
        DocF::Vector(cs) => format!("[{}]", cs.join(" ")),
    })
}

fn extract_positional_args(args: &[String]) -> Vec<&str> {
    let mut result = Vec::new();
    let mut iter = args.iter().peekable();
    let mut past_terminator = false;

    while let Some(arg) = iter.next() {
        if past_terminator {
            result.push(arg.as_str());
        } else if arg == "--" {
            result.push(arg.as_str());
            past_terminator = true;
        } else if arg.starts_with("--") {
            if !arg.contains('=') {
                iter.next();
            }
        } else if arg.starts_with('-') {
            // Short flag — skip
        } else {
            result.push(arg.as_str());
        }
    }
    result
}

fn collect_positional_annotations(
    doc: &Doc<Option<Ann>>,
    positional_args: &[&str],
    out: &mut Vec<(String, String)>,
) {
    if let DocF::List(children) = &doc.node {
        let head = children.first().and_then(|c| c.as_atom());
        if !matches!(head, Some("positional" | "exact")) {
            return;
        }
        if let Some(first_arg) = positional_args.first() {
            for child in children.iter().skip(1) {
                collect_pattern_comparisons(child, first_arg, out);
            }
        }
    }
}

fn collect_pattern_comparisons(
    pattern_doc: &Doc<Option<Ann>>,
    actual_arg: &str,
    out: &mut Vec<(String, String)>,
) {
    match &pattern_doc.node {
        DocF::Atom(s) => {
            if s.starts_with('"') && s.ends_with('"') {
                let pattern_text = &s[1..s.len() - 1];
                let matched = actual_arg == pattern_text;
                let arrow = if matched { "→ yes" } else { "→ no" };
                out.push((s.clone(), format!("\"{}\" = {} {arrow}", actual_arg, s)));
            }
        }
        DocF::List(children) => {
            let head = children.first().and_then(|c| c.as_atom());
            match head {
                Some("or") => {
                    for child in children.iter().skip(1) {
                        collect_pattern_comparisons(child, actual_arg, out);
                    }
                }
                Some("?" | "+" | "*") => {
                    if let Some(inner) = children.get(1) {
                        collect_pattern_comparisons(inner, actual_arg, out);
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
}

pub(super) fn is_forbidden_pattern(doc: &Doc<Option<Ann>>) -> bool {
    if let DocF::List(children) = &doc.node
        && let Some(head) = children.first().and_then(|c| c.as_atom())
    {
        if head == "forbidden" {
            return true;
        }
        if head == "not"
            && let Some(inner) = children.get(1)
            && let DocF::List(inner_children) = &inner.node
            && let Some(inner_head) = inner_children.first().and_then(|c| c.as_atom())
        {
            return inner_head == "anywhere";
        }
    }
    false
}

fn quote_arg_set(items: &[String]) -> String {
    let quoted: Vec<String> = items.iter().map(|s| format!("\"{}\"", s)).collect();
    truncate_list(&quoted, 4)
}

fn truncate_list(items: &[String], max: usize) -> String {
    if items.len() <= max {
        items.join(", ")
    } else {
        let mut parts: Vec<&str> = items[..2].iter().map(|s| s.as_str()).collect();
        parts.push("…");
        parts.push(items.last().unwrap());
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::test_helpers::*;
    use may_i_core::doc::LayoutHint;
    use proptest::prelude::*;

    #[test]
    fn truncate_list_short() {
        let items: Vec<String> = vec!["a".into(), "b".into()];
        assert_eq!(truncate_list(&items, 4), "a, b");
    }

    #[test]
    fn truncate_list_long() {
        let items: Vec<String> = (0..6).map(|i| format!("item{i}")).collect();
        let result = truncate_list(&items, 4);
        assert!(result.contains("…"));
        assert!(result.starts_with("item0"));
        assert!(result.ends_with("item5"));
    }

    #[test]
    fn render_observed_value_short() {
        assert_eq!(render_observed_value("hello"), "\"hello\"");
    }

    #[test]
    fn render_observed_value_escapes() {
        let v = render_observed_value("a\"b\\c\nd");
        assert_eq!(v, r#""a\"b\\c\nd""#);
    }

    #[test]
    fn render_observed_value_truncates_long() {
        let long = "a".repeat(100);
        let rendered = render_observed_value(&long);
        assert!(rendered.len() < 100);
        assert!(rendered.contains("…"));
    }

    #[test]
    fn node_text_atom() {
        assert_eq!(node_text(&atom("hello")), "hello");
    }

    #[test]
    fn node_text_list() {
        let doc = list(vec![atom("a"), atom("b")]);
        assert_eq!(node_text(&doc), "(a b)");
    }

    #[test]
    fn node_text_vector() {
        let doc = vec_doc(vec![atom("x"), atom("y")]);
        assert_eq!(node_text(&doc), "[x y]");
    }

    #[test]
    fn is_forbidden_direct() {
        let doc = list(vec![atom("forbidden"), atom("x")]);
        assert!(is_forbidden_pattern(&doc));
    }

    #[test]
    fn is_forbidden_via_not_anywhere() {
        let inner = list(vec![atom("anywhere"), atom("x")]);
        let doc = list(vec![atom("not"), inner]);
        assert!(is_forbidden_pattern(&doc));
    }

    #[test]
    fn not_forbidden_for_anywhere() {
        let doc = list(vec![atom("anywhere"), atom("x")]);
        assert!(!is_forbidden_pattern(&doc));
    }

    #[test]
    fn extract_positional_args_basic() {
        let args = vec!["cmd".into(), "--flag".into(), "val".into(), "pos".into()];
        let result = extract_positional_args(&args);
        assert_eq!(result, vec!["cmd", "pos"]);
    }

    #[test]
    fn extract_positional_args_with_terminator() {
        let args = vec!["--opt".into(), "v".into(), "--".into(), "--not-flag".into()];
        let result = extract_positional_args(&args);
        assert_eq!(result, vec!["--", "--not-flag"]);
    }

    #[test]
    fn format_annotation_command_mismatch() {
        let ann = Ann::CommandMatch { matched: false };
        let doc = atom("git");
        let result = format_annotation(&doc, &ann);
        assert!(result.is_some());
        let (needle, text) = result.unwrap();
        assert_eq!(needle, "git");
        assert_eq!(text, "no");
    }

    #[test]
    fn format_annotation_command_match_returns_none() {
        let ann = Ann::CommandMatch { matched: true };
        let doc = atom("git");
        assert!(format_annotation(&doc, &ann).is_none());
    }

    #[test]
    fn format_annotation_may_i() {
        let ann = Ann::MayI {
            inner_command: "rm -rf /".into(),
            decision: may_i_core::Decision::Deny,
            reason: Some("dangerous".into()),
        };
        let doc = atom("(may-i *)");
        let result = format_annotation(&doc, &ann).unwrap();
        assert!(result.1.contains("rm -rf /"));
        assert!(result.1.contains(":deny"));
        assert!(result.1.contains("dangerous"));
    }

    #[test]
    fn format_annotation_bind_match() {
        let ann = Ann::BindMatch {
            key: ":host".into(),
            value: Some("prod".into()),
        };
        let doc = atom("[:host]");
        let result = format_annotation(&doc, &ann).unwrap();
        assert!(result.1.contains("facts +="));
        assert!(result.1.contains(":host"));
    }

    #[test]
    fn format_annotation_regex_match() {
        let ann = Ann::RegexMatch {
            pattern: "^prod".into(),
            actual: "prod-01".into(),
            matched: true,
        };
        let doc = atom("(regex)");
        let result = format_annotation(&doc, &ann).unwrap();
        assert!(result.1.contains("prod-01"));
        assert!(result.1.contains("yes"));
    }

    #[test]
    fn format_annotation_fact_query_with_observed() {
        let ann = Ann::FactQuery {
            query_source: "test".into(),
            matched: true,
            observed: Some(vec!["val".into()]),
            failure_reason: None,
        };
        let doc = atom("(fact?)");
        let result = format_annotation(&doc, &ann).unwrap();
        assert!(result.1.contains("val"));
        assert!(result.1.contains("yes"));
    }

    #[test]
    fn format_annotation_fact_query_without_observed() {
        let ann = Ann::FactQuery {
            query_source: "test".into(),
            matched: false,
            observed: None,
            failure_reason: None,
        };
        let doc = atom("(fact?)");
        let result = format_annotation(&doc, &ann).unwrap();
        assert_eq!(result.1, "no");
    }

    #[test]
    fn collect_annotations_anywhere_matched() {
        let doc = list_ann(
            Ann::ArgMatch {
                search_tokens: vec!["\"rm\"".into()],
                arg_set: vec!["rm".into(), "ls".into()],
                matched: true,
            },
            vec![atom("anywhere"), atom("\"rm\"")],
        );
        let annotations = collect_annotations(&doc);
        assert!(!annotations.is_empty());
        assert!(annotations[0].1.contains("yes"));
    }

    #[test]
    fn collect_annotations_anywhere_not_matched() {
        let doc = list_ann(
            Ann::ArgMatch {
                search_tokens: vec!["\"rm\"".into()],
                arg_set: vec!["ls".into()],
                matched: false,
            },
            vec![atom("anywhere"), atom("\"rm\"")],
        );
        let annotations = collect_annotations(&doc);
        assert!(!annotations.is_empty());
        assert!(annotations[0].1.contains("no"));
    }

    #[test]
    fn collect_annotations_forbidden_passed() {
        let doc = Doc {
            ann: Some(Ann::ArgMatch {
                search_tokens: vec!["\"rm\"".into()],
                arg_set: vec!["ls".into()],
                matched: true,
            }),
            node: DocF::List(vec![atom("forbidden"), atom("\"rm\"")]),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        let annotations = collect_annotations(&doc);
        assert!(!annotations.is_empty());
        assert!(annotations[0].1.contains("no"));
    }

    #[test]
    fn collect_annotations_forbidden_failed() {
        let doc = Doc {
            ann: Some(Ann::ArgMatch {
                search_tokens: vec!["\"rm\"".into()],
                arg_set: vec!["rm".into()],
                matched: false,
            }),
            node: DocF::List(vec![atom("forbidden"), atom("\"rm\"")]),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        let annotations = collect_annotations(&doc);
        assert!(!annotations.is_empty());
        assert!(annotations[0].1.contains("yes"));
    }

    #[test]
    fn collect_annotations_positional_pattern() {
        let doc = list_ann(
            Ann::ArgMatch {
                search_tokens: vec![],
                arg_set: vec!["push".into()],
                matched: true,
            },
            vec![atom("positional"), atom("\"push\"")],
        );
        let annotations = collect_annotations(&doc);
        assert!(!annotations.is_empty());
    }

    #[test]
    fn quote_arg_set_short() {
        let items = vec!["a".into(), "b".into()];
        assert_eq!(quote_arg_set(&items), "\"a\", \"b\"");
    }

    #[test]
    fn quote_arg_set_truncates() {
        let items: Vec<String> = (0..6).map(|i| format!("item{i}")).collect();
        let result = quote_arg_set(&items);
        assert!(result.contains("…"));
    }

    #[test]
    fn collect_pattern_comparisons_literal() {
        let pattern_doc = atom("\"push\"");
        let mut out = Vec::new();
        collect_pattern_comparisons(&pattern_doc, "push", &mut out);
        assert_eq!(out.len(), 1);
        assert!(out[0].1.contains("yes"));
    }

    #[test]
    fn collect_pattern_comparisons_or() {
        let pattern_doc = list(vec![atom("or"), atom("\"a\""), atom("\"b\"")]);
        let mut out = Vec::new();
        collect_pattern_comparisons(&pattern_doc, "a", &mut out);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn collect_pattern_comparisons_quantifier() {
        let pattern_doc = list(vec![atom("?"), atom("\"opt\"")]);
        let mut out = Vec::new();
        collect_pattern_comparisons(&pattern_doc, "opt", &mut out);
        assert_eq!(out.len(), 1);
        assert!(out[0].1.contains("yes"));
    }

    proptest! {
        #[test]
        fn render_observed_value_always_quoted(s in "[ -~]{0,100}") {
            let rendered = render_observed_value(&s);
            prop_assert!(rendered.starts_with('"'));
            prop_assert!(rendered.ends_with('"'));
            prop_assert!(rendered.len() <= 42);
        }

        #[test]
        fn truncate_list_preserves_short_lists(items in prop::collection::vec("[a-z]{1,5}", 1..4usize)) {
            let result = truncate_list(&items, 4);
            for item in &items {
                prop_assert!(result.contains(item.as_str()));
            }
        }

        #[test]
        fn node_text_atom_roundtrip(s in "[a-z]{1,10}") {
            let doc = atom(&s);
            prop_assert_eq!(node_text(&doc), s);
        }
    }
}
