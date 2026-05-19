use may_i_core::doc::{Doc, DocF};

use crate::trace::NodeMeta;

pub(super) fn verdict(matched: bool) -> String {
    if matched { "yes".into() } else { "no".into() }
}

pub(super) fn render_observed_value(value: &str) -> String {
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

#[allow(dead_code)]
pub(super) fn is_forbidden_pattern(doc: &Doc<Option<NodeMeta>>) -> bool {
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

pub(super) fn quote_arg_set(items: &[String]) -> String {
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
    use proptest::prelude::*;

    fn atom(s: &str) -> Doc<Option<NodeMeta>> {
        Doc {
            ann: None,
            node: DocF::Atom(s.into()),
            layout: may_i_core::doc::LayoutHint::Auto,
            dimmed: false,
        }
    }

    fn list(children: Vec<Doc<Option<NodeMeta>>>) -> Doc<Option<NodeMeta>> {
        Doc {
            ann: None,
            node: DocF::List(children),
            layout: may_i_core::doc::LayoutHint::Auto,
            dimmed: false,
        }
    }

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
    }
}
