use may_i_core::doc::{Doc, DocF};
use may_i_pp::{Format, pretty, visible_len};

use super::annotate::collect_annotations;
use super::colorize::colorize_right;
use super::transform::{dim_unevaluated, truncate_matched_anywhere, truncate_unevaluated};
use super::{ColRow, ColumnGeometry, strip_ansi};
use crate::annotation::Ann;

pub(super) fn render_annotated_rule(
    doc: &Doc<Option<Ann>>,
    line: Option<usize>,
    geom: &ColumnGeometry,
) -> Vec<ColRow> {
    let doc = dim_unevaluated(truncate_unevaluated(&truncate_matched_anywhere(doc), 2));
    let fmt = Format {
        width: geom.left_width,
        color: true,
        line_number: line,
    };
    let rendered = pretty(&doc, 0, &fmt);

    let annotations = collect_annotations(&doc);
    let outcome = extract_outcome(&doc);
    let matched = has_match(&doc);

    let rendered_lines: Vec<&str> = rendered.lines().collect();
    let stripped_lines: Vec<String> = rendered_lines.iter().map(|l| strip_ansi(l)).collect();

    let mut line_annotations: Vec<String> = vec![String::new(); rendered_lines.len()];
    let mut overflow: Vec<String> = Vec::new();
    let mut search_from = 0;

    for (needle, right_text) in &annotations {
        if needle.is_empty() {
            overflow.push(right_text.clone());
        } else if let Some(idx) = find_line(&stripped_lines, needle, &mut search_from) {
            line_annotations[idx] = right_text.clone();
        } else {
            overflow.push(right_text.clone());
        }
    }

    let already_has_effect_decision = annotations.iter().any(|(_, text)| text.starts_with("→ :"));
    if let Some(out) = outcome
        && matched
        && !already_has_effect_decision
    {
        let mut placed = false;
        for (i, stripped) in stripped_lines.iter().enumerate() {
            if stripped.contains("(effect") && line_annotations[i].is_empty() {
                line_annotations[i] = out.clone();
                placed = true;
                break;
            }
        }
        if !placed {
            overflow.push(out);
        }
    }

    let mut rows: Vec<ColRow> = rendered_lines
        .iter()
        .enumerate()
        .map(|(i, sline)| {
            ColRow::new(
                sline.to_string(),
                visible_len(sline),
                colorize_right(&line_annotations[i]),
            )
        })
        .collect();

    for ann in &overflow {
        rows.push(ColRow::new("", 0, colorize_right(ann)));
    }

    rows
}

fn extract_outcome(doc: &Doc<Option<Ann>>) -> Option<String> {
    if let DocF::List(children) = &doc.node {
        for child in children {
            if let Some(Ann::EffectDecision { decision, reason }) = &child.ann {
                let keyword = format!(":{decision}");
                return Some(match reason {
                    Some(r) => format!("→ {keyword} \"{r}\""),
                    None => format!("→ {keyword}"),
                });
            }
        }
    }
    None
}

fn has_match(doc: &Doc<Option<Ann>>) -> bool {
    if let Some(Ann::RuleMatch { matched: true, .. }) = &doc.ann {
        return true;
    }
    if let DocF::List(children) | DocF::Vector(children) = &doc.node {
        children.iter().any(has_match)
    } else {
        false
    }
}

fn find_line(stripped_lines: &[String], needle: &str, search_from: &mut usize) -> Option<usize> {
    for (i, line) in stripped_lines.iter().enumerate().skip(*search_from) {
        if line.contains(needle) {
            *search_from = i + 1;
            return Some(i);
        }
    }
    let first_token = needle.split_whitespace().next().unwrap_or(needle);
    if first_token != needle && first_token.len() >= 2 {
        for (i, line) in stripped_lines.iter().enumerate().skip(*search_from) {
            if line.contains(first_token) {
                *search_from = i + 1;
                return Some(i);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::test_helpers::*;
    use proptest::prelude::*;

    #[test]
    fn find_line_exact_match() {
        let lines = vec!["foo bar".into(), "baz".into()];
        let mut from = 0;
        assert_eq!(find_line(&lines, "baz", &mut from), Some(1));
        assert_eq!(from, 2);
    }

    #[test]
    fn find_line_fallback_to_first_token() {
        let lines = vec!["hello world".into(), "other".into()];
        let mut from = 0;
        assert_eq!(find_line(&lines, "hello xyz", &mut from), Some(0));
    }

    #[test]
    fn find_line_returns_none_when_not_found() {
        let lines = vec!["foo".into()];
        let mut from = 0;
        assert_eq!(find_line(&lines, "missing", &mut from), None);
    }

    #[test]
    fn extract_outcome_finds_effect_decision() {
        let child = atom_ann(
            ":allow",
            Ann::EffectDecision {
                decision: may_i_core::Decision::Allow,
                reason: None,
            },
        );
        let doc = list(vec![atom("rule"), child]);
        let outcome = extract_outcome(&doc);
        assert!(outcome.is_some());
        assert!(outcome.unwrap().contains(":allow"));
    }

    #[test]
    fn extract_outcome_none_without_annotation() {
        let doc = list(vec![atom("rule"), atom("body")]);
        assert!(extract_outcome(&doc).is_none());
    }

    #[test]
    fn has_match_true() {
        let doc = list_ann(
            Ann::RuleMatch {
                matched: true,
                line: Some(1),
            },
            vec![atom("rule")],
        );
        assert!(has_match(&doc));
    }

    #[test]
    fn has_match_false() {
        let doc = list(vec![atom("rule")]);
        assert!(!has_match(&doc));
    }

    #[test]
    fn render_annotated_rule_simple() {
        let doc = list_ann(
            Ann::RuleMatch {
                matched: true,
                line: Some(5),
            },
            vec![
                atom("rule"),
                atom_ann("git", Ann::CommandMatch { matched: true }),
                atom_ann(
                    ":allow",
                    Ann::EffectDecision {
                        decision: may_i_core::Decision::Allow,
                        reason: None,
                    },
                ),
            ],
        );
        let geom = ColumnGeometry { left_width: 40 };
        let rows = render_annotated_rule(&doc, Some(5), &geom);
        assert!(!rows.is_empty());
    }

    #[test]
    fn render_annotated_rule_with_overflow() {
        let doc = list_ann(
            Ann::RuleMatch {
                matched: true,
                line: Some(1),
            },
            vec![atom("rule")],
        );
        let geom = ColumnGeometry { left_width: 40 };
        let rows = render_annotated_rule(&doc, Some(1), &geom);
        assert!(!rows.is_empty());
    }

    proptest! {
        #[test]
        fn find_line_returns_valid_index(
            lines in prop::collection::vec("[a-z ]{1,20}", 1..10usize),
        ) {
            if let Some(target) = lines.first() {
                let mut from = 0;
                if let Some(idx) = find_line(&lines, target, &mut from) {
                    prop_assert!(idx < lines.len());
                }
            }
        }
    }
}
