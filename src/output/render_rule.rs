use may_i_core::doc::Doc;
use may_i_pp::{AnnotatedLineBuilder, Format, pretty, pretty_into, visible_len};

use super::colorize::colorize_right;
use super::transform::{
    dim_unevaluated, distribute_arg_annotations, truncate_matched_anywhere, truncate_unevaluated,
};
use super::{ColRow, ColumnGeometry};
use crate::annotation::Ann;

pub(super) fn render_annotated_rule(
    doc: &Doc<Option<Ann>>,
    line: Option<usize>,
    geom: &ColumnGeometry,
) -> Vec<ColRow> {
    let doc = dim_unevaluated(truncate_unevaluated(&truncate_matched_anywhere(doc), 2));
    let doc = distribute_arg_annotations(&doc);

    // Render with AnnotatedLineBuilder for structural annotation collection.
    let prefix_width = line.map_or(0, may_i_pp::line_prefix_width);
    let width = geom.left_width;
    let mut alb = AnnotatedLineBuilder::new();
    pretty_into(&doc, prefix_width, width, &mut alb);
    let annotated_lines = alb.into_lines();

    // Build colorised left-column text (with line numbers).
    let fmt = Format {
        width,
        color: true,
        line_number: line,
    };
    let rendered = pretty(&doc, 0, &fmt);
    let rendered_lines: Vec<&str> = rendered.lines().collect();

    // Map structural annotations to right-column text.
    let line_annotations: Vec<String> = annotated_lines
        .iter()
        .map(|al| format_line_annotation(&al.annotations))
        .collect();

    rendered_lines
        .iter()
        .enumerate()
        .map(|(i, sline)| {
            let ann = line_annotations.get(i).map_or("", |s| s.as_str());
            ColRow::new(sline.to_string(), visible_len(sline), colorize_right(ann))
        })
        .collect()
}

/// Map a line's collected annotations to right-column text.
///
/// When multiple annotations exist on one line, the highest-priority one wins.
/// Priority (high to low): EffectDecision, MayI, BindMatch, RegexMatch,
/// FactQuery, CommandMatch (miss only), ArgMatch (per-token), PositionalMatch.
fn format_line_annotation(anns: &[Option<Ann>]) -> String {
    use super::annotate::{quote_arg_set, render_observed_value, verdict};

    for ann in anns {
        if let Some(Ann::EffectDecision { decision, reason }) = ann {
            let keyword = format!(":{decision}");
            return match reason {
                Some(r) => format!("→ {keyword} \"{r}\""),
                None => format!("→ {keyword}"),
            };
        }
    }

    for ann in anns {
        if let Some(Ann::MayI {
            inner_command,
            decision,
            reason,
        }) = ann
        {
            let keyword = format!(":{decision}");
            return match reason {
                Some(r) => format!("`{inner_command}` → {keyword} \"{r}\""),
                None => format!("`{inner_command}` → {keyword}"),
            };
        }
    }

    for ann in anns {
        if let Some(Ann::BindMatch { key, value }) = ann {
            return match value {
                Some(v) => format!("facts += {key} \"{v}\""),
                None => format!("{key} — no match"),
            };
        }
    }

    for ann in anns {
        if let Some(Ann::RegexMatch {
            pattern,
            actual,
            matched,
        }) = ann
        {
            let arrow = if *matched { "→ yes" } else { "→ no" };
            return format!("\"{actual}\" ~ (regex \"{pattern}\") {arrow}");
        }
    }

    for ann in anns {
        if let Some(Ann::FactQuery {
            matched, observed, ..
        }) = ann
        {
            return match observed {
                Some(values) if !values.is_empty() => {
                    let observed_str = render_observed_value(&values[0]);
                    let arrow = if *matched { "yes" } else { "no" };
                    format!("{observed_str} → {arrow}")
                }
                _ => verdict(*matched),
            };
        }
    }

    for ann in anns {
        if let Some(Ann::CommandMatch { matched: false }) = ann {
            return verdict(false);
        }
    }

    for ann in anns {
        if let Some(Ann::ArgMatch {
            search_tokens,
            arg_set,
            matched,
        }) = ann
            && !search_tokens.is_empty()
        {
            let token = &search_tokens[0];
            let quoted_set = quote_arg_set(arg_set);
            let arrow = if *matched { "→ yes" } else { "→ no" };
            return format!("{token} ∈ {{{quoted_set}}} {arrow}");
        }
    }

    for ann in anns {
        if let Some(Ann::PositionalMatch {
            actual_arg,
            pattern_text,
            matched,
        }) = ann
        {
            let arrow = if *matched { "→ yes" } else { "→ no" };
            return format!("\"{actual_arg}\" = {pattern_text} {arrow}");
        }
    }

    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::test_helpers::*;

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

    #[test]
    fn format_line_annotation_effect_decision() {
        let anns = vec![Some(Ann::EffectDecision {
            decision: may_i_core::Decision::Allow,
            reason: Some("read-only".into()),
        })];
        assert_eq!(format_line_annotation(&anns), "→ :allow \"read-only\"");
    }

    #[test]
    fn format_line_annotation_effect_decision_no_reason() {
        let anns = vec![Some(Ann::EffectDecision {
            decision: may_i_core::Decision::Deny,
            reason: None,
        })];
        assert_eq!(format_line_annotation(&anns), "→ :deny");
    }

    #[test]
    fn format_line_annotation_may_i() {
        let anns = vec![Some(Ann::MayI {
            inner_command: "rm -rf /".into(),
            decision: may_i_core::Decision::Deny,
            reason: Some("dangerous".into()),
        })];
        assert_eq!(
            format_line_annotation(&anns),
            "`rm -rf /` → :deny \"dangerous\""
        );
    }

    #[test]
    fn format_line_annotation_bind_match() {
        let anns = vec![Some(Ann::BindMatch {
            key: ":host".into(),
            value: Some("prod".into()),
        })];
        assert_eq!(format_line_annotation(&anns), "facts += :host \"prod\"");
    }

    #[test]
    fn format_line_annotation_regex_match() {
        let anns = vec![Some(Ann::RegexMatch {
            pattern: "^prod".into(),
            actual: "prod-01".into(),
            matched: true,
        })];
        assert_eq!(
            format_line_annotation(&anns),
            "\"prod-01\" ~ (regex \"^prod\") → yes"
        );
    }

    #[test]
    fn format_line_annotation_fact_query_with_observed() {
        let anns = vec![Some(Ann::FactQuery {
            query_source: "test".into(),
            matched: true,
            observed: Some(vec!["val".into()]),
            failure_reason: None,
        })];
        assert_eq!(format_line_annotation(&anns), "\"val\" → yes");
    }

    #[test]
    fn format_line_annotation_command_mismatch() {
        let anns = vec![Some(Ann::CommandMatch { matched: false })];
        assert_eq!(format_line_annotation(&anns), "no");
    }

    #[test]
    fn format_line_annotation_command_match_ignored() {
        let anns = vec![Some(Ann::CommandMatch { matched: true })];
        assert_eq!(format_line_annotation(&anns), "");
    }

    #[test]
    fn format_line_annotation_arg_match_per_token() {
        let anns = vec![Some(Ann::ArgMatch {
            search_tokens: vec!["\"rm\"".into()],
            arg_set: vec!["rm".into(), "ls".into()],
            matched: true,
        })];
        assert_eq!(
            format_line_annotation(&anns),
            "\"rm\" ∈ {\"rm\", \"ls\"} → yes"
        );
    }

    #[test]
    fn format_line_annotation_positional_match() {
        let anns = vec![Some(Ann::PositionalMatch {
            actual_arg: "push".into(),
            pattern_text: "\"pull\"".into(),
            matched: false,
        })];
        assert_eq!(format_line_annotation(&anns), "\"push\" = \"pull\" → no");
    }

    #[test]
    fn format_line_annotation_priority_effect_over_arg() {
        let anns = vec![
            Some(Ann::ArgMatch {
                search_tokens: vec!["\"x\"".into()],
                arg_set: vec!["x".into()],
                matched: true,
            }),
            Some(Ann::EffectDecision {
                decision: may_i_core::Decision::Allow,
                reason: None,
            }),
        ];
        assert_eq!(format_line_annotation(&anns), "→ :allow");
    }

    #[test]
    fn format_line_annotation_empty() {
        let anns: Vec<Option<Ann>> = vec![None, None];
        assert_eq!(format_line_annotation(&anns), "");
    }

    #[test]
    fn format_line_annotation_rule_match_ignored() {
        let anns = vec![Some(Ann::RuleMatch {
            matched: true,
            line: Some(1),
        })];
        assert_eq!(format_line_annotation(&anns), "");
    }

    #[test]
    fn format_line_annotation_combinator_ignored() {
        let anns = vec![Some(Ann::Combinator {
            result_is_nil: true,
        })];
        assert_eq!(format_line_annotation(&anns), "");
    }
}
