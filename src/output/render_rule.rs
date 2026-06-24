use may_i_pp::{AnnotatedLineBuilder, Format, pretty_into, pretty_styled};

use super::colorize::colorize_right;
use super::{ColRow, ColumnGeometry};
use crate::trace::node::{CaptureSource, Evidence, Role};
use crate::trace::{NodeMeta, TraceNode};

/// Render a rule's left/right column rows from a producer-prepared trace
/// node. Renderers MUST NOT pattern-match on `TraceNode` internals; the
/// node is projected to a `Doc<Option<NodeMeta>>` for pretty-printing, and
/// per-line evidence is collected via the structural pretty-print path.
pub(super) fn render_annotated_rule(
    node: &TraceNode,
    line: Option<usize>,
    geom: &ColumnGeometry,
) -> Vec<ColRow> {
    let doc = node.to_render_doc();

    let prefix_width = line.map_or(0, may_i_pp::line_prefix_width);
    let width = geom.left_width;
    let mut alb = AnnotatedLineBuilder::new();
    pretty_into(&doc, prefix_width, width, &mut alb);
    let annotated_lines = alb.into_lines();

    let fmt = Format {
        width,
        color: true,
        line_number: line,
        preserve_user_breaks: false,
    };
    let styled_lines = pretty_styled(&doc, 0, &fmt);

    let line_annotations: Vec<String> = annotated_lines
        .iter()
        .map(|al| format_line_annotation(&al.annotations))
        .collect();

    styled_lines
        .into_iter()
        .enumerate()
        .map(|(i, sline)| {
            let ann = line_annotations.get(i).map_or("", |s| s.as_str());
            ColRow::new(sline, colorize_right(ann))
        })
        .collect()
}

fn captured_source_label(source: CaptureSource) -> &'static str {
    match source {
        CaptureSource::Tail => "tail",
        CaptureSource::Parameter => "value",
    }
}

/// Map a line's collected metas to right-column text. The producer ensures
/// at most one evidence-bearing node per slot; priority arbitration here
/// is residual ordering only.
fn format_line_annotation(metas: &[Option<NodeMeta>]) -> String {
    use super::annotate::{quote_arg_set, render_observed_value, verdict};

    for meta in metas.iter().flatten() {
        if let (Role::EffectDecision, Some(Evidence::Decision { decision, reason })) =
            (meta.role(), meta.evidence())
        {
            let keyword = format!(":{decision}");
            return match reason {
                Some(r) => format!("→ {keyword} \"{r}\""),
                None => format!("→ {keyword}"),
            };
        }
    }

    for meta in metas.iter().flatten() {
        if let (Role::VarRef { name }, Some(Evidence::Match { matched })) =
            (meta.role(), meta.evidence())
        {
            let arrow = if *matched { "→ yes" } else { "→ no" };
            return format!("{name} {arrow}");
        }
    }

    for meta in metas.iter().flatten() {
        if let (Role::BindMatch { key }, Some(Evidence::Bind { value })) =
            (meta.role(), meta.evidence())
        {
            return match value {
                Some(v) => format!("facts += {key} \"{v}\""),
                None => format!("{key} — no match"),
            };
        }
    }

    for meta in metas.iter().flatten() {
        if let (
            Role::RegexMatch,
            Some(Evidence::Regex {
                pattern,
                actual,
                matched,
            }),
        ) = (meta.role(), meta.evidence())
        {
            let arrow = if *matched { "→ yes" } else { "→ no" };
            return format!("\"{actual}\" ~ (regex \"{pattern}\") {arrow}");
        }
    }

    for meta in metas.iter().flatten() {
        match (meta.role(), meta.evidence()) {
            (
                Role::FactQuery,
                Some(Evidence::FactValues {
                    observed, matched, ..
                }),
            ) if !observed.is_empty() => {
                let first = observed.iter().next().expect("non-empty checked above");
                let observed_str = render_observed_value(first);
                let arrow = if *matched { "yes" } else { "no" };
                return format!("{observed_str} → {arrow}");
            }
            (Role::FactQuery, Some(Evidence::FactValues { matched, .. })) => {
                return verdict(*matched);
            }
            (Role::FactQuery, Some(Evidence::FactAbsent)) => {
                return verdict(false);
            }
            (Role::FactQuery, Some(Evidence::Match { matched })) => {
                return verdict(*matched);
            }
            _ => {}
        }
    }

    for meta in metas.iter().flatten() {
        if let (Role::Command, Some(Evidence::Match { matched: false })) =
            (meta.role(), meta.evidence())
        {
            return verdict(false);
        }
    }

    for meta in metas.iter().flatten() {
        if let (Role::ArgMatch, Some(Evidence::CapturedValue { source, value })) =
            (meta.role(), meta.evidence())
        {
            let label = captured_source_label(*source);
            return format!("{label} = \"{value}\"");
        }
    }

    for meta in metas.iter().flatten() {
        if let (
            Role::ArgMatch,
            Some(Evidence::SetMembership {
                token,
                observed,
                matched,
            }),
        ) = (meta.role(), meta.evidence())
        {
            if token.is_empty() {
                continue;
            }
            let quoted_set = quote_arg_set(observed);
            let arrow = if *matched { "→ yes" } else { "→ no" };
            return format!("\"{token}\" ∈ {{{quoted_set}}} {arrow}");
        }
    }

    for meta in metas.iter().flatten() {
        if let (
            Role::PositionalMatch,
            Some(Evidence::Positional {
                actual,
                pattern_text,
                matched,
            }),
        ) = (meta.role(), meta.evidence())
        {
            let arrow = if *matched { "→ yes" } else { "→ no" };
            return format!("\"{actual}\" = {pattern_text} {arrow}");
        }
    }

    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::node::Evidence;
    use may_i_core::Decision;

    #[test]
    fn format_line_annotation_effect_decision() {
        let metas = vec![Some(NodeMeta::new(
            Role::EffectDecision,
            Some(Evidence::Decision {
                decision: Decision::Allow,
                reason: Some("read-only".into()),
            }),
        ))];
        assert_eq!(format_line_annotation(&metas), "→ :allow \"read-only\"");
    }

    #[test]
    fn format_line_annotation_effect_decision_no_reason() {
        let metas = vec![Some(NodeMeta::new(
            Role::EffectDecision,
            Some(Evidence::Decision {
                decision: Decision::Deny,
                reason: None,
            }),
        ))];
        assert_eq!(format_line_annotation(&metas), "→ :deny");
    }

    #[test]
    fn format_line_annotation_bind_match() {
        let metas = vec![Some(NodeMeta::new(
            Role::BindMatch {
                key: ":host".into(),
            },
            Some(Evidence::Bind {
                value: Some("prod".into()),
            }),
        ))];
        assert_eq!(format_line_annotation(&metas), "facts += :host \"prod\"");
    }

    #[test]
    fn format_line_annotation_regex_match() {
        let metas = vec![Some(NodeMeta::new(
            Role::RegexMatch,
            Some(Evidence::Regex {
                pattern: "^prod".into(),
                actual: "prod-01".into(),
                matched: true,
            }),
        ))];
        assert_eq!(
            format_line_annotation(&metas),
            "\"prod-01\" ~ (regex \"^prod\") → yes"
        );
    }

    #[test]
    fn format_line_annotation_fact_query_with_observed() {
        let mut observed = std::collections::BTreeSet::new();
        observed.insert("val".to_string());
        let metas = vec![Some(NodeMeta::new(
            Role::FactQuery,
            Some(Evidence::FactValues {
                expected: "test".into(),
                observed,
                matched: true,
            }),
        ))];
        assert_eq!(format_line_annotation(&metas), "\"val\" → yes");
    }

    #[test]
    fn format_line_annotation_command_mismatch() {
        let metas = vec![Some(NodeMeta::new(
            Role::Command,
            Some(Evidence::Match { matched: false }),
        ))];
        assert_eq!(format_line_annotation(&metas), "no");
    }

    #[test]
    fn format_line_annotation_command_match_ignored() {
        let metas = vec![Some(NodeMeta::new(
            Role::Command,
            Some(Evidence::Match { matched: true }),
        ))];
        assert_eq!(format_line_annotation(&metas), "");
    }

    #[test]
    fn format_line_annotation_arg_match_per_token() {
        let metas = vec![Some(NodeMeta::new(
            Role::ArgMatch,
            Some(Evidence::SetMembership {
                token: "\"rm\"".into(),
                observed: vec!["rm".into(), "ls".into()],
                matched: true,
            }),
        ))];
        assert_eq!(
            format_line_annotation(&metas),
            "\"\"rm\"\" ∈ {\"rm\", \"ls\"} → yes"
        );
    }

    #[test]
    fn format_line_annotation_positional_match() {
        let metas = vec![Some(NodeMeta::new(
            Role::PositionalMatch,
            Some(Evidence::Positional {
                actual: "push".into(),
                pattern_text: "\"pull\"".into(),
                matched: false,
            }),
        ))];
        assert_eq!(format_line_annotation(&metas), "\"push\" = \"pull\" → no");
    }

    #[test]
    fn format_line_annotation_empty() {
        let metas: Vec<Option<NodeMeta>> = vec![None, None];
        assert_eq!(format_line_annotation(&metas), "");
    }

    #[test]
    fn format_line_annotation_var_ref_matched() {
        let metas = vec![Some(NodeMeta::new(
            Role::VarRef {
                name: "build-mode".into(),
            },
            Some(Evidence::Match { matched: true }),
        ))];
        let result = format_line_annotation(&metas);
        assert!(result.contains("build-mode"));
        assert!(result.contains("yes"));
    }
}
