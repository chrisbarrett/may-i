// Trace producer. Lives in the CLI binary so `Doc` never enters the engine
// crate. Emits `TraceNode` trees and structural metadata; renderers consume
// via accessors only (see `crate::trace`).

use std::collections::BTreeSet;

use may_i_core::ast::{Effect, EffectResult, FlagsMode, Rule};
use may_i_core::doc::Doc;
use may_i_core::pattern::{ArgPattern, CommandPattern, MatchMode, Quantifier};
use may_i_core::primitives::ToDoc;
use may_i_core::{ContextFacts, Decision, FactQuery};

use may_i_engine::eval::PredicateResult;
use may_i_engine::fold::{
    ArgMatchDetail, ChildResult, EvalFold, FactDetail, PositionalElementDetail, PositionalMatchKind,
};

use crate::trace::TraceNode;
use crate::trace::node::{CaptureSource, Evidence, Layout, Role};

/// Role of a matched rule in the most-strict-wins combine for its scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CombineRole {
    /// Surviving `reason` (earliest in source order among rules tied at
    /// the strictest effect).
    ReasonSource,
    /// Matched at the strictest effect but dropped in favour of an earlier
    /// tied sibling for the `reason` field.
    TiedSibling,
}

/// A single trace entry produced by the fold.
#[derive(Clone)]
pub enum TraceEntry {
    /// Header for a compound command segment.
    SegmentHeader { command: String, decision: Decision },
    /// A rule evaluation, carrying the producer-decided trace node tree.
    Rule {
        node: TraceNode,
        line: Option<usize>,
        /// Pre-migration Doc for display when the config was migrated.
        pre_migration_doc: Option<Doc<()>>,
        /// Context facts active when this rule was evaluated.
        facts: Vec<(String, String)>,
        /// The command being evaluated, when this rule is inside a
        /// recursive `may-i` evaluation.
        inner_command: Option<String>,
        /// Role in the most-strict-wins combine; `None` for rules that did
        /// not contribute the strictest decision.
        combine_role: Option<CombineRole>,
    },
    /// An embedded command (substitution) was evaluated.
    EmbeddedCommand { source: String, decision: Decision },
    /// A rule's `:allow` was floored to `:ask` because a matcher it
    /// relied on tested an expansion-bearing word. Rendered as an
    /// annotation under the preceding rule rather than a silent
    /// no-match.
    UnresolvedExpansion { words: Vec<String> },
    /// No matching rule — default ask.
    DefaultAsk { reason: String },
    /// Parse diagnostics were emitted.
    ParseDiagnostics {
        diagnostics: Vec<may_i_shell_parser::ParseDiagnostic>,
    },
    /// Resolved parser for the command being evaluated.
    Parser {
        command: String,
        style: String,
        parameter_tokens: Vec<String>,
        flags: FlagsMode,
        rest_binding: Option<String>,
    },
}

// ── helpers ──────────────────────────────────────────────────────────────

fn from_pattern_doc(doc: Doc<()>) -> TraceNode {
    TraceNode::from_doc(doc)
}

fn plain_atom(s: impl Into<String>) -> TraceNode {
    TraceNode::plain_atom(s)
}

fn ellipsis() -> TraceNode {
    TraceNode::ellipsis()
}

fn dimmed(node: TraceNode) -> TraceNode {
    node.into_dimmed()
}

/// Mark a single rendered Effect tree's terminal node with EffectDecision
/// evidence. Used for unevaluated (skipped) bodies in `when` / `unless`.
fn effect_to_static_trace(effect: &Effect) -> TraceNode {
    let node = from_pattern_doc(effect.to_doc());
    apply_terminal_effect(node, effect)
}

fn apply_terminal_effect(node: TraceNode, effect: &Effect) -> TraceNode {
    match effect {
        Effect::Terminal { decision, reason } => node.with_role_and_evidence(
            Role::EffectDecision,
            Some(Evidence::Decision {
                decision: *decision,
                reason: reason.clone(),
            }),
        ),
        _ => node,
    }
}

fn command_pattern_to_doc(pattern: &CommandPattern) -> Doc<()> {
    match pattern {
        CommandPattern::Literal(s) => Doc::atom(format!("\"{}\"", s)),
        CommandPattern::Or(patterns) => {
            let mut cs = vec![Doc::atom("or")];
            cs.extend(patterns.iter().map(command_pattern_to_doc));
            if patterns.len() > 4 {
                Doc::broken_list(cs)
            } else {
                Doc::list(cs)
            }
        }
        _ => Doc::atom("<unknown-command-pattern>"),
    }
}

fn positional_arg_to_doc(p: &may_i_core::pattern::PositionalArg) -> Doc<()> {
    let inner = p.pattern.to_doc();
    match p.quantifier {
        Quantifier::One => inner,
        Quantifier::Optional => Doc::list(vec![Doc::atom("?"), inner]),
        Quantifier::OneOrMore => Doc::list(vec![Doc::atom("+"), inner]),
        Quantifier::ZeroOrMore => Doc::list(vec![Doc::atom("*"), inner]),
    }
}

fn capture_source(pattern: &ArgPattern) -> CaptureSource {
    match pattern {
        ArgPattern::Tail => CaptureSource::Tail,
        ArgPattern::Parameter {
            form: may_i_core::pattern::ParameterForm::Authorise,
            ..
        } => CaptureSource::Parameter,
        other => {
            unreachable!("engine produced a captured value for a non-capturing pattern: {other:?}")
        }
    }
}

fn arg_pattern_to_doc(pattern: &ArgPattern) -> Doc<()> {
    match pattern {
        ArgPattern::Ordered {
            mode: MatchMode::Positional,
            patterns,
            ..
        } => {
            let mut cs = vec![Doc::atom("positional")];
            cs.extend(patterns.iter().map(positional_arg_to_doc));
            Doc::list(cs)
        }
        ArgPattern::Ordered {
            mode: MatchMode::Exact,
            patterns,
            ..
        } => {
            let mut cs = vec![Doc::atom("exact")];
            cs.extend(patterns.iter().map(positional_arg_to_doc));
            Doc::list(cs)
        }
        ArgPattern::Anywhere(exprs) => {
            let mut cs = vec![Doc::atom("anywhere")];
            cs.extend(exprs.iter().map(|e| e.to_doc()));
            Doc::list(cs)
        }
        ArgPattern::Forbidden(exprs) => {
            let mut inner = vec![Doc::atom("anywhere")];
            inner.extend(exprs.iter().map(|e| e.to_doc()));
            Doc::list(vec![Doc::atom("not"), Doc::list(inner)])
        }
        ArgPattern::Flag { names } => {
            let names_doc = flag_names_to_doc(names);
            Doc::list(vec![Doc::atom("flag"), names_doc])
        }
        ArgPattern::Parameter { names, form } => {
            let names_doc = flag_names_to_doc(names);
            let form_doc = match form {
                may_i_core::pattern::ParameterForm::Match(expr) => expr.to_doc(),
                may_i_core::pattern::ParameterForm::Authorise => {
                    Doc::list(vec![Doc::atom("authorise")])
                }
            };
            Doc::list(vec![Doc::atom("parameter"), names_doc, form_doc])
        }
        ArgPattern::Tail => Doc::list(vec![
            Doc::atom("tail"),
            Doc::list(vec![Doc::atom("authorise")]),
        ]),
    }
}

fn flag_names_to_doc(names: &[String]) -> Doc<()> {
    if names.len() == 1 {
        Doc::atom(format!("\"{}\"", names[0]))
    } else {
        Doc::vector(
            names
                .iter()
                .map(|n| Doc::atom(format!("\"{n}\"")))
                .collect(),
        )
    }
}

fn fact_query_to_doc(query: &FactQuery) -> Doc<()> {
    Doc::list(vec![Doc::atom("has"), query.to_doc()])
}

/// True if the top-level pattern doc represents a forbidden pattern shape:
/// `(forbidden …)` or `(not (anywhere …))`.
fn pattern_is_forbidden(node: &TraceNode) -> bool {
    let Some(head_node) = node.children().first() else {
        return false;
    };
    let Some(head) = head_node.label() else {
        return false;
    };
    if head == "forbidden" {
        return true;
    }
    if head == "not"
        && let Some(inner) = node.children().get(1)
        && let Some(inner_head) = inner.children().first().and_then(|c| c.label())
    {
        return inner_head == "anywhere";
    }
    false
}

/// Truncate a matched `(anywhere t1 t2 t3 …)` node to `(anywhere t1)` —
/// producer-side replacement for the renderer's `truncate_matched_anywhere`.
fn truncate_matched_anywhere(node: TraceNode) -> TraceNode {
    if pattern_is_forbidden(&node) {
        return node;
    }
    let head = node
        .children()
        .first()
        .and_then(|c| c.label())
        .map(|s| s.to_string());
    let matched_set = matches!(
        node.evidence(),
        Some(Evidence::SetMembership { matched: true, .. })
    );
    if matched_set
        && head.as_deref() == Some("anywhere")
        && node.children().len() > 2
        && let Some(role) = match node.role() {
            Role::ArgMatch => Some(Role::ArgMatch),
            _ => None,
        }
    {
        let ev = node.evidence().cloned();
        let children = node
            .into_children()
            .expect("matched-anywhere node is a list");
        let kept: Vec<_> = children.into_iter().take(2).collect();
        return TraceNode::plain_list(kept).with_role_and_evidence(role, ev);
    }
    node
}

/// Distribute parent `Evidence::SetMembership` evidence to per-token child
/// atoms — producer-side replacement for the renderer's
/// `distribute_arg_annotations` pass.
fn distribute_anywhere(node: TraceNode) -> TraceNode {
    let head = node
        .children()
        .first()
        .and_then(|c| c.label())
        .map(|s| s.to_string());
    match (node.role(), node.evidence(), head.as_deref()) {
        (
            Role::ArgMatch,
            Some(Evidence::SetMembership {
                token,
                observed,
                matched,
            }),
            Some("anywhere") | Some("forbidden"),
        ) if node.children().len() > 1 && !token.is_empty() => {
            let observed = observed.clone();
            let matched = *matched;
            let mut cs = node
                .clone()
                .into_children()
                .expect("anywhere node is a list");
            let new_children: Vec<TraceNode> = cs
                .drain(..)
                .enumerate()
                .map(|(i, c)| {
                    if i == 0 {
                        c
                    } else if let Some(label) = c.label() {
                        let label = label.to_string();
                        TraceNode::arg_token_atom(label.clone(), label, observed.clone(), matched)
                    } else {
                        c
                    }
                })
                .collect();
            TraceNode::plain_list(new_children)
        }
        _ => node,
    }
}

/// Handle `(not (anywhere …))`: distribute the inner anywhere with inverted
/// match outcome.
fn distribute_forbidden_not(node: TraceNode) -> TraceNode {
    let head = node
        .children()
        .first()
        .and_then(|c| c.label())
        .map(|s| s.to_string());
    if head.as_deref() != Some("not") {
        return node;
    }
    let outer_matched = matches!(
        node.evidence(),
        Some(Evidence::SetMembership { matched: true, .. })
    );
    let observed = match node.evidence() {
        Some(Evidence::SetMembership { observed, .. }) => observed.clone(),
        _ => return node,
    };
    let mut children = node.into_children().expect("not-node is a list");
    if children.len() < 2 {
        return TraceNode::plain_list(children);
    }
    let inner = std::mem::replace(&mut children[1], TraceNode::plain_atom(""));
    let inner_head = inner
        .children()
        .first()
        .and_then(|c| c.label())
        .map(|s| s.to_string());
    let new_inner = if inner_head.as_deref() == Some("anywhere") {
        let inner_observed = match inner.evidence() {
            Some(Evidence::SetMembership { observed, .. }) => observed.clone(),
            _ => observed,
        };
        let inner_matched = match inner.evidence() {
            Some(Evidence::SetMembership { matched, .. }) => *matched,
            _ => !outer_matched,
        };
        let mut inner_children = inner.into_children().expect("anywhere is a list");
        let new_inner_children: Vec<TraceNode> = inner_children
            .drain(..)
            .enumerate()
            .map(|(i, c)| {
                if i == 0 {
                    c
                } else if let Some(label) = c.label() {
                    let label = label.to_string();
                    TraceNode::arg_token_atom(
                        label.clone(),
                        label,
                        inner_observed.clone(),
                        inner_matched,
                    )
                } else {
                    c
                }
            })
            .collect();
        TraceNode::plain_list(new_inner_children)
    } else {
        inner
    };
    children[1] = new_inner;
    TraceNode::plain_list(children)
}

/// Recursively walk a TraceNode tree, applying anywhere truncation and
/// distribution at each list node.
fn apply_structural_passes(node: TraceNode) -> TraceNode {
    let node = truncate_matched_anywhere(node);
    let node = distribute_forbidden_not(node);
    let node = distribute_anywhere(node);
    // Recurse into children.
    if node.label().is_some() {
        return node;
    }
    let role = node.role().clone();
    let evidence = node.evidence().cloned();
    let layout = node.layout();
    let was_dimmed = node.dimmed();
    let was_vector = node.is_vector();
    let mut children = node.into_children().unwrap_or_default();
    let new_children: Vec<TraceNode> = children.drain(..).map(apply_structural_passes).collect();
    let mut rebuilt = if was_vector {
        TraceNode::plain_vector(new_children)
    } else {
        TraceNode::plain_list(new_children)
    }
    .with_role_and_evidence(role, evidence)
    .with_layout(layout);
    if was_dimmed {
        rebuilt = rebuilt.with_dimmed_self();
    }
    rebuilt
}

/// Distribute positional comparison annotations onto literal atoms within
/// `(positional …)` / `(exact …)` children — producer-side replacement for
/// the renderer's positional distribution pass.
fn distribute_positional_comparisons(node: TraceNode, actual_arg: &str) -> TraceNode {
    if let Some(label) = node.label() {
        // Quoted literal atom?
        if label.starts_with('"') && label.ends_with('"') && label.len() > 2 {
            let inner_text = &label[1..label.len() - 1];
            let matched = actual_arg == inner_text;
            return TraceNode::positional_atom(
                label.to_string(),
                actual_arg.to_string(),
                label.to_string(),
                matched,
            );
        }
        return node;
    }
    let head = node
        .children()
        .first()
        .and_then(|c| c.label())
        .map(|s| s.to_string());
    match head.as_deref() {
        Some("or") => {
            let role = node.role().clone();
            let ev = node.evidence().cloned();
            let layout = node.layout();
            let dimmed = node.dimmed();
            let mut children = node.into_children().expect("or-list is a list");
            let new_children: Vec<TraceNode> = children
                .drain(..)
                .enumerate()
                .map(|(i, c)| {
                    if i == 0 {
                        c
                    } else {
                        distribute_positional_comparisons(c, actual_arg)
                    }
                })
                .collect();
            let mut out = TraceNode::plain_list(new_children)
                .with_role_and_evidence(role, ev)
                .with_layout(layout);
            if dimmed {
                out = out.with_dimmed_self();
            }
            out
        }
        Some("?" | "+" | "*") => {
            let role = node.role().clone();
            let ev = node.evidence().cloned();
            let layout = node.layout();
            let dimmed = node.dimmed();
            let mut children = node.into_children().expect("quantifier wrapper is a list");
            let new_children: Vec<TraceNode> = children
                .drain(..)
                .enumerate()
                .map(|(i, c)| {
                    if i == 1 {
                        distribute_positional_comparisons(c, actual_arg)
                    } else {
                        c
                    }
                })
                .collect();
            let mut out = TraceNode::plain_list(new_children)
                .with_role_and_evidence(role, ev)
                .with_layout(layout);
            if dimmed {
                out = out.with_dimmed_self();
            }
            out
        }
        _ => node,
    }
}

/// Extract positional arguments from an args slice, skipping flags and
/// stopping at `--`. Used by the producer to determine the "actual arg"
/// against which positional patterns compare.
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

/// Apply positional distribution to a `(positional|exact)` argv-match node
/// when the args have at least one positional value.
fn distribute_positional_at_top(node: TraceNode, args: &[String]) -> TraceNode {
    let head = node
        .children()
        .first()
        .and_then(|c| c.label())
        .map(|s| s.to_string());
    if !matches!(head.as_deref(), Some("positional") | Some("exact")) {
        return node;
    }
    let positional_args = extract_positional_args(args);
    let Some(first_arg) = positional_args.first().copied() else {
        return node;
    };
    let role = node.role().clone();
    let evidence = node.evidence().cloned();
    let layout = node.layout();
    let dimmed = node.dimmed();
    let first_arg = first_arg.to_string();
    let mut children = node.into_children().expect("positional is a list");
    let new_children: Vec<TraceNode> = children
        .drain(..)
        .enumerate()
        .map(|(i, c)| {
            if i == 0 {
                c
            } else {
                distribute_positional_comparisons(c, &first_arg)
            }
        })
        .collect();
    let mut out = TraceNode::plain_list(new_children)
        .with_role_and_evidence(role, evidence)
        .with_layout(layout);
    if dimmed {
        out = out.with_dimmed_self();
    }
    out
}

/// Truncate a long unannotated list down to head + keep + ellipsis + last.
/// Producer-side replacement for the renderer's `truncate_unevaluated` pass.
fn truncate_unevaluated(node: TraceNode, keep: usize) -> TraceNode {
    if node.label().is_some() {
        return node;
    }
    // Recurse first.
    let role = node.role().clone();
    let evidence = node.evidence().cloned();
    let layout = node.layout();
    let dimmed = node.dimmed();
    let was_vector = node.is_vector();
    let mut children = node.into_children().unwrap_or_default();
    let children: Vec<TraceNode> = children
        .drain(..)
        .map(|c| truncate_unevaluated(c, keep))
        .collect();
    let head_present = children
        .first()
        .map(|c| c.label().is_some())
        .unwrap_or(false);
    let all_unannotated =
        head_present && children[1..].iter().all(|c| !has_visible_evidence_rec(c));
    let len = children.len();
    let new_children = if all_unannotated && len > keep + 2 {
        let mut truncated: Vec<TraceNode> = Vec::with_capacity(keep + 3);
        truncated.push(children[0].clone());
        truncated.extend(children[1..=keep].iter().cloned());
        truncated.push(TraceNode::plain_atom("…").with_dimmed_self());
        truncated.push(children.last().cloned().unwrap());
        truncated
    } else {
        children
    };
    let mut rebuilt = if was_vector {
        TraceNode::plain_vector(new_children)
    } else {
        TraceNode::plain_list(new_children)
    }
    .with_role_and_evidence(role, evidence)
    .with_layout(layout);
    if dimmed {
        rebuilt = rebuilt.with_dimmed_self();
    }
    rebuilt
}

/// True if a node or any descendant carries Evidence (excluding RuleMatch
/// which doesn't render as right-column text).
fn has_visible_evidence_rec(node: &TraceNode) -> bool {
    let role_is_rule = matches!(node.role(), Role::Rule { .. });
    if !role_is_rule && node.evidence().is_some() {
        return true;
    }
    node.children().iter().any(has_visible_evidence_rec)
}

/// Propagate dimming down subtrees that carry no visible evidence — analog
/// of the renderer's `dim_unevaluated` pass.
fn dim_unevaluated(node: TraceNode) -> TraceNode {
    dim_unevaluated_inner(node, false).0
}

fn dim_unevaluated_inner(node: TraceNode, ancestor_annotated: bool) -> (TraceNode, usize) {
    let self_score = usize::from(
        node.evidence().is_some() && !matches!(node.role(), Role::Rule { .. } | Role::Plain),
    );
    let children_inherit = ancestor_annotated || self_score > 0;
    if node.label().is_some() {
        return (node, self_score);
    }
    let role = node.role().clone();
    let evidence = node.evidence().cloned();
    let layout = node.layout();
    let initially_dimmed = node.dimmed();
    let was_vector = node.is_vector();
    let mut children = node.into_children().unwrap_or_default();
    let mut total = self_score;
    let new_children: Vec<TraceNode> = children
        .drain(..)
        .map(|c| {
            let (c, n) = dim_unevaluated_inner(c, children_inherit);
            total += n;
            c
        })
        .collect();
    let mut rebuilt = if was_vector {
        TraceNode::plain_vector(new_children)
    } else {
        TraceNode::plain_list(new_children)
    }
    .with_role_and_evidence(role, evidence)
    .with_layout(layout);
    if initially_dimmed || (!ancestor_annotated && total == 0) {
        rebuilt = rebuilt.with_dimmed_self();
    }
    (rebuilt, total)
}

/// Build the children of a rule node: `(rule <command-pattern> <body>)`.
fn build_rule_children(command_node: TraceNode, effect_node: TraceNode) -> Vec<TraceNode> {
    vec![plain_atom("rule"), command_node, effect_node]
}

/// Annotate positional / exact pattern children with per-element match
/// details (bindings, regex matches).
fn annotate_positional_elements(
    node: TraceNode,
    elements: &[PositionalElementDetail],
) -> TraceNode {
    if elements.is_empty() {
        return node;
    }
    let head = node
        .children()
        .first()
        .and_then(|c| c.label())
        .map(|s| s.to_string());
    if !matches!(head.as_deref(), Some("positional") | Some("exact")) {
        return node;
    }
    let role = node.role().clone();
    let evidence = node.evidence().cloned();
    let layout = node.layout();
    let dimmed = node.dimmed();
    let mut children = node.into_children().expect("positional is a list");
    let head_atom = children.remove(0);
    let mut new_children = vec![head_atom];
    let mut elem_idx = 0;
    for child in children {
        if elem_idx < elements.len() {
            new_children.push(annotate_pattern_element(child, &elements[elem_idx]));
            elem_idx += 1;
        } else {
            new_children.push(child);
        }
    }
    let mut rebuilt = TraceNode::plain_list(new_children)
        .with_role_and_evidence(role, evidence)
        .with_layout(layout);
    if dimmed {
        rebuilt = rebuilt.with_dimmed_self();
    }
    rebuilt
}

fn annotate_pattern_element(node: TraceNode, detail: &PositionalElementDetail) -> TraceNode {
    // BindMatch: structural shape is a Vector with `:key` head.
    if let Some(bind) = &detail.binding
        && node.label().is_none()
    {
        let role = node.role().clone();
        let layout = node.layout();
        let dimmed = node.dimmed();
        let was_vector = node.is_vector();
        let mut children = node.into_children().expect("bind shape is a list");
        if children.len() >= 2
            && let Some(inner) = &bind.inner_match
        {
            let snd = std::mem::replace(&mut children[1], TraceNode::plain_atom(""));
            children[1] = annotate_expr_match(snd, inner);
        }
        let role_to_apply = match &role {
            Role::Plain => Role::BindMatch {
                key: bind.key.to_string(),
            },
            other => other.clone(),
        };
        let evidence_to_apply = Some(Evidence::Bind {
            value: bind.value.clone(),
        });
        let mut rebuilt = if was_vector {
            TraceNode::plain_vector(children)
        } else {
            TraceNode::plain_list(children)
        }
        .with_role_and_evidence(role_to_apply, evidence_to_apply)
        .with_layout(layout);
        if dimmed {
            rebuilt = rebuilt.with_dimmed_self();
        }
        return rebuilt;
    }

    if let PositionalMatchKind::Expr(expr_match) = &detail.match_kind {
        return annotate_expr_match(node, expr_match);
    }

    // Quantifier wrapper: recurse into the wrapped element.
    if node.label().is_none() {
        let head = node
            .children()
            .first()
            .and_then(|c| c.label())
            .map(|s| s.to_string());
        if matches!(head.as_deref(), Some("?") | Some("+") | Some("*"))
            && node.children().len() >= 2
        {
            let role = node.role().clone();
            let evidence = node.evidence().cloned();
            let layout = node.layout();
            let dimmed = node.dimmed();
            let mut children = node.into_children().unwrap();
            let inner = std::mem::replace(&mut children[1], TraceNode::plain_atom(""));
            children[1] = annotate_pattern_element(inner, detail);
            let mut rebuilt = TraceNode::plain_list(children)
                .with_role_and_evidence(role, evidence)
                .with_layout(layout);
            if dimmed {
                rebuilt = rebuilt.with_dimmed_self();
            }
            return rebuilt;
        }
    }

    node
}

fn annotate_expr_match(node: TraceNode, detail: &may_i_engine::fold::ExprMatchDetail) -> TraceNode {
    use may_i_engine::fold::ExprMatchDetail;
    match detail {
        ExprMatchDetail::Regex {
            pattern,
            actual,
            matched,
        } => {
            let label = node.label().map(|s| s.to_string()).unwrap_or_default();
            let layout = node.layout();
            let dimmed = node.dimmed();
            let mut rebuilt =
                TraceNode::regex_match_atom(label, pattern.clone(), actual.clone(), *matched)
                    .with_layout(layout);
            if dimmed {
                rebuilt = rebuilt.with_dimmed_self();
            }
            rebuilt
        }
        _ => node,
    }
}

/// Relocate an effect-decision evidence value onto a specific cond-branch
/// body within positional children — supports the trailing-cond shorthand
/// emitted by `effect_arg_continuation`.
fn move_evidence_to_cond_branch(
    children: &mut [TraceNode],
    branch_idx: usize,
    decision: Decision,
    reason: Option<String>,
) {
    for child in children.iter_mut() {
        if child.label().is_some() {
            continue;
        }
        let head = child
            .children()
            .first()
            .and_then(|c| c.label())
            .map(|s| s.to_string());
        if head.as_deref() != Some("cond") {
            continue;
        }
        let Some(cond_children) = child.children_mut() else {
            continue;
        };
        let clause_idx = branch_idx + 1;
        if clause_idx >= cond_children.len() {
            continue;
        }
        let clause = &mut cond_children[clause_idx];
        let Some(clause_parts) = clause.children_mut() else {
            continue;
        };
        if let Some(body) = clause_parts.last_mut() {
            let new_body = std::mem::replace(body, TraceNode::plain_atom(""))
                .with_role_and_evidence(
                    Role::EffectDecision,
                    Some(Evidence::Decision {
                        decision,
                        reason: reason.clone(),
                    }),
                );
            *body = new_body;
            return;
        }
    }
}

// ── TracingFold ──────────────────────────────────────────────────────────

pub(crate) struct TracingFold {
    pub traces: Vec<TraceEntry>,
    source_text: Option<String>,
    pre_migration_forms: Option<Vec<(may_i_core::Span, Doc<()>)>>,
    recursive_trace_starts: Vec<usize>,
    pending_inner_traces: Vec<(String, Vec<TraceEntry>)>,
    match_stack: Vec<Vec<usize>>,
}

impl Default for TracingFold {
    fn default() -> Self {
        Self::new()
    }
}

impl TracingFold {
    pub(crate) fn new() -> Self {
        Self {
            traces: Vec::new(),
            source_text: None,
            pre_migration_forms: None,
            recursive_trace_starts: Vec::new(),
            pending_inner_traces: Vec::new(),
            match_stack: vec![Vec::new()],
        }
    }

    pub(crate) fn from_load_result(lr: &may_i_config::LoadResult) -> Self {
        Self {
            traces: Vec::new(),
            source_text: lr.source_text.clone(),
            pre_migration_forms: lr.pre_migration_forms.clone(),
            recursive_trace_starts: Vec::new(),
            pending_inner_traces: Vec::new(),
            match_stack: vec![Vec::new()],
        }
    }

    fn append_inner_traces(&mut self, (cmd, mut traces): (String, Vec<TraceEntry>)) {
        if let Some(TraceEntry::Rule { inner_command, .. }) = traces.first_mut() {
            *inner_command = Some(cmd);
        }
        self.traces.extend(traces);
    }

    fn line_of(&self, byte_offset: usize) -> Option<usize> {
        let text = self.source_text.as_ref()?;
        Some(text[..byte_offset.min(text.len())].matches('\n').count() + 1)
    }

    fn find_pre_migration_doc(&self, span: may_i_core::Span) -> Option<Doc<()>> {
        let forms = self.pre_migration_forms.as_ref()?;
        forms
            .iter()
            .find(|(form_span, _)| form_span.start <= span.start && span.start < form_span.end)
            .map(|(_, doc)| doc.clone())
    }
}

impl EvalFold for TracingFold {
    type EffectOut = (EffectResult, TraceNode);
    type PredicateOut = (PredicateResult, TraceNode);

    fn effect_result(out: &Self::EffectOut) -> &EffectResult {
        &out.0
    }

    fn predicate_result(out: &Self::PredicateOut) -> PredicateResult {
        out.0
    }

    fn effect_terminal(&mut self, effect: &Effect, result: EffectResult) -> Self::EffectOut {
        let display_effect = match &result {
            EffectResult::Decision(decision, reason) => Effect::Terminal {
                decision: *decision,
                reason: reason.clone(),
            },
            EffectResult::Nil => effect.clone(),
        };
        let mut node = from_pattern_doc(display_effect.to_doc());
        if let EffectResult::Decision(decision, reason) = &result {
            node = node.with_role_and_evidence(
                Role::EffectDecision,
                Some(Evidence::Decision {
                    decision: *decision,
                    reason: reason.clone(),
                }),
            );
        }
        (result, node)
    }

    fn effect_nil(&mut self, _effect: &Effect) -> Self::EffectOut {
        (EffectResult::Nil, plain_atom("nil"))
    }

    fn effect_command_match(
        &mut self,
        pattern: &CommandPattern,
        cmd: &str,
        matched: bool,
    ) -> Self::EffectOut {
        let node = match pattern {
            CommandPattern::Or(sub_patterns) => {
                let mut cs: Vec<TraceNode> = vec![plain_atom("or")];
                let mut has_pre_ellipsis = false;
                let mut has_post_match = false;
                let mut seen_match = false;
                for sub in sub_patterns {
                    let sub_matched = sub.is_match(cmd);
                    if sub_matched {
                        let sub_node = from_pattern_doc(command_pattern_to_doc(sub))
                            .with_role_and_evidence(
                                Role::Command,
                                Some(Evidence::Match { matched: true }),
                            );
                        cs.push(sub_node);
                        seen_match = true;
                        has_post_match = false;
                    } else if !seen_match {
                        if !has_pre_ellipsis {
                            cs.push(ellipsis());
                            has_pre_ellipsis = true;
                        }
                    } else {
                        has_post_match = true;
                    }
                }
                if has_post_match {
                    cs.push(ellipsis());
                }
                TraceNode::command_list(cs, matched)
            }
            _ => from_pattern_doc(command_pattern_to_doc(pattern))
                .with_role_and_evidence(Role::Command, Some(Evidence::Match { matched })),
        };
        let result = if matched {
            EffectResult::Decision(Decision::Allow, None)
        } else {
            EffectResult::Nil
        };
        (result, node)
    }

    fn effect_arg_match(
        &mut self,
        pattern: &ArgPattern,
        args: &[String],
        matched: bool,
        detail: ArgMatchDetail,
    ) -> Self::EffectOut {
        let mut node = from_pattern_doc(arg_pattern_to_doc(pattern));
        node = annotate_positional_elements(node, &detail.positional_elements);

        let captured = detail
            .captured_value
            .as_ref()
            .map(|v| (capture_source(pattern), v.clone()));

        let role = Role::ArgMatch;
        let evidence = if let Some((source, value)) = captured.clone() {
            Some(Evidence::CapturedValue { source, value })
        } else if !detail.search_tokens.is_empty() {
            Some(Evidence::SetMembership {
                token: detail.search_tokens.first().cloned().unwrap_or_default(),
                observed: detail.arg_set.clone(),
                matched,
            })
        } else {
            Some(Evidence::Match { matched })
        };
        node = node.with_role_and_evidence(role, evidence);

        // For forbidden patterns, annotate the inner anywhere with inverted
        // match so distribution sees the correct flag.
        if matches!(pattern, ArgPattern::Forbidden(_))
            && let Some(children) = node.children_mut()
            && children.len() == 2
        {
            let inner = std::mem::replace(&mut children[1], TraceNode::plain_atom(""));
            let inner_inverted_evidence = Some(Evidence::SetMembership {
                token: detail.search_tokens.first().cloned().unwrap_or_default(),
                observed: detail.arg_set.clone(),
                matched: !matched,
            });
            children[1] = inner.with_role_and_evidence(Role::ArgMatch, inner_inverted_evidence);
        }

        // Apply positional distribution at the top if appropriate.
        node = distribute_positional_at_top(node, args);
        node = apply_structural_passes(node);

        let result = if matched {
            EffectResult::Decision(Decision::Allow, None)
        } else {
            EffectResult::Nil
        };
        (result, node)
    }

    fn effect_and(
        &mut self,
        children: Vec<ChildResult<Self::EffectOut>>,
        result: EffectResult,
    ) -> Self::EffectOut {
        let mut docs = vec![plain_atom("and")];
        for child in children {
            match child {
                ChildResult::Evaluated((_, node)) => docs.push(node),
                ChildResult::Skipped => docs.push(ellipsis()),
            }
        }
        let satisfied = !result.is_nil();
        (result, TraceNode::combinator(docs, satisfied, true))
    }

    fn effect_or(
        &mut self,
        children: Vec<ChildResult<Self::EffectOut>>,
        result: EffectResult,
    ) -> Self::EffectOut {
        let mut docs = vec![plain_atom("or")];
        for child in children {
            match child {
                ChildResult::Evaluated((_, node)) => docs.push(node),
                ChildResult::Skipped => docs.push(ellipsis()),
            }
        }
        let satisfied = !result.is_nil();
        (result, TraceNode::combinator(docs, satisfied, true))
    }

    fn effect_not(&mut self, child: Self::EffectOut, result: EffectResult) -> Self::EffectOut {
        let docs = vec![plain_atom("not"), child.1];
        let satisfied = !result.is_nil();
        (result, TraceNode::combinator(docs, satisfied, false))
    }

    fn effect_when(
        &mut self,
        pred: Self::PredicateOut,
        body: ChildResult<Self::EffectOut>,
        body_effect: &Effect,
        result: EffectResult,
    ) -> Self::EffectOut {
        let body_node = match body {
            ChildResult::Evaluated((_, node)) => node,
            ChildResult::Skipped => dimmed(effect_to_static_trace(body_effect)),
        };
        let docs = vec![plain_atom("when"), pred.1, body_node];
        let satisfied = !result.is_nil();
        (result, TraceNode::combinator(docs, satisfied, true))
    }

    fn effect_unless(
        &mut self,
        pred: Self::PredicateOut,
        body: ChildResult<Self::EffectOut>,
        body_effect: &Effect,
        result: EffectResult,
    ) -> Self::EffectOut {
        let body_node = match body {
            ChildResult::Evaluated((_, node)) => node,
            ChildResult::Skipped => dimmed(effect_to_static_trace(body_effect)),
        };
        let docs = vec![plain_atom("unless"), pred.1, body_node];
        let satisfied = !result.is_nil();
        (result, TraceNode::combinator(docs, satisfied, true))
    }

    fn effect_if(
        &mut self,
        pred: Self::PredicateOut,
        then_: ChildResult<Self::EffectOut>,
        else_: ChildResult<Self::EffectOut>,
        result: EffectResult,
    ) -> Self::EffectOut {
        let then_node = match then_ {
            ChildResult::Evaluated((_, node)) => node,
            ChildResult::Skipped => ellipsis(),
        };
        let else_node = match else_ {
            ChildResult::Evaluated((_, node)) => node,
            ChildResult::Skipped => ellipsis(),
        };
        let docs = vec![plain_atom("if"), pred.1, then_node, else_node];
        let satisfied = !result.is_nil();
        (result, TraceNode::combinator(docs, satisfied, true))
    }

    fn effect_cond(
        &mut self,
        branches: Vec<(
            ChildResult<Self::PredicateOut>,
            ChildResult<Self::EffectOut>,
        )>,
        fallback: Option<ChildResult<Self::EffectOut>>,
        result: EffectResult,
    ) -> Self::EffectOut {
        let mut docs = vec![plain_atom("cond")];

        let trailing_skipped_start = {
            let mut start = branches.len();
            for (i, (pred, body)) in branches.iter().enumerate().rev() {
                if matches!((pred, body), (ChildResult::Skipped, ChildResult::Skipped)) {
                    start = i;
                } else {
                    break;
                }
            }
            start
        };
        let has_trailing_skipped = trailing_skipped_start < branches.len();

        for (i, (pred, body)) in branches.into_iter().enumerate() {
            if i >= trailing_skipped_start {
                break;
            }
            let pred_node = match pred {
                ChildResult::Evaluated((_, node)) => node,
                ChildResult::Skipped => ellipsis(),
            };
            let body_node = match body {
                ChildResult::Evaluated((_, node)) => node,
                ChildResult::Skipped => ellipsis(),
            };
            docs.push(TraceNode::plain_list(vec![pred_node, body_node]));
        }

        if has_trailing_skipped {
            docs.push(ellipsis());
        } else if let Some(fb) = fallback {
            match fb {
                ChildResult::Evaluated((_, node)) => docs.push(node),
                ChildResult::Skipped => docs.push(ellipsis()),
            }
        }

        let satisfied = !result.is_nil();
        (result, TraceNode::combinator(docs, satisfied, true))
    }

    fn effect_arg_continuation(
        &mut self,
        pattern: &ArgPattern,
        args: &[String],
        detail: ArgMatchDetail,
        continuation: Self::EffectOut,
    ) -> Self::EffectOut {
        let result = continuation.0.clone();
        let mut node = from_pattern_doc(arg_pattern_to_doc(pattern));
        node = annotate_positional_elements(node, &detail.positional_elements);

        let captured = detail
            .captured_value
            .as_ref()
            .map(|v| (capture_source(pattern), v.clone()));
        let evidence_for_node = if let Some((source, value)) = captured.clone() {
            Some(Evidence::CapturedValue { source, value })
        } else if !detail.search_tokens.is_empty() {
            Some(Evidence::SetMembership {
                token: detail.search_tokens.first().cloned().unwrap_or_default(),
                observed: detail.arg_set.clone(),
                matched: detail.matched,
            })
        } else {
            Some(Evidence::Match {
                matched: detail.matched,
            })
        };
        node = node.with_role_and_evidence(Role::ArgMatch, evidence_for_node);
        node = distribute_positional_at_top(node, args);

        let mut children = node.into_children().unwrap_or_default();

        let trailing_cond_branch = match pattern {
            ArgPattern::Ordered {
                mode: MatchMode::Positional,
                continuation: None,
                ..
            }
            | ArgPattern::Ordered {
                mode: MatchMode::Exact,
                continuation: None,
                ..
            } => detail
                .positional_elements
                .last()
                .and_then(|e| match e.match_kind {
                    PositionalMatchKind::CondBranch(idx) => Some(idx),
                    _ => None,
                }),
            _ => None,
        };

        if let Some(branch_idx) = trailing_cond_branch
            && let Some(Evidence::Decision { decision, reason }) = continuation.1.evidence()
        {
            let decision = *decision;
            let reason = reason.clone();
            move_evidence_to_cond_branch(&mut children, branch_idx, decision, reason);
            let cont_clean = continuation
                .1
                .clone()
                .with_role_and_evidence(Role::Plain, None);
            children.push(cont_clean);
        } else {
            children.push(continuation.1);
        }

        let captured_evidence = if let Some((source, value)) = captured {
            Some(Evidence::CapturedValue { source, value })
        } else {
            Some(Evidence::Match {
                matched: detail.matched,
            })
        };
        let wrapper = TraceNode::plain_list(children)
            .with_role_and_evidence(Role::ArgMatch, captured_evidence)
            .with_layout(Layout::AlwaysBreak);
        (result, wrapper)
    }

    fn begin_recursive_eval(&mut self) {
        self.recursive_trace_starts.push(self.traces.len());
        self.match_stack.push(Vec::new());
    }

    fn rules_combined(&mut self, tied_rule_indices: &[usize], reason_source_index: Option<usize>) {
        let top: Vec<usize> = self.match_stack.last().cloned().unwrap_or_default();
        for &match_pos in tied_rule_indices {
            let Some(&trace_idx) = top.get(match_pos) else {
                continue;
            };
            let Some(TraceEntry::Rule { combine_role, .. }) = self.traces.get_mut(trace_idx) else {
                continue;
            };
            *combine_role = if Some(match_pos) == reason_source_index {
                Some(CombineRole::ReasonSource)
            } else {
                Some(CombineRole::TiedSibling)
            };
        }
        if let Some(top) = self.match_stack.last_mut() {
            top.clear();
        }
        if self.match_stack.len() > 1 {
            self.match_stack.pop();
        }
    }

    fn record_parser(&mut self, command: &str, parser: &may_i_core::ast::ResolvedParser) {
        self.traces.push(TraceEntry::Parser {
            command: command.to_string(),
            style: parser.style.name().to_string(),
            parameter_tokens: parser.parameter_tokens(),
            flags: parser.flags_mode.clone(),
            rest_binding: parser.rest.as_ref().map(|b| b.to_string()),
        });
    }

    fn predicate_fact(
        &mut self,
        query: &FactQuery,
        result: PredicateResult,
        detail: FactDetail,
    ) -> Self::PredicateOut {
        let expected = query.to_source();
        let node = from_pattern_doc(fact_query_to_doc(query));
        let matched = result == PredicateResult::Match;
        let evidence = if let Some(observed) = detail.observed {
            let observed: BTreeSet<String> = observed.into_iter().collect();
            Some(Evidence::FactValues {
                expected,
                observed,
                matched,
            })
        } else if matches!(detail.failure_reason.as_deref(), Some("absent")) {
            Some(Evidence::FactAbsent)
        } else {
            Some(Evidence::Match { matched })
        };
        (
            result,
            node.with_role_and_evidence(Role::FactQuery, evidence),
        )
    }

    fn predicate_arg(
        &mut self,
        pattern: &ArgPattern,
        args: &[String],
        result: PredicateResult,
    ) -> Self::PredicateOut {
        let matched = result == PredicateResult::Match;
        let node = from_pattern_doc(arg_pattern_to_doc(pattern));
        let evidence = Some(Evidence::SetMembership {
            token: String::new(),
            observed: args.to_vec(),
            matched,
        });
        let node = node.with_role_and_evidence(Role::ArgMatch, evidence);
        // Truncate long unannotated child lists BEFORE distributing
        // positional evidence — otherwise the per-token evidence makes
        // every literal atom "annotated" and suppresses truncation.
        let node = truncate_unevaluated(node, 2);
        let node = distribute_positional_at_top(node, args);
        (result, apply_structural_passes(node))
    }

    fn predicate_and(
        &mut self,
        children: Vec<ChildResult<Self::PredicateOut>>,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        let mut docs = vec![plain_atom("and")];
        for child in children {
            match child {
                ChildResult::Evaluated((_, node)) => docs.push(node),
                ChildResult::Skipped => docs.push(ellipsis()),
            }
        }
        (result, TraceNode::combinator_plain(docs, true))
    }

    fn predicate_or(
        &mut self,
        children: Vec<ChildResult<Self::PredicateOut>>,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        let mut docs = vec![plain_atom("or")];
        for child in children {
            match child {
                ChildResult::Evaluated((_, node)) => docs.push(node),
                ChildResult::Skipped => docs.push(ellipsis()),
            }
        }
        (result, TraceNode::combinator_plain(docs, true))
    }

    fn predicate_not(
        &mut self,
        child: Self::PredicateOut,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        let docs = vec![plain_atom("not"), child.1];
        (result, TraceNode::combinator_plain(docs, false))
    }

    fn predicate_named(
        &mut self,
        name: &str,
        resolved: Self::PredicateOut,
        _result: PredicateResult,
    ) -> Self::PredicateOut {
        let matched = resolved.0 == PredicateResult::Match;
        let docs = vec![plain_atom(name), resolved.1];
        (
            resolved.0,
            TraceNode::var_ref(docs, name.to_string(), matched),
        )
    }

    fn predicate_bound(
        &mut self,
        binding: &may_i_core::ast::BindingName,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        let docs = vec![plain_atom("bound?"), plain_atom(binding.to_string())];
        (result, TraceNode::plain_list(docs))
    }

    fn predicate_matches(
        &mut self,
        binding: &may_i_core::ast::BindingName,
        _pattern: &may_i_core::pattern::Expr<may_i_core::ast::Effect>,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        let docs = vec![
            plain_atom("matches?"),
            plain_atom(binding.to_string()),
            plain_atom("<expr>"),
        ];
        (result, TraceNode::plain_list(docs))
    }

    fn predicate_every(
        &mut self,
        binding: &may_i_core::ast::BindingName,
        _pattern: &may_i_core::pattern::Expr<may_i_core::ast::Effect>,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        let docs = vec![
            plain_atom("every?"),
            plain_atom(binding.to_string()),
            plain_atom("<expr>"),
        ];
        (result, TraceNode::plain_list(docs))
    }

    fn predicate_some(
        &mut self,
        binding: &may_i_core::ast::BindingName,
        _pattern: &may_i_core::pattern::Expr<may_i_core::ast::Effect>,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        let docs = vec![
            plain_atom("some?"),
            plain_atom(binding.to_string()),
            plain_atom("<expr>"),
        ];
        (result, TraceNode::plain_list(docs))
    }

    fn rule_matched(
        &mut self,
        rule: &Rule,
        _line: Option<usize>,
        facts: &ContextFacts,
        command_out: Self::EffectOut,
        effect_out: Self::EffectOut,
    ) -> Self::EffectOut {
        let line = self.line_of(rule.span.start);
        let pre_migration_doc = self.find_pre_migration_doc(rule.span);
        let terminal_result = effect_out.0.clone();

        let children = build_rule_children(command_out.1, effect_out.1);
        let node = TraceNode::rule(children, line, true);
        let node = truncate_unevaluated(node, 2);
        let node = dim_unevaluated(node);
        let trace_idx = self.traces.len();
        self.traces.push(TraceEntry::Rule {
            node: node.clone(),
            line,
            pre_migration_doc,
            facts: flatten_facts(facts),
            inner_command: None,
            combine_role: None,
        });
        if let Some(top) = self.match_stack.last_mut() {
            top.push(trace_idx);
        }
        if let Some(inner) = self.pending_inner_traces.pop() {
            self.append_inner_traces(inner);
        }
        (terminal_result, node)
    }

    fn rule_not_matched(
        &mut self,
        rule: &Rule,
        facts: &ContextFacts,
        command_out: Self::EffectOut,
        effect_out: Self::EffectOut,
    ) -> Self::EffectOut {
        let line = self.line_of(rule.span.start);
        let pre_migration_doc = self.find_pre_migration_doc(rule.span);

        let children = build_rule_children(command_out.1, effect_out.1);
        let node = TraceNode::rule(children, line, false);
        let node = truncate_unevaluated(node, 2);
        let node = dim_unevaluated(node);
        self.traces.push(TraceEntry::Rule {
            node: node.clone(),
            line,
            pre_migration_doc,
            facts: flatten_facts(facts),
            inner_command: None,
            combine_role: None,
        });
        if let Some(inner) = self.pending_inner_traces.pop() {
            self.append_inner_traces(inner);
        }
        (EffectResult::Nil, node)
    }

    fn rule_skipped(&mut self, _rule: &Rule) -> Self::EffectOut {
        (EffectResult::Nil, plain_atom("…"))
    }

    fn default_ask(&mut self, reason: &str) -> Self::EffectOut {
        let node = TraceNode::plain_list(vec![
            plain_atom("default"),
            plain_atom(":ask"),
            plain_atom(format!("\"{}\"", reason)),
        ])
        .with_role_and_evidence(
            Role::EffectDecision,
            Some(Evidence::Decision {
                decision: Decision::Ask,
                reason: Some(reason.to_string()),
            }),
        );
        self.traces.push(TraceEntry::DefaultAsk {
            reason: reason.to_string(),
        });
        (
            EffectResult::Decision(Decision::Ask, Some(reason.to_string())),
            node,
        )
    }

    fn embedded_command(&mut self, source: &str, decision: Decision) {
        self.traces.push(TraceEntry::EmbeddedCommand {
            source: source.to_string(),
            decision,
        });
    }

    fn unresolved_floor(&mut self, words: &[String]) {
        self.traces.push(TraceEntry::UnresolvedExpansion {
            words: words.to_vec(),
        });
    }
}

fn flatten_facts(facts: &ContextFacts) -> Vec<(String, String)> {
    facts
        .iter()
        .flat_map(|(k, vs)| vs.iter().map(move |v| (k.to_string(), v.clone())))
        .collect()
}

impl std::fmt::Debug for TraceEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SegmentHeader { command, .. } => write!(f, "SegmentHeader({command})"),
            Self::Rule { line, .. } => write!(f, "Rule(line={line:?})"),
            Self::EmbeddedCommand { source, .. } => write!(f, "EmbeddedCommand({source})"),
            Self::UnresolvedExpansion { words } => {
                write!(f, "UnresolvedExpansion({})", words.join(", "))
            }
            Self::DefaultAsk { reason } => write!(f, "DefaultAsk({reason})"),
            Self::ParseDiagnostics { .. } => write!(f, "ParseDiagnostics"),
            Self::Parser { command, .. } => write!(f, "Parser({command})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::Span;
    use may_i_core::ast::{Config, Spanned};
    use may_i_engine::eval::evaluate_with_fold;
    use may_i_engine::fold::PureFold;
    use may_i_engine::test_generators::*;
    use proptest::prelude::*;

    fn dummy_span() -> Span {
        Span::new(0, 0)
    }

    fn spanned<T>(value: T) -> Spanned<T> {
        Spanned::new(value, dummy_span())
    }

    fn make_config(rules: Vec<Rule>) -> Config {
        Config {
            rules,
            ..Config::default()
        }
    }

    fn make_rule(command: CommandPattern, effect: Effect) -> Rule {
        Rule::new(
            spanned(Effect::CommandPattern(command)),
            spanned(effect),
            vec![],
            dummy_span(),
        )
    }

    fn eval_tracing(config: &Config, cmd: &str, args: &[String]) -> Vec<TraceEntry> {
        let facts = ContextFacts::default();
        let mut fold = TracingFold::new();
        evaluate_with_fold(cmd, args, config, &facts, &mut fold).unwrap();
        fold.traces
    }

    fn terminal(decision: Decision, reason: &str) -> Effect {
        Effect::Terminal {
            decision,
            reason: Some(reason.into()),
        }
    }

    #[test]
    fn tied_rules_at_strictest_marked_reason_source_and_sibling() {
        let cfg = make_config(vec![
            make_rule(
                CommandPattern::Literal("rm".into()),
                terminal(Decision::Deny, "primary"),
            ),
            make_rule(
                CommandPattern::Literal("rm".into()),
                terminal(Decision::Deny, "loaded"),
            ),
        ]);
        let entries = eval_tracing(&cfg, "rm", &[]);
        let rule_entries: Vec<(usize, Option<CombineRole>)> = entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                if let TraceEntry::Rule { combine_role, .. } = e {
                    Some((i, *combine_role))
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(rule_entries.len(), 2, "both rules should appear in trace");
        assert_eq!(rule_entries[0].1, Some(CombineRole::ReasonSource));
        assert_eq!(rule_entries[1].1, Some(CombineRole::TiedSibling));
    }

    #[test]
    fn sole_strictest_rule_has_no_tied_sibling_marker() {
        let cfg = make_config(vec![
            make_rule(
                CommandPattern::Literal("rm".into()),
                terminal(Decision::Allow, "allow1"),
            ),
            make_rule(
                CommandPattern::Literal("rm".into()),
                terminal(Decision::Deny, "the deny"),
            ),
            make_rule(
                CommandPattern::Literal("rm".into()),
                terminal(Decision::Allow, "allow2"),
            ),
        ]);
        let entries = eval_tracing(&cfg, "rm", &[]);
        let combines: Vec<Option<CombineRole>> = entries
            .iter()
            .filter_map(|e| {
                if let TraceEntry::Rule { combine_role, .. } = e {
                    Some(*combine_role)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(combines.len(), 3);
        let strict_marks: Vec<_> = combines.iter().filter(|m| m.is_some()).collect();
        assert_eq!(
            strict_marks.len(),
            1,
            "only the sole Deny rule should be marked"
        );
    }

    proptest! {
        #[test]
        fn tracing_fold_matches_pure_fold(
            cfg in any_config(3),
            (cmd, args, facts) in any_eval_context_data(),
        ) {
            let mut pure_fold = PureFold;
            let pure_result = evaluate_with_fold(
                cmd.as_str(),
                &args,
                &cfg,
                &facts,
                &mut pure_fold,
            ).unwrap();
            let mut tracing_fold = TracingFold::new();
            let tracing_result = evaluate_with_fold(
                cmd.as_str(),
                &args,
                &cfg,
                &facts,
                &mut tracing_fold,
            ).unwrap();
            prop_assert_eq!(
                pure_result.decision, tracing_result.decision,
                "TracingFold must produce the same decision as PureFold"
            );
            prop_assert_eq!(
                pure_result.reason, tracing_result.reason,
                "TracingFold must produce the same reason as PureFold"
            );
        }
    }

    #[test]
    fn rule_node_carries_role_rule_and_match_evidence() {
        let cfg = make_config(vec![make_rule(
            CommandPattern::Literal("rm".into()),
            terminal(Decision::Allow, "ok"),
        )]);
        let entries = eval_tracing(&cfg, "rm", &[]);
        let Some(TraceEntry::Rule { node, .. }) = entries
            .iter()
            .find(|e| matches!(e, TraceEntry::Rule { .. }))
        else {
            panic!("expected at least one Rule entry, got: {entries:?}");
        };
        assert!(matches!(node.role(), Role::Rule { .. }));
    }
}
