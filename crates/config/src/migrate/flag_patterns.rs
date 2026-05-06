//! Migrate string-literal flag matchers into structured `(flag …)` and
//! `(parameter …)` patterns.
//!
//! Three shapes are rewritten:
//!
//! - `(anywhere "-x")`        → `(flag "x")`
//! - `(forbidden "-x")`       → `(not (flag "x"))`
//! - `(positional "-c" . R)`  → `(parameter "c" R)`
//!
//! Mixed-token cases such as `(anywhere "-x" "verb")` are split: the
//! flag-prefixed literals are converted to `(flag …)` patterns and the rest
//! remain in an `(anywhere …)` pattern, joined with `(and …)`.
//!
//! Long flags `--foo` map to `(flag "foo")`; short flags `-x` map to
//! `(flag "x")`. The `-` prefix is the trigger — bare literals like `"verb"`
//! are left alone.

#![allow(clippy::vec_box)]

use super::helpers::{rebuild_list, strip_whitespace_trivia, tagged_list};
use may_i_sexpr::cst::{CstNode, Shape, TriviaAnn};

pub(crate) fn rule_anywhere_to_flag(node: &CstNode) -> Option<Box<CstNode>> {
    if let Some(transformed) = rewrite_node(node) {
        return Some(transformed);
    }
    recurse_children(node)
}

/// Try to rewrite `node` itself (one level). Returns `None` if no rewrite
/// applies at this level.
fn rewrite_node(node: &CstNode) -> Option<Box<CstNode>> {
    if let Some(rewritten) = rewrite_anywhere(node) {
        return Some(rewritten);
    }
    if let Some(rewritten) = rewrite_forbidden(node) {
        return Some(rewritten);
    }
    if let Some(rewritten) = rewrite_positional_dot_to_parameter(node) {
        return Some(rewritten);
    }
    None
}

fn recurse_children(node: &CstNode) -> Option<Box<CstNode>> {
    let list = node.as_list()?;
    let mut new_children = Vec::with_capacity(list.len());
    let mut changed = false;
    for child in list {
        if let Some(transformed) = rule_anywhere_to_flag(child) {
            new_children.push(transformed);
            changed = true;
        } else {
            new_children.push(child.clone());
        }
    }
    if changed {
        return Some(rebuild_list(node, new_children));
    }
    None
}

/// `(anywhere LIT…)` — `anywhere` semantics is "at least one literal matches",
/// so multiple flag-prefixed entries combine with `(or …)`. Non-flag entries
/// (e.g. `"verb"`) stay in a residual `(anywhere …)` clause that joins the
/// flag disjunction with `(and …)`.
fn rewrite_anywhere(node: &CstNode) -> Option<Box<CstNode>> {
    let children = tagged_list("anywhere", node)?;
    if children.len() < 2 {
        return None;
    }
    let (flags, others) = split_flag_literals(&children[1..]);
    if flags.is_empty() {
        return None;
    }
    let flag_clauses: Vec<Box<CstNode>> = flags
        .into_iter()
        .map(|name| build_flag_pattern(&name))
        .collect();
    let flag_clause = combine_with("or", flag_clauses);
    let mut clauses = vec![flag_clause];
    if !others.is_empty() {
        clauses.push(build_anywhere(&children[0], &others));
    }
    Some(combine_with_and_outer(node, clauses))
}

/// `(forbidden LIT…)` — `forbidden` semantics is "none of these match",
/// equivalent to `(and (not L1) (not L2) …)`. Each flag-prefixed literal
/// becomes `(not (flag …))`; non-flag literals stay in a residual
/// `(forbidden …)` clause. Multiple clauses combine with `(and …)`.
fn rewrite_forbidden(node: &CstNode) -> Option<Box<CstNode>> {
    let children = tagged_list("forbidden", node)?;
    if children.len() < 2 {
        return None;
    }
    let (flags, others) = split_flag_literals(&children[1..]);
    if flags.is_empty() {
        return None;
    }
    let mut clauses: Vec<Box<CstNode>> = flags
        .into_iter()
        .map(|name| wrap_not(build_flag_pattern(&name)))
        .collect();
    if !others.is_empty() {
        clauses.push(build_forbidden(&children[0], &others));
    }
    Some(combine_with_and_outer(node, clauses))
}

/// `(positional "-c" . R)` (and equivalents) → `(parameter "c" R)`. Only the
/// first positional matters; if there are additional patterns before the
/// dot, we leave the form alone.
fn rewrite_positional_dot_to_parameter(node: &CstNode) -> Option<Box<CstNode>> {
    let children = tagged_list("positional", node)?;
    // Need at least: tag, flag-literal, ".", continuation
    if children.len() != 4 {
        return None;
    }
    let flag = literal_value(&children[1])?;
    let name = strip_flag_prefix(&flag)?;
    if children[2].as_atom() != Some(".") {
        return None;
    }
    let cont = &children[3];

    let parameter_tag = Box::new(CstNode::atom(
        "parameter",
        TriviaAnn {
            leading: children[0].ann.leading.clone(),
            trailing: children[0].ann.trailing.clone(),
            span: children[0].ann.span,
        },
    ));
    let name_node = Box::new(CstNode {
        ann: children[1].ann.clone(),
        shape: Shape::String(name),
    });
    let cont_clone = Box::new(strip_whitespace_trivia(cont));

    Some(Box::new(CstNode::list(
        vec![parameter_tag, name_node, cont_clone],
        TriviaAnn {
            leading: node.ann.leading.clone(),
            trailing: node.ann.trailing.clone(),
            span: node.ann.span,
        },
    )))
}

/// Partition children into ("-prefixed flag names without the dash", "other
/// literal nodes left intact"). Anything that is not a string literal at all
/// goes into `others` unchanged.
fn split_flag_literals(items: &[Box<CstNode>]) -> (Vec<String>, Vec<Box<CstNode>>) {
    let mut flags = Vec::new();
    let mut others = Vec::new();
    for item in items {
        match literal_value(item).and_then(|s| strip_flag_prefix(&s)) {
            Some(name) => flags.push(name),
            None => others.push(item.clone()),
        }
    }
    (flags, others)
}

/// Returns the string contents of a literal-shaped node (string OR symbol)
/// when it could plausibly be a flag spelling. Keywords are excluded — they
/// cannot start with `-`.
fn literal_value(node: &CstNode) -> Option<String> {
    match &node.shape {
        Shape::String(s) => Some(s.clone()),
        Shape::Symbol(s) => Some(s.clone()),
        _ => None,
    }
}

/// `"-x"` → `Some("x")`; `"--force"` → `Some("force")`; non-flag literals →
/// `None`.
fn strip_flag_prefix(s: &str) -> Option<String> {
    if let Some(rest) = s.strip_prefix("--") {
        if rest.is_empty() {
            return None;
        }
        return Some(rest.to_string());
    }
    if let Some(rest) = s.strip_prefix('-') {
        if rest.is_empty() {
            return None;
        }
        return Some(rest.to_string());
    }
    None
}

fn build_flag_pattern(name: &str) -> Box<CstNode> {
    let tag = Box::new(CstNode::atom("flag", TriviaAnn::default()));
    let name_node = Box::new(CstNode {
        ann: TriviaAnn::default(),
        shape: Shape::String(name.to_string()),
    });
    Box::new(CstNode::list(vec![tag, name_node], TriviaAnn::default()))
}

fn build_anywhere(original_tag: &CstNode, items: &[Box<CstNode>]) -> Box<CstNode> {
    let tag = Box::new(CstNode::atom(
        "anywhere",
        TriviaAnn {
            leading: original_tag.ann.leading.clone(),
            trailing: original_tag.ann.trailing.clone(),
            span: original_tag.ann.span,
        },
    ));
    let mut children = vec![tag];
    for item in items {
        children.push(Box::new(strip_whitespace_trivia(item)));
    }
    Box::new(CstNode::list(children, TriviaAnn::default()))
}

fn build_forbidden(original_tag: &CstNode, items: &[Box<CstNode>]) -> Box<CstNode> {
    let tag = Box::new(CstNode::atom(
        "forbidden",
        TriviaAnn {
            leading: original_tag.ann.leading.clone(),
            trailing: original_tag.ann.trailing.clone(),
            span: original_tag.ann.span,
        },
    ));
    let mut children = vec![tag];
    for item in items {
        children.push(Box::new(strip_whitespace_trivia(item)));
    }
    Box::new(CstNode::list(children, TriviaAnn::default()))
}

fn wrap_not(inner: Box<CstNode>) -> Box<CstNode> {
    let tag = Box::new(CstNode::atom("not", TriviaAnn::default()));
    Box::new(CstNode::list(vec![tag, inner], TriviaAnn::default()))
}

/// Single clause → emit it directly. Multiple clauses → wrap in
/// `(<combinator> …)`. Used for inner combinators where the original node's
/// trivia does not need to follow.
fn combine_with(combinator: &str, mut clauses: Vec<Box<CstNode>>) -> Box<CstNode> {
    if clauses.len() == 1 {
        return clauses.pop().unwrap();
    }
    let tag = Box::new(CstNode::atom(combinator, TriviaAnn::default()));
    let mut children = vec![tag];
    children.extend(clauses);
    Box::new(CstNode::list(children, TriviaAnn::default()))
}

/// Like `combine_with("and", …)` but preserves the outer node's trivia,
/// since the result replaces the original `(anywhere …)` / `(forbidden …)`.
fn combine_with_and_outer(node: &CstNode, mut clauses: Vec<Box<CstNode>>) -> Box<CstNode> {
    if clauses.len() == 1 {
        let mut single = *clauses.pop().unwrap();
        single.ann.leading = node.ann.leading.clone();
        single.ann.trailing = node.ann.trailing.clone();
        single.ann.span = node.ann.span;
        return Box::new(single);
    }
    let tag = Box::new(CstNode::atom("and", TriviaAnn::default()));
    let mut children = vec![tag];
    children.extend(clauses);
    Box::new(CstNode::list(
        children,
        TriviaAnn {
            leading: node.ann.leading.clone(),
            trailing: node.ann.trailing.clone(),
            span: node.ann.span,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migrate_str(input: &str) -> String {
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_anywhere_to_flag(&node).unwrap_or(node);
        result.serialize()
    }

    fn migrate_str_opt(input: &str) -> Option<String> {
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        rule_anywhere_to_flag(&node).map(|n| n.serialize())
    }

    #[test]
    fn anywhere_short_flag_becomes_flag() {
        let out = migrate_str(r#"(anywhere "-x")"#);
        assert_eq!(out, r#"(flag "x")"#);
    }

    #[test]
    fn anywhere_long_flag_becomes_flag() {
        let out = migrate_str(r#"(anywhere "--force")"#);
        assert_eq!(out, r#"(flag "force")"#);
    }

    #[test]
    fn forbidden_short_flag_becomes_not_flag() {
        let out = migrate_str(r#"(forbidden "-x")"#);
        assert_eq!(out, r#"(not (flag "x"))"#);
    }

    #[test]
    fn forbidden_long_flag_becomes_not_flag() {
        let out = migrate_str(r#"(forbidden "--force")"#);
        assert_eq!(out, r#"(not (flag "force"))"#);
    }

    #[test]
    fn positional_dot_short_flag_becomes_parameter() {
        let out = migrate_str(r#"(positional "-c" . (may-i *))"#);
        assert_eq!(out, r#"(parameter "c" (may-i *))"#);
    }

    #[test]
    fn positional_dot_long_flag_becomes_parameter() {
        let out = migrate_str(r#"(positional "--cmd" . (may-i *))"#);
        assert_eq!(out, r#"(parameter "cmd" (may-i *))"#);
    }

    #[test]
    fn anywhere_two_flags_becomes_or_of_flags() {
        let out = migrate_str(r#"(anywhere "-r" "--recursive")"#);
        assert!(out.contains("(or"), "got: {out}");
        assert!(out.contains(r#"(flag "r")"#), "got: {out}");
        assert!(out.contains(r#"(flag "recursive")"#), "got: {out}");
    }

    #[test]
    fn mixed_anywhere_splits_into_and() {
        let out = migrate_str(r#"(anywhere "-x" "verb")"#);
        assert!(out.contains("(and"), "got: {out}");
        assert!(out.contains(r#"(flag "x")"#), "got: {out}");
        assert!(out.contains(r#"(anywhere "verb")"#), "got: {out}");
    }

    #[test]
    fn mixed_forbidden_splits_into_and() {
        let out = migrate_str(r#"(forbidden "-x" "verb")"#);
        assert!(out.contains("(and"), "got: {out}");
        assert!(out.contains(r#"(not (flag "x"))"#), "got: {out}");
        assert!(out.contains(r#"(forbidden "verb")"#), "got: {out}");
    }

    #[test]
    fn anywhere_with_no_flag_literals_is_unchanged() {
        let out = migrate_str_opt(r#"(anywhere "verb")"#);
        assert!(
            out.is_none(),
            "expected no migration to apply, got: {out:?}"
        );
    }

    #[test]
    fn positional_without_flag_literal_is_unchanged() {
        let out = migrate_str_opt(r#"(positional "x" . (may-i *))"#);
        assert!(out.is_none(), "got: {out:?}");
    }

    #[test]
    fn nested_inside_rule() {
        let input = r#"(rule "rm" (forbidden "-r"))"#;
        let out = migrate_str(input);
        assert_eq!(out, r#"(rule "rm" (not (flag "r")))"#);
    }
}
