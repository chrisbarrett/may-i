// Drop literal boundary tokens from `(positional …)` lists inside rules
// over prelude wrapper commands that declare an explicit-token tail.
//
// Class A syntactic rewrite. When the prelude declares
// `(parser "mise" (style gnu) (tail (after "--")))`, the tokeniser eats
// the `"--"` boundary before the outer style runs, so a rule like
// `(rule "mise" (positional "exec" "--") …)` cannot match — the `"--"`
// has already been consumed. Migration drops the literal token from the
// positional list so the rule keeps matching after the boundary fix.
//
// Only fires for prelude commands whose tail is `(after STRING)`.
// `(after :flags)` boundaries have no literal token to drop.

use crate::migrate::helpers::rebuild_list;
use may_i_sexpr::cst::CstNode;

pub(crate) fn prelude_tail_drop(node: &CstNode) -> Option<Box<CstNode>> {
    let list = node.as_list()?;
    if list.first()?.as_atom()? != "rule" {
        return None;
    }
    let cmd_node = list.get(1)?;
    let cmd = cmd_node.as_str().or_else(|| cmd_node.as_atom())?;
    let token = prelude_tail_token(cmd)?;

    let body_results: Vec<(Box<CstNode>, bool)> = list[2..]
        .iter()
        .map(|c| drop_token_in_subtree(c, token))
        .collect();
    if !body_results.iter().any(|(_, c)| *c) {
        return None;
    }

    let mut new_children: Vec<Box<CstNode>> = Vec::with_capacity(list.len());
    new_children.push(list[0].clone());
    new_children.push(list[1].clone());
    new_children.extend(body_results.into_iter().map(|(n, _)| n));
    Some(rebuild_list(node, new_children))
}

fn prelude_tail_token(cmd: &str) -> Option<&'static str> {
    // Mirrors `crates/config/src/prelude.lisp`. Update both together if a
    // new wrapper command ships with `(tail (after STRING))`.
    match cmd {
        "mise" => Some("--"),
        _ => None,
    }
}

fn drop_token_in_subtree(node: &CstNode, token: &str) -> (Box<CstNode>, bool) {
    let Some(list) = node.as_list() else {
        return (Box::new(node.clone()), false);
    };

    let mut changed = false;
    let mut new_children: Vec<Box<CstNode>> = Vec::with_capacity(list.len());
    for child in list {
        let (rewritten, child_changed) = drop_token_in_subtree(child, token);
        new_children.push(rewritten);
        if child_changed {
            changed = true;
        }
    }

    let is_positional = new_children.first().and_then(|c| c.as_atom()) == Some("positional");
    if is_positional {
        let original_len = new_children.len();
        let head = new_children.remove(0);
        new_children.retain(|c| c.as_str() != Some(token));
        new_children.insert(0, head);
        if new_children.len() != original_len {
            changed = true;
        }
    }

    if changed {
        (rebuild_list(node, new_children), true)
    } else {
        (Box::new(node.clone()), false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migrate_first(input: &str) -> String {
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        match prelude_tail_drop(&node) {
            Some(out) => out.serialize(),
            None => node.serialize(),
        }
    }

    #[test]
    fn drops_double_dash_from_mise_positional() {
        let out = migrate_first(r#"(rule "mise" (positional "exec" "--") (allow))"#);
        assert!(out.contains(r#"(positional "exec")"#), "{out}");
        assert!(!out.contains(r#""--""#), "{out}");
    }

    #[test]
    fn drops_double_dash_when_only_token() {
        let out = migrate_first(r#"(rule "mise" (positional "--") (allow))"#);
        assert!(out.contains("(positional)"), "{out}");
    }

    #[test]
    fn no_change_when_token_absent() {
        let input = r#"(rule "mise" (positional "exec") (allow))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        assert!(prelude_tail_drop(&node).is_none());
    }

    #[test]
    fn no_change_for_non_wrapper_command() {
        let input = r#"(rule "git" (positional "exec" "--") (allow))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        assert!(prelude_tail_drop(&node).is_none());
    }

    #[test]
    fn no_change_for_after_flags_wrapper() {
        // sudo declares `(tail (after :flags))` — no literal token to drop.
        let input = r#"(rule "sudo" (positional "rm" "--") (allow))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        assert!(prelude_tail_drop(&node).is_none());
    }

    #[test]
    fn drops_inside_nested_combinator() {
        let out = migrate_first(r#"(rule "mise" (and (positional "exec" "--") (allow)))"#);
        assert!(out.contains(r#"(positional "exec")"#), "{out}");
        assert!(!out.contains(r#""--""#), "{out}");
    }

    #[test]
    fn preserves_other_string_args() {
        let out = migrate_first(r#"(rule "mise" (positional "exec" "--" "task") (allow))"#);
        assert!(out.contains(r#"(positional "exec" "task")"#), "{out}");
    }

    #[test]
    fn matches_symbol_command_head() {
        let out = migrate_first(r#"(rule mise (positional "exec" "--") (allow))"#);
        assert!(out.contains(r#"(positional "exec")"#), "{out}");
    }
}
