// Drop a redundant boundary-token literal from a rule's positional prefix
// when the prelude declares `(tail (after "TOKEN"))` for that command.
//
// Class A syntactic rewrite. After the parser splits argv at the boundary
// token, the literal token never appears in the outer positional stream —
// `(positional ... "TOKEN")` would never match. The migration strips it
// preemptively.

use crate::prelude::prelude_parsers;
use may_i_core::ast::Tail;
use may_i_sexpr::cst::{CstNode, ShapeF};

pub(crate) fn strip_redundant_boundary(node: &CstNode) -> Option<Box<CstNode>> {
    let list = node.as_list()?;
    if list.first().and_then(|c| c.as_atom()) != Some("rule") {
        return None;
    }
    let prog = list.get(1).and_then(|c| c.as_str())?;
    let tokens = prelude_tail_tokens(prog)?;

    let body_changed = list[2..]
        .iter()
        .any(|child| body_contains_redundant_boundary(child, &tokens));
    if !body_changed {
        return None;
    }

    let mut new_children: Vec<Box<CstNode>> = Vec::with_capacity(list.len());
    new_children.push(list[0].clone());
    new_children.push(list[1].clone());
    for child in &list[2..] {
        new_children.push(strip_in_node(child, &tokens));
    }

    Some(Box::new(CstNode {
        ann: node.ann.clone(),
        shape: ShapeF::List(new_children),
    }))
}

/// Return the boundary token set if the prelude declares
/// `(tail (after STR…))` for `prog`. None for `:after-flags` or no
/// declaration.
fn prelude_tail_tokens(prog: &str) -> Option<Vec<String>> {
    let parsers = prelude_parsers();
    let parser = parsers.into_iter().find(|p| p.program == prog)?;
    match parser.tail {
        Some(Tail::AfterToken(toks)) => Some(toks),
        _ => None,
    }
}

fn body_contains_redundant_boundary(node: &CstNode, tokens: &[String]) -> bool {
    let Some(list) = node.as_list() else {
        return false;
    };
    if list.first().and_then(|c| c.as_atom()) == Some("positional")
        && list
            .iter()
            .skip(1)
            .any(|c| c.as_str().is_some_and(|s| tokens.iter().any(|t| t == s)))
    {
        return true;
    }
    list.iter()
        .any(|c| body_contains_redundant_boundary(c, tokens))
}

fn strip_in_node(node: &CstNode, tokens: &[String]) -> Box<CstNode> {
    let Some(list) = node.as_list() else {
        return Box::new(node.clone());
    };
    if list.first().and_then(|c| c.as_atom()) == Some("positional") {
        let kept: Vec<Box<CstNode>> = list
            .iter()
            .enumerate()
            .filter(|(i, c)| {
                *i == 0
                    || c.as_str()
                        .map(|s| !tokens.iter().any(|t| t == s))
                        .unwrap_or(true)
            })
            .map(|(_, c)| c.clone())
            .collect();
        return Box::new(CstNode {
            ann: node.ann.clone(),
            shape: ShapeF::List(kept),
        });
    }
    let recursed: Vec<Box<CstNode>> = list.iter().map(|c| strip_in_node(c, tokens)).collect();
    Box::new(CstNode {
        ann: node.ann.clone(),
        shape: ShapeF::List(recursed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migrate_first(input: &str) -> String {
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        match strip_redundant_boundary(&node) {
            Some(out) => out.serialize(),
            None => node.serialize(),
        }
    }

    #[test]
    fn no_change_for_command_without_prelude_tail_token() {
        // Prelude has no AfterToken parser at this revision; mise/terragrunt
        // are user-side. Migration leaves their literal `--` alone.
        let input = r#"(rule "mise" (when (positional "exec" "--") (tail (authorise))))"#;
        assert_eq!(migrate_first(input), input);
    }

    #[test]
    fn no_change_for_command_with_after_flags_tail() {
        // sudo's prelude tail is :after-flags (not AfterToken); literal
        // tokens in positional prefix are not boundary-redundant.
        let input = r#"(rule "sudo" (when (positional "literal") (tail (authorise))))"#;
        assert_eq!(migrate_first(input), input);
    }

    #[test]
    fn strips_nix_command_literal_via_multi_token_prelude() {
        // The prelude declares `(parser "nix" (style gnu) (tail (after
        // ["--command" "-c"])))`. A migrated rule containing the literal
        // `"--command"` in its positional prefix has it stripped.
        let input = r#"(rule "nix" (when (positional (or "shell" "develop") "--command") (tail (authorise))))"#;
        let expected =
            r#"(rule "nix" (when (positional (or "shell" "develop")) (tail (authorise))))"#;
        assert_eq!(migrate_first(input), expected);
    }

    #[test]
    fn strips_nix_short_alias_literal_via_multi_token_prelude() {
        let input =
            r#"(rule "nix" (when (positional (or "shell" "develop") "-c") (tail (authorise))))"#;
        let expected =
            r#"(rule "nix" (when (positional (or "shell" "develop")) (tail (authorise))))"#;
        assert_eq!(migrate_first(input), expected);
    }
}
