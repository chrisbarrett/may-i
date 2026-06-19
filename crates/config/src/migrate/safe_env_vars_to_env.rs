//! Migration: `(safe-env-vars "A" "B" …)` → `(env "A" (allow)) (env "B"
//! (allow)) …`.
//!
//! This is a one-to-many top-level expansion, so it cannot be expressed as a
//! node-level [`RewriteFn`] (which is one-to-one). It runs at the
//! forms-list level in [`crate::migrate::migrate_forms`] instead.
//!
//! The rewrite is semantics-preserving (Class A): an unconditional
//! `(env NAME (allow))` lowers to the same safe-env-vars allowlist entry as
//! `(safe-env-vars NAME)`, so the `:safe-env-vars` trust scope's canonical
//! form and hash are unchanged and existing approvals carry over.

use may_i_sexpr::cst::CstNode;

/// If `node` is a `(safe-env-vars "A" "B" …)` form with one or more string
/// names, return the expanded `(env "NAME" (allow))` forms. The original
/// form's leading trivia (comments) attaches to the first expanded form and
/// its trailing trivia to the last, so surrounding comments survive.
///
/// Returns `None` for anything that is not a non-empty `(safe-env-vars …)`
/// form (caller falls back to ordinary node migration).
#[allow(clippy::vec_box)]
pub(crate) fn expand_safe_env_vars(node: &CstNode) -> Option<Vec<Box<CstNode>>> {
    let children = node.as_list()?;
    if children.first()?.as_atom()? != "safe-env-vars" {
        return None;
    }
    let names: Vec<&str> = children[1..].iter().filter_map(|c| atom_text(c)).collect();
    // Every argument must be a plain name; bail on a malformed form (it will
    // surface as a parse error downstream rather than be silently dropped).
    if names.is_empty() || names.len() != children.len() - 1 {
        return None;
    }

    let mut forms: Vec<Box<CstNode>> = Vec::with_capacity(names.len());
    for name in names {
        let text = format!(r#"(env "{name}" (allow))"#);
        let (parsed, errors) = may_i_sexpr::parse_cst(&text);
        if !errors.is_empty() {
            return None;
        }
        forms.push(parsed.into_iter().next()?);
    }

    // Preserve the original form's surrounding comments.
    if let Some(first) = forms.first_mut() {
        first.ann.leading = node.ann.leading.clone();
    }
    if let Some(last) = forms.last_mut() {
        last.ann.trailing = node.ann.trailing.clone();
    }
    Some(forms)
}

/// The text of a string-or-symbol leaf node, or `None` for anything else.
fn atom_text(node: &CstNode) -> Option<&str> {
    use may_i_sexpr::cst::ShapeF;
    match &node.shape {
        ShapeF::String(s) | ShapeF::Symbol(s) => Some(s.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_one(input: &str) -> Box<CstNode> {
        let (forms, errors) = may_i_sexpr::parse_cst(input);
        assert!(errors.is_empty(), "{errors:?}");
        forms.into_iter().next().unwrap()
    }

    #[test]
    fn expands_multiple_names() {
        let node = parse_one(r#"(safe-env-vars "A" "B")"#);
        let forms = expand_safe_env_vars(&node).expect("expands");
        let texts: Vec<String> = forms.iter().map(|f| f.serialize()).collect();
        assert_eq!(texts, vec![r#"(env "A" (allow))"#, r#"(env "B" (allow))"#]);
    }

    #[test]
    fn expands_single_name() {
        let node = parse_one(r#"(safe-env-vars "HOME")"#);
        let forms = expand_safe_env_vars(&node).expect("expands");
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].serialize(), r#"(env "HOME" (allow))"#);
    }

    #[test]
    fn ignores_non_safe_env_vars_form() {
        let node = parse_one(r#"(rule "git" (allow))"#);
        assert!(expand_safe_env_vars(&node).is_none());
    }

    #[test]
    fn ignores_empty_form() {
        let node = parse_one("(safe-env-vars)");
        assert!(expand_safe_env_vars(&node).is_none());
    }
}
