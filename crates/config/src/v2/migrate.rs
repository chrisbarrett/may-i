// Migration tool for converting v1 configs to v2 syntax using rewrite rules.
//
// This module provides rewrite rules that transform v1 s-expression syntax
// into v2 syntax. The rules are applied iteratively until convergence.

use may_i_sexpr::cst::{CstNode, Shape, TriviaAnn};

/// A rewrite rule that transforms v1 syntax to v2.
pub type RewriteFn = Box<dyn Fn(&CstNode) -> Option<Box<CstNode>>>;

/// Get all v1→v2 migration rewrite rules.
pub fn migration_rules() -> Vec<RewriteFn> {
    vec![
        // Rule: (rule (command X) ...) → (rule X ...)
        Box::new(rule_simplify_command),
        // Rule: (rule ... (context EXPR) ...) → (rule ... EXPR ...)
        Box::new(rule_inline_context),
        // Rule: (rule ... (args MATCHER) ...) → (rule ... MATCHER ...)
        Box::new(rule_inline_args),
        // Rule: (wrapper CMD ...) → (rule CMD ... . (may-i *))
        Box::new(wrapper_to_rule),
        // Rule: (defcontext NAME EXPR) → (define NAME EXPR)
        Box::new(defcontext_to_define),
        // Rule: (args (cond ...)) → (case ...) in effect position
        Box::new(args_cond_to_case),
    ]
}

/// Simplify (rule (command X) ...) to (rule X ...)
fn rule_simplify_command(node: &CstNode) -> Option<Box<CstNode>> {
    if !node.is_tagged("rule") {
        return None;
    }

    let children = node.as_list()?;
    if children.len() < 2 {
        return None;
    }

    // Check if second element is (command ...)
    let second = &children[1];
    if !second.is_tagged("command") {
        return None;
    }

    // Extract the command value
    let cmd_children = second.as_list()?;
    if cmd_children.len() != 2 {
        return None;
    }

    let cmd_value = &cmd_children[1];

    // Build new children: tag, cmd_value, rest...
    let mut new_children = Vec::new();
    new_children.push(children[0].clone()); // "rule" tag

    // New command value with combined trivia
    let mut new_cmd = (**cmd_value).clone();
    new_cmd.annotation.leading = second.annotation.leading.clone();
    new_cmd.annotation.trailing = second.annotation.trailing.clone();
    new_children.push(Box::new(new_cmd));

    // Rest of children
    for child in &children[2..] {
        new_children.push(child.clone());
    }

    Some(Box::new(CstNode {
        annotation: node.annotation.clone(),
        shape: Shape::List(new_children),
    }))
}

/// Inline (context EXPR) into the rule as a predicate
fn rule_inline_context(node: &CstNode) -> Option<Box<CstNode>> {
    if !node.is_tagged("rule") {
        return None;
    }

    let children = node.as_list()?;
    let mut new_children = Vec::new();
    let mut changed = false;

    new_children.push(children[0].clone()); // "rule" tag

    for child in &children[1..] {
        if child.is_tagged("context") {
            // Extract the context expression
            let ctx_children = child.as_list()?;
            if ctx_children.len() == 2 {
                // Inline the context expression directly
                let expr = &ctx_children[1];
                let mut inlined = (**expr).clone();
                // Combine trivia
                inlined.annotation.leading = child.annotation.leading.clone();
                inlined.annotation.trailing = child.annotation.trailing.clone();
                new_children.push(Box::new(inlined));
                changed = true;
                continue;
            }
        }
        new_children.push(child.clone());
    }

    if !changed {
        return None;
    }

    Some(Box::new(CstNode {
        annotation: node.annotation.clone(),
        shape: Shape::List(new_children),
    }))
}

/// Inline (args MATCHER) into the rule as predicates
fn rule_inline_args(node: &CstNode) -> Option<Box<CstNode>> {
    if !node.is_tagged("rule") {
        return None;
    }

    let children = node.as_list()?;
    let mut new_children = Vec::new();
    let mut changed = false;

    new_children.push(children[0].clone()); // "rule" tag

    for child in &children[1..] {
        if child.is_tagged("args") {
            // Extract the args matcher - need to handle different forms
            let args_children = child.as_list()?;
            if args_children.len() == 2 {
                let matcher = &args_children[1];

                // Skip cond forms - they're handled by args_cond_to_case
                if matcher.is_tagged("cond") {
                    new_children.push(child.clone());
                    continue;
                }

                // For simple matchers, inline them
                let mut inlined = (**matcher).clone();
                inlined.annotation.leading = child.annotation.leading.clone();
                inlined.annotation.trailing = child.annotation.trailing.clone();
                new_children.push(Box::new(inlined));
                changed = true;
                continue;
            }
        }
        new_children.push(child.clone());
    }

    if !changed {
        return None;
    }

    Some(Box::new(CstNode {
        annotation: node.annotation.clone(),
        shape: Shape::List(new_children),
    }))
}

/// Convert (wrapper CMD ...) to (rule CMD ... . (may-i *))
fn wrapper_to_rule(node: &CstNode) -> Option<Box<CstNode>> {
    if !node.is_tagged("wrapper") {
        return None;
    }

    let children = node.as_list()?;
    if children.len() < 2 {
        return None;
    }

    // Extract command
    let cmd = &children[1];

    // Build rule children
    let mut new_children = Vec::new();

    // "rule" tag
    new_children.push(Box::new(CstNode::atom(
        "rule",
        TriviaAnn {
            leading: node.annotation.leading.clone(),
            ..Default::default()
        },
    )));

    // Command
    new_children.push(cmd.clone());

    // Build positional pattern from wrapper steps
    let mut patterns = Vec::new();
    let mut has_capture = false;

    for step in &children[2..] {
        if step.is_tagged("positional") {
            let pos_children = step.as_list()?;
            for pat in &pos_children[1..] {
                // Check for capture markers inside positional
                if let Some(atom) = pat.as_atom()
                    && (atom == ":command+args" || atom == ":command" || atom == ":args")
                {
                    has_capture = true;
                }
                patterns.push(pat.clone());
            }
        } else if step.is_tagged("flag") {
            // (flag "--command" ...) → "--command" and patterns
            let flag_children = step.as_list()?;
            if flag_children.len() >= 2 {
                patterns.push(flag_children[1].clone());
                for pat in &flag_children[2..] {
                    patterns.push(pat.clone());
                }
            }
        } else if let Some(atom) = step.as_atom() {
            // Bare atoms like :command+args
            if atom == ":command+args" || atom == ":command" || atom == ":args" {
                has_capture = true;
            }
        }
    }

    // Add positional pattern if we have any
    if !patterns.is_empty() {
        let pos_list = CstNode::list(
            patterns,
            TriviaAnn {
                leading: vec![may_i_sexpr::cst::Trivia::Whitespace(" ".to_string())],
                ..Default::default()
            },
        );

        let positional = CstNode::list(
            vec![
                Box::new(CstNode::atom("positional", Default::default())),
                Box::new(pos_list),
            ],
            Default::default(),
        );
        new_children.push(Box::new(positional));
    }

    // Add recursive marker if capture was present
    if has_capture {
        // Add . (may-i *) to the list
        let dot = CstNode::atom(".", Default::default());
        let may_i = CstNode::list(
            vec![
                Box::new(CstNode::atom("may-i", Default::default())),
                Box::new(CstNode::atom("*", Default::default())),
            ],
            Default::default(),
        );

        if let Some(last) = new_children.last_mut()
            && let Some(list_children) = last.as_list()
        {
            let mut new_last_children = list_children.to_vec();
            new_last_children.push(Box::new(dot));
            new_last_children.push(Box::new(may_i));
            **last = CstNode::list(new_last_children, last.annotation.clone());
        }
    }

    // Add (effect :allow)
    let effect = CstNode::list(
        vec![
            Box::new(CstNode::atom("effect", Default::default())),
            Box::new(CstNode::atom(":allow", Default::default())),
        ],
        TriviaAnn {
            leading: vec![may_i_sexpr::cst::Trivia::Whitespace(" ".to_string())],
            ..Default::default()
        },
    );
    new_children.push(Box::new(effect));

    Some(Box::new(CstNode::list(
        new_children,
        TriviaAnn {
            trailing: node.annotation.trailing.clone(),
            ..Default::default()
        },
    )))
}

/// Convert (defcontext NAME EXPR) to (define NAME EXPR)
fn defcontext_to_define(node: &CstNode) -> Option<Box<CstNode>> {
    if !node.is_tagged("defcontext") {
        return None;
    }

    let children = node.as_list()?;
    if children.len() != 3 {
        return None;
    }

    // Build (define NAME EXPR)
    let new_children = vec![
        Box::new(CstNode::atom(
            "define",
            TriviaAnn {
                leading: node.annotation.leading.clone(),
                ..Default::default()
            },
        )),
        children[1].clone(), // NAME
        children[2].clone(), // EXPR
    ];

    Some(Box::new(CstNode::list(
        new_children,
        TriviaAnn {
            trailing: node.annotation.trailing.clone(),
            ..Default::default()
        },
    )))
}

/// Convert (args (cond ...)) in rule to (case ...) as effect
fn args_cond_to_case(node: &CstNode) -> Option<Box<CstNode>> {
    if !node.is_tagged("rule") {
        return None;
    }

    let children = node.as_list()?;
    let mut new_children = Vec::new();
    let mut found_cond = None;
    let mut cond_index = 0;

    new_children.push(children[0].clone()); // "rule" tag

    // First pass: collect non-args children and find cond
    for (i, child) in children[1..].iter().enumerate() {
        if child.is_tagged("args") {
            let args_children = child.as_list()?;
            if args_children.len() == 2 {
                let matcher = &args_children[1];
                if matcher.is_tagged("cond") {
                    found_cond = Some(matcher.clone());
                    cond_index = i + 1;
                    continue;
                }
            }
        }
        new_children.push(child.clone());
    }

    let cond = found_cond?;
    let cond_children = cond.as_list()?;

    // Build case expression from cond branches
    let mut case_children = vec![Box::new(CstNode::atom("case", Default::default()))];

    for branch in &cond_children[1..] {
        if branch.is_tagged("else") {
            // (else EFFECT) → (else EFFECT)
            case_children.push(branch.clone());
        } else {
            // (PREDICATE EFFECT) pair
            case_children.push(branch.clone());
        }
    }

    // Insert case at the position where args was
    let case_node = Box::new(CstNode::list(case_children, Default::default()));

    // Find where to insert - after the last predicate or at end
    if cond_index >= new_children.len() {
        new_children.push(case_node);
    } else {
        new_children.insert(cond_index, case_node);
    }

    Some(Box::new(CstNode::list(
        new_children,
        node.annotation.clone(),
    )))
}

/// Apply all migration rules to a CST until convergence.
pub fn migrate(node: Box<CstNode>) -> Box<CstNode> {
    may_i_sexpr::cst::rewrite_until_convergence(node, &migration_rules())
}

/// Migrate multiple top-level forms.
pub fn migrate_forms(forms: Vec<Box<CstNode>>) -> Vec<Box<CstNode>> {
    forms.into_iter().map(migrate).collect()
}

/// Validate that migrated output can be parsed with the v2 parser.
/// Returns Ok(()) if valid, or Err with a list of validation errors.
pub fn validate_migration(migrated_text: &str) -> Result<(), Vec<String>> {
    match super::config::parse_config(migrated_text) {
        Ok(_) => Ok(()),
        Err(e) => Err(vec![format!("{}", e)]),
    }
}

/// Check for unhandled v1 constructs in the original source that couldn't be migrated.
/// Returns a list of warnings about constructs that may need manual attention.
pub fn check_unhandled_cases(original_text: &str) -> Vec<UnhandledCase> {
    let mut warnings = Vec::new();
    let (forms, _) = may_i_sexpr::parse_cst(original_text);

    for form in &forms {
        check_node_unhandled(form, &mut warnings);
    }

    warnings
}

/// A single unhandled case warning.
#[derive(Debug, Clone)]
pub struct UnhandledCase {
    /// Description of the unhandled construct
    pub description: String,
    /// The source text that couldn't be handled
    pub source: String,
    /// Suggestion for manual fix
    pub suggestion: String,
}

/// Recursively check a CST node for unhandled v1 constructs.
fn check_node_unhandled(node: &CstNode, warnings: &mut Vec<UnhandledCase>) {
    if let Some(list) = node.as_list()
        && !list.is_empty()
    {
        if let Some(tag) = list[0].as_atom() {
            match tag {
                // Legacy v1 forms that should have been converted
                "wrapper" => {
                    warnings.push(UnhandledCase {
                        description: "Legacy wrapper form".to_string(),
                        source: node.serialize(),
                        suggestion: "Convert to (rule ...) with . (may-i *)".to_string(),
                    });
                }
                "defcontext" => {
                    warnings.push(UnhandledCase {
                        description: "Legacy defcontext form".to_string(),
                        source: node.serialize(),
                        suggestion: "Convert to (define ...)".to_string(),
                    });
                }
                "context" => {
                    warnings.push(UnhandledCase {
                        description: "Legacy context form in rule".to_string(),
                        source: node.serialize(),
                        suggestion: "Inline context expression into rule predicates".to_string(),
                    });
                }
                "args" => {
                    // Check if this is an args with cond that might not migrate well
                    if list.len() >= 2
                        && let Some(inner_tag) = list[1].as_atom()
                        && inner_tag == "cond"
                    {
                        warnings.push(UnhandledCase {
                            description: "Legacy args with cond form".to_string(),
                            source: node.serialize(),
                            suggestion: "Convert to (case ...) in effect position".to_string(),
                        });
                    }
                }
                "MatcherCondPredicate" | "ArgMatcher" | "BoolExpr" => {
                    warnings.push(UnhandledCase {
                        description: "Legacy internal type name".to_string(),
                        source: node.serialize(),
                        suggestion: "This should not appear in user config".to_string(),
                    });
                }
                _ => {}
            }
        }

        // Recursively check children
        for child in list {
            check_node_unhandled(child, warnings);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_simplify_command() {
        let input = "(rule (command git) (effect :allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_simplify_command(&node).unwrap();
        assert_eq!(result.serialize(), "(rule git (effect :allow))");
    }

    #[test]
    fn test_defcontext_to_define() {
        let input = "(defcontext ssh (has :via/ssh))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = defcontext_to_define(&node).unwrap();
        assert_eq!(result.serialize(), "(define ssh (has :via/ssh))");
    }
}
