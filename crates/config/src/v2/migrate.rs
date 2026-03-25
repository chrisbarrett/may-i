//! Migration tool for converting v1 configs to v2 syntax using rewrite rules.
//!
//! This module provides rewrite rules that transform v1 s-expression syntax
//! into v2 syntax. The rules are applied iteratively until convergence.
//!
//! # Migration Pipeline
//!
//! 1. **Parse**: CST parses source, preserving trivia (comments/whitespace)
//! 2. **Analyze**: Compare original vs migrated forms to create diff
//! 3. **Migrate**: Apply rewrite rules until convergence
//! 4. **Validate**: Parse output with v2 parser to ensure validity
//!
//! # String Type Preservation
//!
//! A critical implementation detail is distinguishing string literals from bare atoms.
//! The CST represents `"~/.config"` as `Shape::Str` and `bare-atom` as `Shape::Atom`.
//! During serialization, `Shape::Str` is always quoted while `Shape::Atom` is not.
//! Without this distinction, valid v1 quoted paths produce invalid v2 unquoted output.

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
        // Rule: (args (cond/if ...)) → (case ...) in effect position
        // MUST run before rule_inline_args which removes the args tag
        Box::new(args_cond_to_case),
        // Rule: (rule ... (args MATCHER) ...) → (rule ... MATCHER ...)
        Box::new(rule_inline_args),
        // Rule: (wrapper CMD ...) → (rule CMD ... . (may-i *))
        Box::new(wrapper_to_rule),
        // Rule: (defcontext NAME EXPR) → (define NAME EXPR)
        Box::new(defcontext_to_define),
        // Rule: (has ...) → (fact? ...)
        // Rename has to fact? for the new unified syntax
        Box::new(rename_has_to_fact),
        // Rule: (rule ... (effect E)) → (rule ... :effect E)
        // MUST run after other rule transformations that may produce old-style rules
        Box::new(rule_convert_effect_to_keyword),
        // Rule: Add :effect :ask when rule has no default effect
        // This handles v1 rules that relied on if/cond covering all cases
        Box::new(rule_add_default_effect),
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
    new_cmd.ann.leading = second.ann.leading.clone();
    new_cmd.ann.trailing = second.ann.trailing.clone();
    new_children.push(Box::new(new_cmd));

    // Rest of children
    for child in &children[2..] {
        new_children.push(child.clone());
    }

    Some(Box::new(CstNode {
        ann: node.ann.clone(),
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
                inlined.ann.leading = child.ann.leading.clone();
                inlined.ann.trailing = child.ann.trailing.clone();
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
        ann: node.ann.clone(),
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
                inlined.ann.leading = child.ann.leading.clone();
                inlined.ann.trailing = child.ann.trailing.clone();
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
        ann: node.ann.clone(),
        shape: Shape::List(new_children),
    }))
}

/// Convert old-style `(effect EFFECT)` to new-style `:effect EFFECT` in rules.
/// Transforms: (rule X ... (effect E)) → (rule X ... :effect E)
fn rule_convert_effect_to_keyword(node: &CstNode) -> Option<Box<CstNode>> {
    if !node.is_tagged("rule") {
        return None;
    }

    let children = node.as_list()?;
    if children.len() < 3 {
        return None;
    }

    // Check if the last element is (effect ...)
    let last_idx = children.len() - 1;
    let last_child = &children[last_idx];

    if !last_child.is_tagged("effect") {
        return None;
    }

    // Extract the effect content from (effect EFFECT) or (effect EFFECT "reason")
    let effect_children = last_child.as_list()?;
    if effect_children.len() < 2 || effect_children.len() > 3 {
        // Invalid (effect) form, skip
        return None;
    }

    // Build the effect content: either just the keyword, or [:keyword "reason"]
    let effect_content = if effect_children.len() == 2 {
        // Simple effect: (effect :keyword) → :keyword
        effect_children[1].clone()
    } else {
        // Effect with reason: (effect :keyword "reason") → [:keyword "reason"]
        let keyword = &effect_children[1];
        let reason = &effect_children[2];
        Box::new(CstNode {
            ann: TriviaAnn {
                leading: keyword.ann.leading.clone(),
                trailing: reason.ann.trailing.clone(),
                span: keyword.ann.span, // Approximate
            },
            shape: Shape::Vector(vec![keyword.clone(), reason.clone()]),
        })
    };

    // Build new children: all except last, then :effect keyword, then effect content
    let mut new_children = Vec::new();

    // Copy all children except the last
    for child in &children[..last_idx] {
        new_children.push(child.clone());
    }

    // Add :effect keyword with leading trivia from the old (effect ...) list
    let effect_keyword = CstNode::atom(
        ":effect",
        TriviaAnn {
            leading: last_child.ann.leading.clone(),
            ..Default::default()
        },
    );
    new_children.push(Box::new(effect_keyword));

    // Add the effect content with combined trailing trivia
    let mut new_effect_content = (*effect_content).clone();
    new_effect_content.ann.trailing = last_child.ann.trailing.clone();
    new_children.push(Box::new(new_effect_content));

    Some(Box::new(CstNode {
        ann: node.ann.clone(),
        shape: Shape::List(new_children),
    }))
}

/// Add default :effect :ask to rules that don't have one.
/// This handles v1 rules that relied on if/cond covering all cases.
fn rule_add_default_effect(node: &CstNode) -> Option<Box<CstNode>> {
    if !node.is_tagged("rule") {
        return None;
    }

    let children = node.as_list()?;
    if children.len() < 2 {
        return None;
    }

    // Check if the rule already has a :effect keyword
    for child in &children[1..] {
        if let Some(atom) = child.as_atom() {
            if atom == ":effect" {
                // Rule already has :effect keyword
                return None;
            }
        }
    }

    // Add :effect :ask at the end
    let mut new_children: Vec<Box<CstNode>> = children.iter().cloned().collect();

    // Add :effect keyword
    new_children.push(Box::new(CstNode::atom(
        ":effect",
        TriviaAnn {
            leading: vec![may_i_sexpr::cst::Trivia::Whitespace(" ".to_string())],
            ..Default::default()
        },
    )));

    // Add :ask default effect
    new_children.push(Box::new(CstNode::atom(
        ":ask",
        TriviaAnn {
            leading: vec![may_i_sexpr::cst::Trivia::Whitespace(" ".to_string())],
            ..Default::default()
        },
    )));

    Some(Box::new(CstNode {
        ann: node.ann.clone(),
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
            leading: node.ann.leading.clone(),
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
        // Build (positional PATTERN PATTERN ...) directly - don't wrap in extra list
        let mut positional_children =
            vec![Box::new(CstNode::atom("positional", Default::default()))];

        // Add each pattern as a direct child with proper spacing
        for (i, pat) in patterns.iter().enumerate() {
            let mut pat = pat.clone();

            // Convert v1 bracket capture patterns [:key *] to just * for v2
            // The capture functionality is handled by the wrapper mechanism
            if let Some(vector) = pat.as_vector()
                && vector.len() == 2
                && let Some(second) = vector.get(1)
                && let Some(atom) = second.as_atom()
                && atom == "*"
            {
                // Replace [:key *] with just *
                pat = Box::new(CstNode::atom("*", pat.ann.clone()));
            }

            // Add leading whitespace for spacing between patterns
            if i == 0 {
                pat.ann.leading = vec![may_i_sexpr::cst::Trivia::Whitespace(" ".to_string())];
            }
            positional_children.push(pat);
        }

        let positional = CstNode::list(positional_children, Default::default());
        new_children.push(Box::new(positional));
    }

    // Add recursive marker if capture was present
    // The dot and continuation effect go at the RULE level, not inside positional
    if has_capture {
        // Add . (may-i *) as separate children at the rule level
        let dot = CstNode::atom(
            ".",
            TriviaAnn {
                leading: vec![may_i_sexpr::cst::Trivia::Whitespace(" ".to_string())],
                ..Default::default()
            },
        );
        let may_i = CstNode::list(
            vec![
                Box::new(CstNode::atom("may-i", Default::default())),
                Box::new(CstNode::atom("*", Default::default())),
            ],
            TriviaAnn {
                leading: vec![may_i_sexpr::cst::Trivia::Whitespace(" ".to_string())],
                ..Default::default()
            },
        );

        new_children.push(Box::new(dot));
        new_children.push(Box::new(may_i));
    }

    // Add :effect :allow
    // In new unified syntax, :effect keyword comes before default effect
    new_children.push(Box::new(CstNode::atom(
        ":effect",
        TriviaAnn {
            leading: vec![may_i_sexpr::cst::Trivia::Whitespace(" ".to_string())],
            ..Default::default()
        },
    )));
    new_children.push(Box::new(CstNode::atom(":allow", Default::default())));

    Some(Box::new(CstNode::list(
        new_children,
        TriviaAnn {
            trailing: node.ann.trailing.clone(),
            ..Default::default()
        },
    )))
}

/// Convert (defcontext NAME EXPR) to (define NAME EXPR)
/// Also transforms v1 has expressions: (has :key "value") → (has [:key "value"])
fn defcontext_to_define(node: &CstNode) -> Option<Box<CstNode>> {
    if !node.is_tagged("defcontext") {
        return None;
    }

    let children = node.as_list()?;
    if children.len() != 3 {
        return None;
    }

    // Transform the expression to handle v1 has syntax
    let transformed_expr = transform_has_expression(&children[2]);

    // Build (define NAME EXPR)
    let new_children = vec![
        Box::new(CstNode::atom(
            "define",
            TriviaAnn {
                leading: node.ann.leading.clone(),
                ..Default::default()
            },
        )),
        children[1].clone(), // NAME
        transformed_expr,
    ];

    Some(Box::new(CstNode::list(
        new_children,
        TriviaAnn {
            trailing: node.ann.trailing.clone(),
            ..Default::default()
        },
    )))
}

/// Transform v1 has expressions to v2 syntax.
/// Converts (has :key "value") to (has [:key "value"])
fn transform_has_expression(expr: &CstNode) -> Box<CstNode> {
    // Check if this is a (has ...) expression
    if let Some(list) = expr.as_list()
        && !list.is_empty()
        && list[0].as_atom() == Some("has")
        && list.len() == 3
    {
        // This is (has KEY VALUE) - convert to (has [KEY VALUE])
        let key = &list[1];
        let value = &list[2];

        // Create the vector [key value]
        let vector_node = CstNode {
            ann: TriviaAnn {
                leading: vec![],
                trailing: vec![],
                span: key.ann.span, // Use key's span as approximation
            },
            shape: Shape::Vector(vec![key.clone(), value.clone()]),
        };

        // Create (has [key value])
        let new_children = vec![
            list[0].clone(), // "has" tag
            Box::new(vector_node),
        ];

        Box::new(CstNode::list(
            new_children,
            TriviaAnn {
                leading: expr.ann.leading.clone(),
                trailing: expr.ann.trailing.clone(),
                span: expr.ann.span,
            },
        ))
    } else if let Some(list) = expr.as_list()
        && !list.is_empty()
        && list[0].as_atom() == Some("has")
        && list.len() == 2
    {
        // This is (has KEY) - presence check, keep as-is
        Box::new(expr.clone())
    } else if let Some(list) = expr.as_list() {
        // Recursively transform children
        let mut new_children = Vec::new();
        let mut changed = false;

        for child in list {
            let transformed = transform_has_expression(child);
            // Check if transformation actually changed anything by comparing serialized output
            if transformed.serialize() != child.serialize() {
                changed = true;
            }
            new_children.push(transformed);
        }

        if changed {
            Box::new(CstNode::list(
                new_children,
                TriviaAnn {
                    leading: expr.ann.leading.clone(),
                    trailing: expr.ann.trailing.clone(),
                    span: expr.ann.span,
                },
            ))
        } else {
            Box::new(expr.clone())
        }
    } else {
        // Atom or string - return as-is
        Box::new(expr.clone())
    }
}

/// Rename `has` to `fact?` in all expressions.
/// This is part of the unified effect model where `has` was renamed to `fact?`.
fn rename_has_to_fact(node: &CstNode) -> Option<Box<CstNode>> {
    if let Some(list) = node.as_list() {
        if list.is_empty() {
            return None;
        }

        // Check if this is a (has ...) expression
        if let Some(tag) = list[0].as_atom()
            && tag == "has"
        {
            // Rename to fact?
            let mut new_children = Vec::new();
            new_children.push(Box::new(CstNode::atom(
                "fact?",
                TriviaAnn {
                    leading: list[0].ann.leading.clone(),
                    trailing: list[0].ann.trailing.clone(),
                    span: list[0].ann.span,
                },
            )));
            // Copy the rest of the children
            for child in &list[1..] {
                new_children.push(child.clone());
            }

            return Some(Box::new(CstNode::list(
                new_children,
                TriviaAnn {
                    leading: node.ann.leading.clone(),
                    trailing: node.ann.trailing.clone(),
                    span: node.ann.span,
                },
            )));
        }

        // Recursively process children
        let mut new_children = Vec::new();
        let mut changed = false;

        for child in list {
            if let Some(transformed) = rename_has_to_fact(child) {
                new_children.push(transformed);
                changed = true;
            } else {
                new_children.push(child.clone());
            }
        }

        if changed {
            return Some(Box::new(CstNode::list(
                new_children,
                TriviaAnn {
                    leading: node.ann.leading.clone(),
                    trailing: node.ann.trailing.clone(),
                    span: node.ann.span,
                },
            )));
        }
    }

    None
}

/// Find and extract a cond/if form nested within boolean combinators.
/// Returns (remaining_predicates, cond_or_if_node) if found.
#[allow(clippy::vec_box)]
fn find_cond_or_if_in_booleans(node: &CstNode) -> Option<(Vec<Box<CstNode>>, Box<CstNode>)> {
    // Check if this is a boolean combinator
    if let Some(list) = node.as_list()
        && !list.is_empty()
        && let Some(tag) = list[0].as_atom()
    {
        match tag {
            "and" | "or" => {
                // Look through children for cond/if
                let mut remaining = Vec::new();
                let mut found = None;

                for child in &list[1..] {
                    if child.is_tagged("cond") || child.is_tagged("if") {
                        found = Some(child.clone());
                    } else if let Some((nested_remaining, nested_found)) =
                        find_cond_or_if_in_booleans(child)
                    {
                        // Found nested - merge remaining predicates
                        found = Some(nested_found);
                        remaining.extend(nested_remaining);
                    } else {
                        remaining.push(child.clone());
                    }
                }

                found.map(|f| (remaining, f))
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Convert (args ...) in rule to predicates and an effect.
/// Handles cond/if nested inside and/or combinators.
/// Also collects bare atom predicates between command and args (e.g., from inlined context).
fn args_cond_to_case(node: &CstNode) -> Option<Box<CstNode>> {
    if !node.is_tagged("rule") {
        return None;
    }

    let children = node.as_list()?;
    if children.len() < 2 {
        return None;
    }

    let mut new_children = Vec::new();
    let mut predicates_to_add = Vec::new();
    let mut rule_level_predicates = Vec::new(); // Predicates from inlined context
    let mut found_case_source = None;

    new_children.push(children[0].clone()); // "rule" tag
    new_children.push(children[1].clone()); // command

    // First pass: collect rule-level predicates (bare atoms after command, before args/effects)
    // and find args with cond/if
    for child in &children[2..] {
        if child.is_tagged("args") {
            let args_children = child.as_list()?;
            if args_children.len() == 2 {
                let matcher = &args_children[1];

                // Check for direct cond/if
                if matcher.is_tagged("cond") {
                    found_case_source = Some((Vec::new(), matcher.clone()));
                    continue;
                }
                if matcher.is_tagged("if") {
                    let if_children = matcher.as_list()?;
                    if if_children.len() == 4 {
                        found_case_source = Some((Vec::new(), matcher.clone()));
                        continue;
                    }
                }

                // Check for cond/if nested in and/or
                if let Some((remaining, cond_or_if)) = find_cond_or_if_in_booleans(matcher) {
                    predicates_to_add = remaining;
                    found_case_source = Some((Vec::new(), cond_or_if));
                    continue;
                }
            }
        } else if child.as_atom().is_some() && !child.is_tagged(":effect") {
            // Bare atom after command - likely a context predicate from inlined (context ...)
            // Skip :effect keyword and collect other atoms as predicates
            rule_level_predicates.push(child.clone());
        } else {
            new_children.push(child.clone());
        }
    }

    let (extra_predicates, case_source) = found_case_source?;

    // Build cond expression based on source type
    let mut case_children = vec![Box::new(CstNode::atom("cond", Default::default()))];

    if case_source.is_tagged("cond") {
        let cond_children = case_source.as_list()?;
        for branch in &cond_children[1..] {
            case_children.push(branch.clone());
        }
    } else if case_source.is_tagged("if") {
        // Convert (if PRED THEN ELSE) to case branches
        let if_children = case_source.as_list()?;
        if if_children.len() == 4 {
            // First branch: (PRED THEN)
            let pred = &if_children[1];
            let then_eff = &if_children[2];
            let branch = CstNode::list(
                vec![Box::new((**pred).clone()), Box::new((**then_eff).clone())],
                Default::default(),
            );
            case_children.push(Box::new(branch));

            // Else branch: (else ELSE)
            let else_eff = &if_children[3];
            let else_branch = CstNode::list(
                vec![
                    Box::new(CstNode::atom("else", Default::default())),
                    Box::new((**else_eff).clone()),
                ],
                Default::default(),
            );
            case_children.push(Box::new(else_branch));
        }
    }

    // Combine all predicates: from args, from cond/if, and from rule-level context references
    let all_predicates: Vec<_> = rule_level_predicates
        .iter()
        .chain(predicates_to_add.iter())
        .chain(extra_predicates.iter())
        .cloned()
        .collect();

    // Wrap the cond in a when expression if there are predicates
    let final_effect = if all_predicates.is_empty() {
        // No predicates, use cond directly
        Box::new(CstNode::list(case_children, Default::default()))
    } else if all_predicates.len() == 1 {
        // Single predicate, wrap in when
        let pred = &all_predicates[0];
        let cond_node = CstNode::list(case_children, Default::default());
        let when_children = vec![
            Box::new(CstNode::atom("when", Default::default())),
            pred.clone(),
            Box::new(cond_node),
        ];
        Box::new(CstNode::list(when_children, Default::default()))
    } else {
        // Multiple predicates, wrap in (and ...) then when
        let mut and_children = vec![Box::new(CstNode::atom("and", Default::default()))];
        for pred in &all_predicates {
            and_children.push(pred.clone());
        }
        let and_node = CstNode::list(and_children, Default::default());
        let cond_node = CstNode::list(case_children, Default::default());
        let when_children = vec![
            Box::new(CstNode::atom("when", Default::default())),
            Box::new(and_node),
            Box::new(cond_node),
        ];
        Box::new(CstNode::list(when_children, Default::default()))
    };

    // Insert the final effect at the END
    new_children.push(final_effect);

    Some(Box::new(CstNode::list(new_children, node.ann.clone())))
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
pub fn validate_migration(migrated_text: &str) -> Result<(), Vec<may_i_sexpr::RawError>> {
    match super::config::parse_config(migrated_text) {
        Ok(_) => Ok(()),
        Err(e) => Err(vec![e]),
    }
}

/// Check for unhandled v1 constructs in the original source that couldn't be migrated.
/// Returns a list of warnings about constructs that may need manual attention.
pub fn check_unhandled_cases(original_text: &str) -> Vec<UnhandledCase> {
    let mut warnings = Vec::new();
    let (forms, _) = may_i_sexpr::parse_cst(original_text);

    for form in &forms {
        check_node_unhandled(form, &mut warnings, true);
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

/// A span in the source text (for error reporting).
#[derive(Debug, Clone, Copy)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// A single form that will be migrated.
#[derive(Debug, Clone)]
pub struct MigrationDiff {
    /// Original form text (with trivia)
    pub before: String,
    /// Migrated form text
    pub after: String,
    /// Up to 2 lines of trivia before the form
    pub context_before: Vec<String>,
    /// Up to 2 lines of trivia after the form
    pub context_after: Vec<String>,
    /// Span in original file (for error reporting)
    pub span: Span,
}

/// Error with context for display.
#[derive(Debug, Clone)]
pub struct MigrationError {
    pub message: String,
    pub span: Span,
    pub context_before: Vec<String>,
    pub context_after: Vec<String>,
}

/// Result of analyzing a config for migration.
#[derive(Debug, Clone)]
pub struct MigrationAnalysis {
    /// Forms that will change
    pub diffs: Vec<MigrationDiff>,
    /// Forms that couldn't be parsed (with context)
    pub errors: Vec<MigrationError>,
    /// Forms that remained unchanged
    pub unchanged_count: usize,
}

/// Extract trivia context (up to N lines) from a node's leading trivia.
pub fn extract_leading_context(node: &CstNode, max_lines: usize) -> Vec<String> {
    extract_context_from_trivia(&node.ann.leading, max_lines)
}

/// Extract trivia context (up to N lines) from a node's trailing trivia.
pub fn extract_trailing_context(node: &CstNode, max_lines: usize) -> Vec<String> {
    extract_context_from_trivia(&node.ann.trailing, max_lines)
}

/// Extract context from trivia items, up to max_lines lines.
fn extract_context_from_trivia(
    trivia: &[may_i_sexpr::cst::Trivia],
    max_lines: usize,
) -> Vec<String> {
    let mut result = Vec::new();
    let mut line_count = 0;

    for item in trivia.iter().rev() {
        let text = item.as_str();
        result.push(text.to_string());
        line_count += text.matches('\n').count();
        if line_count >= max_lines {
            break;
        }
    }

    // Reverse to maintain original order
    result.reverse();
    result
}

/// Analyze a config for migration and produce a detailed diff.
pub fn analyze_migration(source: &str) -> MigrationAnalysis {
    let (forms, errors) = may_i_sexpr::parse_cst(source);
    let mut diffs = Vec::new();
    let mut migration_errors = Vec::new();
    let mut unchanged_count = 0;

    // Convert parse errors to migration errors with context
    for err in &errors {
        migration_errors.push(MigrationError {
            message: format!("{}", err),
            span: Span { start: 0, end: 0 },
            context_before: vec![],
            context_after: vec![],
        });
    }

    // Analyze each form
    for form in &forms {
        let original = form.serialize();
        let migrated_form = migrate(form.clone());
        let migrated = migrated_form.serialize();

        if original != migrated {
            // Form changed - create a diff
            diffs.push(MigrationDiff {
                before: original,
                after: migrated,
                context_before: extract_leading_context(form, 2),
                context_after: extract_trailing_context(form, 2),
                span: Span {
                    start: form.ann.span.start,
                    end: form.ann.span.end,
                },
            });
        } else {
            unchanged_count += 1;
        }
    }

    MigrationAnalysis {
        diffs,
        errors: migration_errors,
        unchanged_count,
    }
}

/// Recursively check a CST node for unhandled v1 constructs.
/// Only reports forms at the top level of each form (not nested inside migratable forms).
fn check_node_unhandled(node: &CstNode, warnings: &mut Vec<UnhandledCase>, is_top_level: bool) {
    if let Some(list) = node.as_list()
        && !list.is_empty()
    {
        if let Some(tag) = list[0].as_atom() {
            match tag {
                // Legacy v1 forms that should have been converted - only report at top level
                "wrapper" if is_top_level => {
                    warnings.push(UnhandledCase {
                        description: "Legacy wrapper form".to_string(),
                        source: node.serialize(),
                        suggestion: "Convert to (rule ...) with . (may-i *)".to_string(),
                    });
                    // Don't recurse into wrapper forms - they're already flagged
                    return;
                }
                "defcontext" if is_top_level => {
                    warnings.push(UnhandledCase {
                        description: "Legacy defcontext form".to_string(),
                        source: node.serialize(),
                        suggestion: "Convert to (define ...)".to_string(),
                    });
                    return;
                }
                "context" => {
                    // Context inside a rule should be reported
                    warnings.push(UnhandledCase {
                        description: "Legacy context form in rule".to_string(),
                        source: node.serialize(),
                        suggestion: "Inline context expression into rule predicates".to_string(),
                    });
                    return;
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
                    return;
                }
                "MatcherCondPredicate" | "ArgMatcher" | "BoolExpr" => {
                    warnings.push(UnhandledCase {
                        description: "Legacy internal type name".to_string(),
                        source: node.serialize(),
                        suggestion: "This should not appear in user config".to_string(),
                    });
                    return;
                }
                _ => {}
            }
        }

        // Recursively check children (not at top level)
        for child in list {
            check_node_unhandled(child, warnings, false);
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

    #[test]
    fn test_defcontext_to_define_with_has_value() {
        // Test that (has :key "value") gets converted to (has [:key "value"])
        let input = r#"(defcontext prod (has :env "prod"))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = defcontext_to_define(&node).unwrap();
        // Note: serialization adds a space after [ for formatting
        assert_eq!(result.serialize(), r#"(define prod (has [ :env "prod"]))"#);
    }

    // --- Additional tests for uncovered lines ---

    #[test]
    fn test_rule_simplify_command_not_rule() {
        let input = "(other (command git))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_simplify_command(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_rule_simplify_command_too_short() {
        let input = "(rule)";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_simplify_command(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_rule_simplify_command_not_command_tag() {
        let input = "(rule git (effect :allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_simplify_command(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_rule_simplify_command_wrong_size() {
        let input = "(rule (command git extra) (effect :allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_simplify_command(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_rule_inline_context_not_rule() {
        let input = "(other (context x))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_inline_context(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_rule_inline_context_no_context() {
        let input = "(rule git (effect :allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_inline_context(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_rule_inline_context_wrong_size() {
        let input = "(rule git (context) (effect :allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_inline_context(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_rule_inline_args_not_rule() {
        let input = "(other (args x))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_inline_args(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_rule_inline_args_no_args() {
        let input = "(rule git (effect :allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_inline_args(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_rule_inline_args_with_cond() {
        let input = "(rule git (args (cond (x :allow))) (effect :allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_inline_args(&node);
        // Should return None since cond is handled by args_cond_to_case
        assert!(result.is_none());
    }

    #[test]
    fn test_wrapper_to_rule_not_wrapper() {
        let input = "(other cmd)";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = wrapper_to_rule(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_wrapper_to_rule_too_short() {
        let input = "(wrapper)";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = wrapper_to_rule(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_wrapper_to_rule_with_capture() {
        let input = "(wrapper docker (positional run :command))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = wrapper_to_rule(&node).unwrap();
        let serialized = result.serialize();
        assert!(serialized.contains("rule"));
        assert!(serialized.contains("may-i") || serialized.contains("effect"));
    }

    #[test]
    fn test_defcontext_to_define_not_defcontext() {
        let input = "(define x y)";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = defcontext_to_define(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_defcontext_to_define_wrong_size() {
        let input = "(defcontext x)";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = defcontext_to_define(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_args_cond_to_case_not_rule() {
        let input = "(other (args (cond)))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = args_cond_to_case(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_args_cond_to_case_no_cond() {
        let input = "(rule git (args (positional)) (effect :allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = args_cond_to_case(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_migrate_top_level() {
        let input = "(rule (command git) (effect :allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = migrate(node);
        // New unified syntax uses :effect keyword with shorthand
        assert_eq!(result.serialize(), "(rule git :effect :allow)");
    }

    #[test]
    fn test_migrate_forms() {
        let input = "(rule (command git) (effect :allow))\n(defcontext ssh (has :via/ssh))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let results = migrate_forms(nodes);
        assert_eq!(results.len(), 2);
        // New unified syntax uses :effect keyword with shorthand
        assert!(results[0].serialize().contains("(rule git :effect :allow)"));
        assert!(
            results[1]
                .serialize()
                .contains("(define ssh (fact? :via/ssh))")
        );
    }

    #[test]
    fn test_validate_migration_success() {
        let input = "(rule (command git) (effect :allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let migrated = migrate(nodes.into_iter().next().unwrap());
        let result = validate_migration(&migrated.serialize());
        // Should pass now that migration outputs new unified syntax
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_migration_failure() {
        let result = validate_migration("(invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_check_unhandled_cases_wrapper() {
        let input = "(wrapper docker :command)";
        let warnings = check_unhandled_cases(input);
        assert!(!warnings.is_empty());
        assert!(warnings[0].description.contains("wrapper"));
    }

    #[test]
    fn test_check_unhandled_cases_defcontext() {
        let input = "(defcontext x y)";
        let warnings = check_unhandled_cases(input);
        assert!(!warnings.is_empty());
        assert!(warnings[0].description.contains("defcontext"));
    }

    #[test]
    fn test_check_unhandled_cases_context() {
        let input = "(rule x (context y) (effect :allow))";
        let warnings = check_unhandled_cases(input);
        assert!(!warnings.is_empty());
        assert!(warnings[0].description.contains("context"));
    }

    #[test]
    fn test_check_unhandled_cases_args_cond() {
        // The check looks for args where the inner element is directly the atom "cond"
        // This would be malformed input but tests the detection logic
        let input = "(args cond)";
        let warnings = check_unhandled_cases(input);
        assert!(!warnings.is_empty());
        assert!(warnings[0].description.contains("args with cond"));
    }

    #[test]
    fn test_check_unhandled_cases_legacy_types() {
        let input = "(MatcherCondPredicate x)";
        let warnings = check_unhandled_cases(input);
        assert!(!warnings.is_empty());
        assert!(warnings[0].description.contains("internal type"));
    }

    #[test]
    fn test_transform_has_expression_simple() {
        // Test (has :key "value") -> (has [:key "value"])
        let input = r#"(has :env "prod")"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = transform_has_expression(&node);
        assert!(result.serialize().contains("[ :env \"prod\"]"));
    }

    #[test]
    fn test_transform_has_expression_presence() {
        // Test (has :key) stays as-is
        let input = "(has :env)";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = transform_has_expression(&node);
        assert_eq!(result.serialize(), "(has :env)");
    }

    #[test]
    fn test_transform_has_expression_nested() {
        // Test nested has expressions
        let input = r#"(and (has :env "prod") (has :region "us-east"))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = transform_has_expression(&node);
        let serialized = result.serialize();
        assert!(serialized.contains("[ :env \"prod\"]"));
        assert!(serialized.contains("[ :region \"us-east\"]"));
    }

    #[test]
    fn test_args_cond_to_case_with_if() {
        // Test (args (if PRED THEN ELSE)) -> (cond ...)
        let input = r#"(rule "mv" (args (if (anywhere "-f") (effect :ask) (effect :allow))) (effect :allow))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = args_cond_to_case(&node).unwrap();
        let serialized = result.serialize();
        assert!(serialized.contains("cond"));
        assert!(!serialized.contains("args"));
    }

    #[test]
    fn test_wrapper_to_rule_with_capture_pattern() {
        // Test wrapper with [:key *] capture pattern
        let input = r#"(wrapper "ssh" (positional [:host *] :command+args))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = wrapper_to_rule(&node).unwrap();
        let serialized = result.serialize();
        // Should convert [:host *] to just *
        assert!(serialized.contains("positional *"));
        assert!(serialized.contains(":command+args"));
    }

    #[test]
    fn test_wrapper_to_rule_with_flag() {
        // Test wrapper with flag step
        let input = r#"(wrapper "docker" (flag "--rm" :command))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = wrapper_to_rule(&node).unwrap();
        let serialized = result.serialize();
        // Should include the flag pattern
        assert!(serialized.contains("positional"));
        assert!(serialized.contains("\"--rm\""));
    }
}
