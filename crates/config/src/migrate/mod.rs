//! Migration tool for converting v1 configs to canonical syntax using rewrite rules.
//!
//! This module provides rewrite rules that transform v1 s-expression syntax
//! into canonical syntax. The rules are applied iteratively until convergence.
//!
//! # Migration Pipeline
//!
//! 1. **Parse**: CST parses source, preserving trivia (comments/whitespace)
//! 2. **Analyze**: Compare original vs migrated forms to create diff
//! 3. **Migrate**: Apply rewrite rules until convergence
//! 4. **Validate**: Parse output with the canonical parser to ensure validity
//!
//! # String Type Preservation
//!
//! A critical implementation detail is distinguishing string literals from bare atoms.
//! The CST represents `"~/.config"` as `Shape::Str` and `bare-atom` as `Shape::Atom`.
//! During serialization, `Shape::Str` is always quoted while `Shape::Atom` is not.
//! Without this distinction, valid v1 quoted paths produce invalid canonical unquoted output.

// Shared helpers used by multiple rules.
pub(crate) mod helpers;

// Rewrite rules — one module per rule (or small related group).
mod collapse_effects;
mod cond_simplify;
mod defcontext_to_define;
mod effect_to_when;
mod flatten_combinators;
mod flatten_nested_if;
mod hoist_cond;
mod inline_args;
mod inline_context;
mod or_when_to_if;
mod predicate_pushdown;
mod rename_has_to_fact;
mod simplify_command;
mod wrapper_to_rule;

use may_i_sexpr::cst::CstNode;

/// A rewrite rule that transforms v1 syntax to canonical.
pub type RewriteFn = Box<dyn Fn(&CstNode) -> Option<Box<CstNode>>>;

/// Get all v1→canonical migration rewrite rules.
///
/// Rules are applied by `rewrite_until_convergence`, which repeatedly walks the
/// whole tree applying each rule until no rule fires.  The ordering within the
/// vec only affects which rule wins when multiple rules could fire on the same
/// node in the same pass; it does **not** mean earlier rules run before later
/// ones globally.
///
/// # Ordering constraints
///
/// The following dependencies must be respected when adding or reordering rules:
///
/// - `hoist_cond` **before** `rule_inline_args`: `hoist_cond` needs the
///   `(args ...)` tag present to detect `(args (cond ...))`.  `rule_inline_args`
///   removes that tag by inlining the matcher directly.
///
/// - `rule_collapse_effects` **after** all rules that may produce multiple body
///   children in a rule (e.g., `rule_inline_context`, `rule_inline_args`):
///   collapsing only makes sense once the rule body is in its final shape.
///
/// - `flatten_combinators` **after** `rule_inline_args` and `hoist_cond`:
///   inlining may create nested `(and (and ...))` structures that flattening
///   then canonicalises.
///
/// - `cond_single_clause_to_if`, `and_trailing_effect_to_when`,
///   `or_leading_when_to_if`, `flatten_nested_if`, and `predicate_pushdown`
///   are cosmetic simplifiers that run last and have no dependencies other
///   than the tree being in near-canonical form.
///
/// - `or_leading_when_to_if` **before** `predicate_pushdown`:
///   peels the leading `(when P E)` off an `or` to produce `(if P E rest)`.
///   This must fire before `predicate_pushdown` would collapse the trailing
///   `when` into the `or`.
///
/// - `flatten_nested_if` composes with `or_leading_when_to_if`: repeated
///   peeling produces `(if P1 E1 (if P2 E2 ...))`, which is then collapsed
///   into `(cond (P1 E1) (P2 E2) ...)`.
///
/// - `predicate_pushdown` **after** `and_trailing_effect_to_when`:
///   `and_trailing_effect_to_when` produces `(when ...)` from
///   `(and ... (effect ...))`, and `predicate_pushdown` then lifts
///   any remaining `(and/or ... (when ...))` patterns.
pub fn migration_rules() -> Vec<RewriteFn> {
    vec![
        // Stage 1 — structural unwrapping
        Box::new(simplify_command::rule_simplify_command),
        Box::new(inline_context::rule_inline_context),
        Box::new(hoist_cond::hoist_cond),
        Box::new(inline_args::rule_inline_args),
        Box::new(wrapper_to_rule::wrapper_to_rule),
        Box::new(defcontext_to_define::defcontext_to_define),
        Box::new(rename_has_to_fact::rename_has_to_fact),
        // Stage 2 — normalisation (must run after stage 1 is stable)
        Box::new(collapse_effects::rule_collapse_effects),
        Box::new(flatten_combinators::flatten_combinators),
        // Stage 3 — cosmetic simplification
        Box::new(cond_simplify::cond_single_clause_to_if),
        Box::new(cond_simplify::cond_absorb_else),
        Box::new(effect_to_when::and_trailing_effect_to_when),
        Box::new(or_when_to_if::or_leading_when_to_if),
        Box::new(flatten_nested_if::flatten_nested_if),
        Box::new(predicate_pushdown::predicate_pushdown),
    ]
}

/// Apply all migration rules to a CST until convergence.
pub fn migrate(node: Box<CstNode>) -> Box<CstNode> {
    may_i_sexpr::cst::rewrite_until_convergence(node, &migration_rules())
}

/// Migrate multiple top-level forms.
pub fn migrate_forms(forms: Vec<Box<CstNode>>) -> Vec<Box<CstNode>> {
    forms.into_iter().map(migrate).collect()
}

/// Validate that migrated output can be parsed with the canonical parser.
/// Returns Ok(()) if valid, or Err with a list of validation errors.
pub fn validate_migration(migrated_text: &str) -> Result<(), Vec<may_i_sexpr::RawError>> {
    match crate::config::parse_config(migrated_text) {
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
    fn test_migrate_top_level() {
        let input = "(rule (command git) (effect :allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = migrate(node);
        assert_eq!(result.serialize(), "(rule git (effect :allow))");
    }

    #[test]
    fn test_migrate_forms() {
        let input = "(rule (command git) (effect :allow))\n(defcontext ssh (has :via/ssh))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let results = migrate_forms(nodes);
        assert_eq!(results.len(), 2);
        assert!(
            results[0]
                .serialize()
                .contains("(rule git (effect :allow))")
        );
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
}
