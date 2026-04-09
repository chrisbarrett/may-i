// Define resolution and validation for the unified DSL.
// Tasks 3.1-3.5: Build resolution map, detect duplicates, undefined refs, cycles, and resolve.

use may_i_core::ast::{Define, Effect, Predicate, Rule, Spanned};
use may_i_core::span::Span;
use std::collections::{HashMap, HashSet};

/// A resolution error with source span information.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ResolutionError {
    pub message: String,
    pub span: Span,
    pub help: Option<String>,
}

impl ResolutionError {
    pub(crate) fn new(message: impl Into<String>, span: Span) -> Self {
        Self {
            message: message.into(),
            span,
            help: None,
        }
    }

    pub(crate) fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }
}

impl std::fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(help) = &self.help {
            write!(f, "\n  help: {help}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ResolutionError {}

/// Map of define names to their definitions.
#[derive(Debug, Clone, Default)]
pub(crate) struct DefineMap {
    /// Name -> (index in original defines list, span)
    indices: HashMap<String, (usize, Span)>,
}

impl DefineMap {
    /// Create a new define map from a list of defines.
    /// Returns an error if there are duplicate names.
    pub(crate) fn from_defines(defines: &[Define]) -> Result<Self, ResolutionError> {
        let mut indices: HashMap<String, (usize, Span)> = HashMap::new();

        for (idx, define) in defines.iter().enumerate() {
            if let Some((_, existing_span)) = indices.get(&define.name) {
                return Err(ResolutionError::new(
                    format!(
                        "duplicate define name: '{}' (first defined at byte offset {})",
                        define.name, existing_span.start
                    ),
                    define.span,
                )
                .with_help(
                    "each (define ...) must have a unique name, consider renaming this one"
                        .to_string(),
                ));
            }
            indices.insert(define.name.clone(), (idx, define.span));
        }

        Ok(Self { indices })
    }

    /// Get the define index and span for a name.
    pub(crate) fn get(&self, name: &str) -> Option<(usize, Span)> {
        self.indices.get(name).copied()
    }

    /// Get all defined names.
    pub(crate) fn names(&self) -> impl Iterator<Item = &String> {
        self.indices.keys()
    }

    /// Check if a name is defined.
    #[cfg(test)]
    fn contains(&self, name: &str) -> bool {
        self.indices.contains_key(name)
    }
}

/// Information about a predicate reference.
#[derive(Debug, Clone)]
pub(crate) struct NamedRef {
    pub name: String,
    pub span: Span,
}

/// Collect all named predicate references from a predicate.
pub(crate) fn collect_named_refs(predicate: &Spanned<Predicate>) -> Vec<NamedRef> {
    let mut refs = Vec::new();
    collect_refs_recursive(&predicate.value, predicate.span, &mut refs);
    refs
}

fn collect_refs_recursive(predicate: &Predicate, span: Span, refs: &mut Vec<NamedRef>) {
    match predicate {
        Predicate::Named(name) => {
            refs.push(NamedRef {
                name: name.clone(),
                span,
            });
        }
        Predicate::And(predicates) | Predicate::Or(predicates) => {
            for p in predicates {
                collect_refs_recursive(p, span, refs);
            }
        }
        Predicate::Not(inner) => {
            collect_refs_recursive(inner, span, refs);
        }
        _ => {} // Has and Arg don't contain nested predicates
    }
}

/// Detect cycles in define references using DFS.
pub(crate) fn detect_cycles(
    defines: &[Define],
    define_map: &DefineMap,
) -> Result<(), ResolutionError> {
    // Build adjacency list: name -> names it references
    let mut adjacency: HashMap<String, Vec<String>> = HashMap::new();

    for define in defines {
        let refs = collect_named_refs(&define.predicate);
        let ref_names: Vec<String> = refs.into_iter().map(|r| r.name).collect();
        adjacency.insert(define.name.clone(), ref_names);
    }

    // DFS to detect cycles
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();

    for name in define_map.names() {
        if !visited.contains(name) {
            dfs_check_cycle(name, &adjacency, &mut visiting, &mut visited, define_map)?;
        }
    }

    Ok(())
}

fn dfs_check_cycle(
    name: &str,
    adjacency: &HashMap<String, Vec<String>>,
    visiting: &mut HashSet<String>,
    visited: &mut HashSet<String>,
    define_map: &DefineMap,
) -> Result<(), ResolutionError> {
    visiting.insert(name.to_string());

    if let Some(neighbors) = adjacency.get(name) {
        for neighbor in neighbors {
            if visiting.contains(neighbor) {
                // Found a cycle
                let (_, span) = define_map.get(name).unwrap();
                return Err(ResolutionError::new(
                    format!("cyclic define reference detected: '{name}' -> '{neighbor}'"),
                    span,
                )
                .with_help("predicates cannot reference each other in a cycle"));
            }

            if !visited.contains(neighbor) {
                dfs_check_cycle(neighbor, adjacency, visiting, visited, define_map)?;
            }
        }
    }

    visiting.remove(name);
    visited.insert(name.to_string());
    Ok(())
}

/// Check for undefined predicate references in a list of rules and defines.
pub(crate) fn check_undefined_refs(
    rules: &[Rule],
    defines: &[Define],
    define_map: &DefineMap,
) -> Result<(), ResolutionError> {
    // Collect all defined names
    let defined_names: HashSet<String> = define_map.names().cloned().collect();

    // Check references in defines
    for define in defines {
        let refs = collect_named_refs(&define.predicate);
        for named_ref in refs {
            if !defined_names.contains(&named_ref.name) {
                return Err(ResolutionError::new(
                    format!("undefined predicate reference: '{}'", named_ref.name),
                    named_ref.span,
                )
                .with_help(format!(
                    "define '{}' before using it, or check for typos",
                    named_ref.name
                )));
            }
        }
    }

    // Check references in rules (predicates can appear in effects within conditionals)
    for rule in rules {
        // Check effect for named predicate references
        {
            let refs = collect_named_refs_from_effect(&rule.effect);
            for named_ref in refs {
                if !defined_names.contains(&named_ref.name) {
                    return Err(ResolutionError::new(
                        format!(
                            "undefined predicate reference: '{}' in rule",
                            named_ref.name
                        ),
                        named_ref.span,
                    )
                    .with_help(format!(
                        "define '{}' before using it, or check for typos",
                        named_ref.name
                    )));
                }
            }
        }
    }

    Ok(())
}

/// Collect all named predicate references from an effect.
/// This recursively searches through conditionals (when/unless/if/cond).
pub(crate) fn collect_named_refs_from_effect(effect: &Spanned<Effect>) -> Vec<NamedRef> {
    let mut refs = Vec::new();
    collect_refs_from_effect_recursive(&effect.value, effect.span, &mut refs);
    refs
}

fn collect_refs_from_effect_recursive(effect: &Effect, _span: Span, refs: &mut Vec<NamedRef>) {
    match effect {
        Effect::When { predicate, .. } | Effect::Unless { predicate, .. } => {
            collect_refs_recursive(&predicate.value, predicate.span, refs);
        }
        Effect::If {
            predicate,
            then_effect,
            else_effect,
        } => {
            collect_refs_recursive(&predicate.value, predicate.span, refs);
            collect_refs_from_effect_recursive(&then_effect.value, then_effect.span, refs);
            collect_refs_from_effect_recursive(&else_effect.value, else_effect.span, refs);
        }
        Effect::Cond { branches, fallback } => {
            for (pred, eff) in branches {
                collect_refs_recursive(&pred.value, pred.span, refs);
                collect_refs_from_effect_recursive(&eff.value, eff.span, refs);
            }
            if let Some(fb) = fallback {
                collect_refs_from_effect_recursive(&fb.value, fb.span, refs);
            }
        }
        Effect::And { effects } | Effect::Or { effects } => {
            for e in effects {
                collect_refs_from_effect_recursive(&e.value, e.span, refs);
            }
        }
        Effect::Not { effect } => {
            collect_refs_from_effect_recursive(&effect.value, effect.span, refs);
        }
        _ => {} // Terminal effects and patterns don't contain predicates
    }
}

/// Resolve all named predicates by inlining their definitions.
/// Returns a new list of rules with all named predicates resolved.
pub(crate) fn resolve_predicates(
    rules: &[Rule],
    defines: &[Define],
    define_map: &DefineMap,
) -> Result<Vec<Rule>, ResolutionError> {
    rules
        .iter()
        .map(|rule| resolve_rule_predicates(rule, defines, define_map))
        .collect()
}

fn resolve_rule_predicates(
    rule: &Rule,
    defines: &[Define],
    define_map: &DefineMap,
) -> Result<Rule, ResolutionError> {
    let resolved_command = resolve_effect_predicates(&rule.command_effect, defines, define_map)?;
    let resolved_effect = resolve_effect_predicates(&rule.effect, defines, define_map)?;

    Ok(Rule {
        command_effect: resolved_command,
        effect: resolved_effect,
        checks: rule.checks.clone(),
        span: rule.span,
    })
}

fn resolve_effect_predicates(
    effect: &Spanned<Effect>,
    defines: &[Define],
    define_map: &DefineMap,
) -> Result<Spanned<Effect>, ResolutionError> {
    let resolved = match &effect.value {
        Effect::When {
            predicate,
            effect: inner,
        } => {
            let resolved_pred = resolve_single_predicate(predicate, defines, define_map)?;
            let resolved_inner = resolve_effect_predicates(inner, defines, define_map)?;
            Effect::When {
                predicate: resolved_pred,
                effect: Box::new(resolved_inner),
            }
        }
        Effect::Unless {
            predicate,
            effect: inner,
        } => {
            let resolved_pred = resolve_single_predicate(predicate, defines, define_map)?;
            let resolved_inner = resolve_effect_predicates(inner, defines, define_map)?;
            Effect::Unless {
                predicate: resolved_pred,
                effect: Box::new(resolved_inner),
            }
        }
        Effect::If {
            predicate,
            then_effect,
            else_effect,
        } => {
            let resolved_pred = resolve_single_predicate(predicate, defines, define_map)?;
            let resolved_then = resolve_effect_predicates(then_effect, defines, define_map)?;
            let resolved_else = resolve_effect_predicates(else_effect, defines, define_map)?;
            Effect::If {
                predicate: resolved_pred,
                then_effect: Box::new(resolved_then),
                else_effect: Box::new(resolved_else),
            }
        }
        Effect::Cond { branches, fallback } => {
            let resolved_branches: Result<Vec<_>, _> = branches
                .iter()
                .map(|(pred, eff)| {
                    let resolved_pred = resolve_single_predicate(pred, defines, define_map)?;
                    let resolved_eff = resolve_effect_predicates(eff, defines, define_map)?;
                    Ok((resolved_pred, resolved_eff))
                })
                .collect();
            let resolved_fallback = if let Some(fb) = fallback {
                Some(Box::new(resolve_effect_predicates(
                    fb, defines, define_map,
                )?))
            } else {
                None
            };
            Effect::Cond {
                branches: resolved_branches?,
                fallback: resolved_fallback,
            }
        }
        Effect::And { effects } => {
            let resolved: Result<Vec<_>, _> = effects
                .iter()
                .map(|e| resolve_effect_predicates(e, defines, define_map))
                .collect();
            Effect::And { effects: resolved? }
        }
        Effect::Or { effects } => {
            let resolved: Result<Vec<_>, _> = effects
                .iter()
                .map(|e| resolve_effect_predicates(e, defines, define_map))
                .collect();
            Effect::Or { effects: resolved? }
        }
        Effect::Not { effect } => {
            let resolved = resolve_effect_predicates(effect, defines, define_map)?;
            Effect::Not {
                effect: Box::new(resolved),
            }
        }
        other => other.clone(),
    };

    Ok(Spanned::new(resolved, effect.span))
}

fn resolve_single_predicate(
    predicate: &Spanned<Predicate>,
    defines: &[Define],
    define_map: &DefineMap,
) -> Result<Spanned<Predicate>, ResolutionError> {
    let resolved = match &predicate.value {
        Predicate::Named(name) => {
            // Get the define and inline it, then resolve recursively
            // since the inlined body may itself contain Named references.
            if let Some((idx, _)) = define_map.get(name) {
                let inlined = Spanned::new(defines[idx].predicate.value.clone(), predicate.span);
                return resolve_single_predicate(&inlined, defines, define_map);
            } else {
                // This shouldn't happen if we checked for undefined refs first
                return Err(ResolutionError::new(
                    format!("internal error: undefined predicate '{name}'"),
                    predicate.span,
                ));
            }
        }
        Predicate::And(predicates) => {
            let resolved: Result<Vec<_>, _> = predicates
                .iter()
                .map(|p| {
                    resolve_single_predicate(
                        &Spanned::new(p.clone(), predicate.span),
                        defines,
                        define_map,
                    )
                })
                .collect();
            Predicate::And(resolved?.into_iter().map(|s| s.value).collect())
        }
        Predicate::Or(predicates) => {
            let resolved: Result<Vec<_>, _> = predicates
                .iter()
                .map(|p| {
                    resolve_single_predicate(
                        &Spanned::new(p.clone(), predicate.span),
                        defines,
                        define_map,
                    )
                })
                .collect();
            Predicate::Or(resolved?.into_iter().map(|s| s.value).collect())
        }
        Predicate::Not(inner) => {
            let resolved = resolve_single_predicate(
                &Spanned::new(inner.as_ref().clone(), predicate.span),
                defines,
                define_map,
            )?;
            Predicate::Not(Box::new(resolved.value))
        }
        other => other.clone(),
    };

    Ok(Spanned::new(resolved, predicate.span))
}

/// Full validation pipeline for defines and rules.
/// Performs all validation checks in the correct order.
pub fn validate_and_resolve(
    rules: &[Rule],
    defines: &[Define],
) -> Result<Vec<Rule>, Vec<ResolutionError>> {
    let mut errors = Vec::new();

    // Step 1: Build define map and check for duplicates (3.1, 3.2)
    let define_map = match DefineMap::from_defines(defines) {
        Ok(map) => map,
        Err(e) => {
            errors.push(e);
            return Err(errors);
        }
    };

    // Step 2: Check for undefined references (3.3)
    if let Err(e) = check_undefined_refs(rules, defines, &define_map) {
        errors.push(e);
        return Err(errors);
    }

    // Step 3: Detect cycles (3.4)
    if let Err(e) = detect_cycles(defines, &define_map) {
        errors.push(e);
        return Err(errors);
    }

    // Step 4: Resolve named predicates (3.5)
    let resolved_rules = match resolve_predicates(rules, defines, &define_map) {
        Ok(rules) => rules,
        Err(e) => {
            errors.push(e);
            return Err(errors);
        }
    };

    Ok(resolved_rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::pattern::CommandPattern;

    fn dummy_span() -> Span {
        Span::new(0, 0)
    }

    fn create_rule_with_conditional(predicate: Predicate, effect: Effect) -> Rule {
        let conditional_effect = Effect::When {
            predicate: Spanned::new(predicate, dummy_span()),
            effect: Box::new(Spanned::new(effect, dummy_span())),
        };
        Rule::new(
            Spanned::new(
                Effect::CommandPattern(CommandPattern::Literal("test".to_string())),
                dummy_span(),
            ),
            Spanned::new(conditional_effect, dummy_span()),
            vec![],
            dummy_span(),
        )
    }

    fn create_define(name: &str, predicate: Predicate) -> Define {
        Define {
            name: name.to_string(),
            predicate: Spanned::new(predicate, dummy_span()),
            span: dummy_span(),
        }
    }

    #[test]
    fn collect_named_refs_finds_all_refs() {
        let defines = vec![
            create_define("foo", Predicate::fact_presence(":x")),
            create_define("bar", Predicate::fact_presence(":y")),
        ];
        let rules = vec![];
        let define_map = DefineMap::from_defines(&defines).unwrap();

        // Just verify no errors
        assert!(check_undefined_refs(&rules, &defines, &define_map).is_ok());
    }

    #[test]
    fn detect_undefined_reference() {
        let defines = vec![];
        // Create a rule with a named predicate reference inside a conditional
        let rules = vec![create_rule_with_conditional(
            Predicate::Named("undefined".to_string()),
            Effect::Allow(None),
        )];
        let define_map = DefineMap::default();

        let result = check_undefined_refs(&rules, &defines, &define_map);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("undefined"));
    }

    #[test]
    fn detect_direct_cycle() {
        let defines = vec![
            create_define("a", Predicate::Named("b".to_string())),
            create_define("b", Predicate::Named("a".to_string())),
        ];
        let define_map = DefineMap::from_defines(&defines).unwrap();

        let result = detect_cycles(&defines, &define_map);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("cyclic"));
    }

    #[test]
    fn detect_indirect_cycle() {
        let defines = vec![
            create_define("a", Predicate::Named("b".to_string())),
            create_define("b", Predicate::Named("c".to_string())),
            create_define("c", Predicate::Named("a".to_string())),
        ];
        let define_map = DefineMap::from_defines(&defines).unwrap();

        let result = detect_cycles(&defines, &define_map);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("cyclic"));
    }

    #[test]
    fn resolve_simple_named_predicate() {
        let defines = vec![create_define("safe", Predicate::fact_presence(":safe"))];
        let rules = vec![create_rule_with_conditional(
            Predicate::Named("safe".to_string()),
            Effect::Allow(None),
        )];
        let define_map = DefineMap::from_defines(&defines).unwrap();

        let resolved = resolve_predicates(&rules, &defines, &define_map).unwrap();
        assert_eq!(resolved.len(), 1);
        // After resolution, the Named predicate in the effect should be replaced with Fact
        match &resolved[0].effect.value {
            Effect::When { predicate, .. } => {
                assert!(matches!(predicate.value, Predicate::Fact(_)));
            }
            _ => panic!("expected When effect"),
        }
    }

    #[test]
    fn resolve_nested_predicate() {
        let defines = vec![
            create_define("a", Predicate::fact_presence(":a")),
            create_define(
                "b",
                Predicate::And(vec![
                    Predicate::Named("a".to_string()),
                    Predicate::fact_presence(":b"),
                ]),
            ),
        ];
        let rules = vec![create_rule_with_conditional(
            Predicate::Named("b".to_string()),
            Effect::Allow(None),
        )];
        let define_map = DefineMap::from_defines(&defines).unwrap();

        let resolved = resolve_predicates(&rules, &defines, &define_map).unwrap();
        match &resolved[0].effect.value {
            Effect::When { predicate, .. } => {
                assert!(matches!(predicate.value, Predicate::And(_)));
            }
            _ => panic!("expected When effect"),
        }
    }

    #[test]
    fn resolution_error_display_without_help() {
        let err = ResolutionError::new("test error", dummy_span());
        let display = format!("{}", err);
        assert_eq!(display, "test error");
    }

    #[test]
    fn resolution_error_display_with_help() {
        let err = ResolutionError::new("test error", dummy_span()).with_help("try this");
        let display = format!("{}", err);
        assert!(display.contains("test error"));
        assert!(display.contains("help: try this"));
    }

    #[test]
    fn define_map_contains_name() {
        let defines = vec![create_define("foo", Predicate::fact_presence(":x"))];
        let map = DefineMap::from_defines(&defines).unwrap();
        assert!(map.contains("foo"));
        assert!(!map.contains("bar"));
    }

    #[test]
    fn define_map_get_returns_index_and_span() {
        let defines = vec![create_define("foo", Predicate::fact_presence(":x"))];
        let map = DefineMap::from_defines(&defines).unwrap();
        assert!(map.get("foo").is_some());
        assert!(map.get("bar").is_none());
    }

    #[test]
    fn define_map_names_returns_all_names() {
        let defines = vec![
            create_define("foo", Predicate::fact_presence(":x")),
            create_define("bar", Predicate::fact_presence(":y")),
        ];
        let map = DefineMap::from_defines(&defines).unwrap();
        let names: Vec<_> = map.names().collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&&"foo".to_string()));
        assert!(names.contains(&&"bar".to_string()));
    }

    #[test]
    fn detect_undefined_in_define() {
        let defines = vec![create_define(
            "foo",
            Predicate::And(vec![
                Predicate::fact_presence(":x"),
                Predicate::Named("undefined".to_string()),
            ]),
        )];
        let rules = vec![];
        let define_map = DefineMap::from_defines(&defines).unwrap();

        let result = check_undefined_refs(&rules, &defines, &define_map);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("undefined"));
    }

    #[test]
    fn detect_undefined_in_or_predicate() {
        let defines = vec![];
        let rules = vec![create_rule_with_conditional(
            Predicate::Or(vec![
                Predicate::fact_presence(":x"),
                Predicate::Named("undefined".to_string()),
            ]),
            Effect::Allow(None),
        )];
        let define_map = DefineMap::default();

        let result = check_undefined_refs(&rules, &defines, &define_map);
        assert!(result.is_err());
    }

    #[test]
    fn detect_undefined_in_not_predicate() {
        let defines = vec![];
        let rules = vec![create_rule_with_conditional(
            Predicate::Not(Box::new(Predicate::Named("undefined".to_string()))),
            Effect::Allow(None),
        )];
        let define_map = DefineMap::default();

        let result = check_undefined_refs(&rules, &defines, &define_map);
        assert!(result.is_err());
    }

    #[test]
    fn collect_named_refs_from_predicate_tree() {
        let predicate = Predicate::And(vec![
            Predicate::Named("a".to_string()),
            Predicate::Or(vec![
                Predicate::Named("b".to_string()),
                Predicate::Not(Box::new(Predicate::Named("c".to_string()))),
            ]),
        ]);
        let spanned = Spanned::new(predicate, dummy_span());
        let refs = collect_named_refs(&spanned);
        assert_eq!(refs.len(), 3);
    }

    #[test]
    fn resolve_not_predicate() {
        let defines = vec![create_define("safe", Predicate::fact_presence(":safe"))];
        let rules = vec![create_rule_with_conditional(
            Predicate::Not(Box::new(Predicate::Named("safe".to_string()))),
            Effect::Allow(None),
        )];
        let define_map = DefineMap::from_defines(&defines).unwrap();

        let resolved = resolve_predicates(&rules, &defines, &define_map).unwrap();
        // The predicate should be resolved within the effect
        assert!(matches!(resolved[0].effect.value, Effect::When { .. }));
    }

    #[test]
    fn validate_and_resolve_full_pipeline() {
        let defines = vec![create_define("safe", Predicate::fact_presence(":safe"))];
        let rules = vec![create_rule_with_conditional(
            Predicate::Named("safe".to_string()),
            Effect::Allow(None),
        )];

        let result = validate_and_resolve(&rules, &defines);
        assert!(result.is_ok());
        let resolved_rules = result.unwrap();
        assert_eq!(resolved_rules.len(), 1);
    }

    #[test]
    fn validate_and_resolve_detects_duplicate() {
        let defines = vec![
            create_define("safe", Predicate::fact_presence(":safe")),
            create_define("safe", Predicate::fact_presence(":other")),
        ];
        let rules = vec![];

        let result = validate_and_resolve(&rules, &defines);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 1);
    }

    #[test]
    fn validate_and_resolve_detects_undefined() {
        let defines = vec![];
        let rules = vec![create_rule_with_conditional(
            Predicate::Named("undefined".to_string()),
            Effect::Allow(None),
        )];

        let result = validate_and_resolve(&rules, &defines);
        assert!(result.is_err());
    }

    #[test]
    fn validate_and_resolve_detects_cycle() {
        let defines = vec![
            create_define("a", Predicate::Named("b".to_string())),
            create_define("b", Predicate::Named("a".to_string())),
        ];
        let rules = vec![];

        let result = validate_and_resolve(&rules, &defines);
        assert!(result.is_err());
    }

    // --- Effect variant resolution tests ---
    // Each test wraps a Named predicate inside a different Effect variant
    // to exercise the resolution and ref-collection arms.

    fn create_rule_with_effect(effect: Effect) -> Rule {
        Rule::new(
            Spanned::new(
                Effect::CommandPattern(CommandPattern::Literal("test".to_string())),
                dummy_span(),
            ),
            Spanned::new(effect, dummy_span()),
            vec![],
            dummy_span(),
        )
    }

    #[test]
    fn resolve_unless_with_named_predicate() {
        let defines = vec![create_define("safe", Predicate::fact_presence(":safe"))];
        let effect = Effect::Unless {
            predicate: Spanned::new(Predicate::Named("safe".to_string()), dummy_span()),
            effect: Box::new(Spanned::new(Effect::Deny(None), dummy_span())),
        };
        let rules = vec![create_rule_with_effect(effect)];
        let define_map = DefineMap::from_defines(&defines).unwrap();

        let resolved = resolve_predicates(&rules, &defines, &define_map).unwrap();
        match &resolved[0].effect.value {
            Effect::Unless { predicate, .. } => {
                assert!(matches!(predicate.value, Predicate::Fact(_)));
            }
            _ => panic!("expected Unless effect"),
        }
    }

    #[test]
    fn resolve_if_with_named_predicate() {
        let defines = vec![create_define("safe", Predicate::fact_presence(":safe"))];
        let effect = Effect::If {
            predicate: Spanned::new(Predicate::Named("safe".to_string()), dummy_span()),
            then_effect: Box::new(Spanned::new(Effect::Allow(None), dummy_span())),
            else_effect: Box::new(Spanned::new(Effect::Deny(None), dummy_span())),
        };
        let rules = vec![create_rule_with_effect(effect)];
        let define_map = DefineMap::from_defines(&defines).unwrap();

        let resolved = resolve_predicates(&rules, &defines, &define_map).unwrap();
        match &resolved[0].effect.value {
            Effect::If { predicate, .. } => {
                assert!(matches!(predicate.value, Predicate::Fact(_)));
            }
            _ => panic!("expected If effect"),
        }
    }

    #[test]
    fn resolve_cond_with_named_predicate() {
        let defines = vec![create_define("safe", Predicate::fact_presence(":safe"))];
        let effect = Effect::Cond {
            branches: vec![(
                Spanned::new(Predicate::Named("safe".to_string()), dummy_span()),
                Spanned::new(Effect::Allow(None), dummy_span()),
            )],
            fallback: Some(Box::new(Spanned::new(Effect::Deny(None), dummy_span()))),
        };
        let rules = vec![create_rule_with_effect(effect)];
        let define_map = DefineMap::from_defines(&defines).unwrap();

        let resolved = resolve_predicates(&rules, &defines, &define_map).unwrap();
        match &resolved[0].effect.value {
            Effect::Cond { branches, .. } => {
                assert!(matches!(branches[0].0.value, Predicate::Fact(_)));
            }
            _ => panic!("expected Cond effect"),
        }
    }

    #[test]
    fn resolve_and_effect_with_named_predicate() {
        let defines = vec![create_define("safe", Predicate::fact_presence(":safe"))];
        let effect = Effect::And {
            effects: vec![Spanned::new(
                Effect::When {
                    predicate: Spanned::new(Predicate::Named("safe".to_string()), dummy_span()),
                    effect: Box::new(Spanned::new(Effect::Allow(None), dummy_span())),
                },
                dummy_span(),
            )],
        };
        let rules = vec![create_rule_with_effect(effect)];
        let define_map = DefineMap::from_defines(&defines).unwrap();

        let resolved = resolve_predicates(&rules, &defines, &define_map).unwrap();
        match &resolved[0].effect.value {
            Effect::And { effects } => match &effects[0].value {
                Effect::When { predicate, .. } => {
                    assert!(matches!(predicate.value, Predicate::Fact(_)));
                }
                _ => panic!("expected When inside And"),
            },
            _ => panic!("expected And effect"),
        }
    }

    #[test]
    fn resolve_or_effect_with_named_predicate() {
        let defines = vec![create_define("safe", Predicate::fact_presence(":safe"))];
        let effect = Effect::Or {
            effects: vec![Spanned::new(
                Effect::When {
                    predicate: Spanned::new(Predicate::Named("safe".to_string()), dummy_span()),
                    effect: Box::new(Spanned::new(Effect::Allow(None), dummy_span())),
                },
                dummy_span(),
            )],
        };
        let rules = vec![create_rule_with_effect(effect)];
        let define_map = DefineMap::from_defines(&defines).unwrap();

        let resolved = resolve_predicates(&rules, &defines, &define_map).unwrap();
        match &resolved[0].effect.value {
            Effect::Or { effects } => match &effects[0].value {
                Effect::When { predicate, .. } => {
                    assert!(matches!(predicate.value, Predicate::Fact(_)));
                }
                _ => panic!("expected When inside Or"),
            },
            _ => panic!("expected Or effect"),
        }
    }

    #[test]
    fn resolve_not_effect_with_named_predicate() {
        let defines = vec![create_define("safe", Predicate::fact_presence(":safe"))];
        let effect = Effect::Not {
            effect: Box::new(Spanned::new(
                Effect::When {
                    predicate: Spanned::new(Predicate::Named("safe".to_string()), dummy_span()),
                    effect: Box::new(Spanned::new(Effect::Allow(None), dummy_span())),
                },
                dummy_span(),
            )),
        };
        let rules = vec![create_rule_with_effect(effect)];
        let define_map = DefineMap::from_defines(&defines).unwrap();

        let resolved = resolve_predicates(&rules, &defines, &define_map).unwrap();
        match &resolved[0].effect.value {
            Effect::Not { effect } => match &effect.value {
                Effect::When { predicate, .. } => {
                    assert!(matches!(predicate.value, Predicate::Fact(_)));
                }
                _ => panic!("expected When inside Not"),
            },
            _ => panic!("expected Not effect"),
        }
    }

    #[test]
    fn resolve_or_predicate_with_named() {
        let defines = vec![
            create_define("a", Predicate::fact_presence(":a")),
            create_define("b", Predicate::fact_presence(":b")),
        ];
        let rules = vec![create_rule_with_conditional(
            Predicate::Or(vec![
                Predicate::Named("a".to_string()),
                Predicate::Named("b".to_string()),
            ]),
            Effect::Allow(None),
        )];
        let define_map = DefineMap::from_defines(&defines).unwrap();

        let resolved = resolve_predicates(&rules, &defines, &define_map).unwrap();
        match &resolved[0].effect.value {
            Effect::When { predicate, .. } => {
                assert!(matches!(predicate.value, Predicate::Or(_)));
                if let Predicate::Or(preds) = &predicate.value {
                    assert!(preds.iter().all(|p| matches!(p, Predicate::Fact(_))));
                }
            }
            _ => panic!("expected When effect"),
        }
    }

    // --- Ref collection from effect variants ---

    #[test]
    fn collect_refs_from_if_effect() {
        let effect = Spanned::new(
            Effect::If {
                predicate: Spanned::new(Predicate::Named("a".to_string()), dummy_span()),
                then_effect: Box::new(Spanned::new(
                    Effect::When {
                        predicate: Spanned::new(Predicate::Named("b".to_string()), dummy_span()),
                        effect: Box::new(Spanned::new(Effect::Allow(None), dummy_span())),
                    },
                    dummy_span(),
                )),
                else_effect: Box::new(Spanned::new(Effect::Deny(None), dummy_span())),
            },
            dummy_span(),
        );

        let refs = collect_named_refs_from_effect(&effect);
        let names: Vec<&str> = refs.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
    }

    #[test]
    fn collect_refs_from_cond_effect() {
        let effect = Spanned::new(
            Effect::Cond {
                branches: vec![(
                    Spanned::new(Predicate::Named("a".to_string()), dummy_span()),
                    Spanned::new(Effect::Allow(None), dummy_span()),
                )],
                fallback: Some(Box::new(Spanned::new(
                    Effect::When {
                        predicate: Spanned::new(Predicate::Named("b".to_string()), dummy_span()),
                        effect: Box::new(Spanned::new(Effect::Deny(None), dummy_span())),
                    },
                    dummy_span(),
                ))),
            },
            dummy_span(),
        );

        let refs = collect_named_refs_from_effect(&effect);
        let names: Vec<&str> = refs.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
    }

    #[test]
    fn collect_refs_from_and_or_not_effects() {
        let effect = Spanned::new(
            Effect::And {
                effects: vec![Spanned::new(
                    Effect::Or {
                        effects: vec![Spanned::new(
                            Effect::Not {
                                effect: Box::new(Spanned::new(
                                    Effect::When {
                                        predicate: Spanned::new(
                                            Predicate::Named("x".to_string()),
                                            dummy_span(),
                                        ),
                                        effect: Box::new(Spanned::new(
                                            Effect::Allow(None),
                                            dummy_span(),
                                        )),
                                    },
                                    dummy_span(),
                                )),
                            },
                            dummy_span(),
                        )],
                    },
                    dummy_span(),
                )],
            },
            dummy_span(),
        );

        let refs = collect_named_refs_from_effect(&effect);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "x");
    }
}
