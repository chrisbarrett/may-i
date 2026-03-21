// Define resolution and validation for v2 DSL.
// Tasks 3.1-3.5: Build resolution map, detect duplicates, undefined refs, cycles, and resolve.

use may_i_core::span::Span;
use may_i_core::v2::ast::{Define, Rule, Spanned};
use may_i_core::v2::predicate::Predicate;
use std::collections::{HashMap, HashSet};

/// A resolution error with source span information.
#[derive(Debug, Clone)]
pub struct ResolutionError {
    pub message: String,
    pub span: Span,
    pub help: Option<String>,
}

impl ResolutionError {
    pub fn new(message: impl Into<String>, span: Span) -> Self {
        Self {
            message: message.into(),
            span,
            help: None,
        }
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
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
pub struct DefineMap {
    /// Name -> (index in original defines list, span)
    indices: HashMap<String, (usize, Span)>,
}

impl DefineMap {
    /// Create a new define map from a list of defines.
    /// Returns an error if there are duplicate names.
    pub fn from_defines(defines: &[Define]) -> Result<Self, ResolutionError> {
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

    /// Check if a name is defined.
    pub fn contains(&self, name: &str) -> bool {
        self.indices.contains_key(name)
    }

    /// Get the define index and span for a name.
    pub fn get(&self, name: &str) -> Option<(usize, Span)> {
        self.indices.get(name).copied()
    }

    /// Get all defined names.
    pub fn names(&self) -> impl Iterator<Item = &String> {
        self.indices.keys()
    }
}

/// Information about a predicate reference.
#[derive(Debug, Clone)]
pub struct NamedRef {
    pub name: String,
    pub span: Span,
}

/// Collect all named predicate references from a predicate.
pub fn collect_named_refs(predicate: &Spanned<Predicate>) -> Vec<NamedRef> {
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
pub fn detect_cycles(defines: &[Define], define_map: &DefineMap) -> Result<(), ResolutionError> {
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
pub fn check_undefined_refs(
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

    // Check references in rules
    for rule in rules {
        for predicate in &rule.predicates {
            let refs = collect_named_refs(predicate);
            for named_ref in refs {
                if !defined_names.contains(&named_ref.name) {
                    return Err(ResolutionError::new(
                        format!(
                            "undefined predicate reference: '{}' in rule for '{}'",
                            named_ref.name,
                            format_command_pattern(&rule.command.value)
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

fn format_command_pattern(pattern: &may_i_core::v2::pattern::CommandPattern) -> String {
    use may_i_core::v2::pattern::CommandPattern;
    match pattern {
        CommandPattern::Literal(s) => s.clone(),
        CommandPattern::Regex(_) => "(regex ...)".to_string(),
        CommandPattern::Or(_) => "(or ...)".to_string(),
    }
}

/// Resolve all named predicates by inlining their definitions.
/// Returns a new list of rules with all named predicates resolved.
pub fn resolve_predicates(
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
    let resolved_predicates: Result<Vec<_>, _> = rule
        .predicates
        .iter()
        .map(|p| resolve_single_predicate(p, defines, define_map))
        .collect();

    Ok(Rule {
        command: rule.command.clone(),
        predicates: resolved_predicates?,
        effect: rule.effect.clone(),
        span: rule.span,
    })
}

fn resolve_single_predicate(
    predicate: &Spanned<Predicate>,
    defines: &[Define],
    define_map: &DefineMap,
) -> Result<Spanned<Predicate>, ResolutionError> {
    let resolved = match &predicate.value {
        Predicate::Named(name) => {
            // Get the define and inline it
            if let Some((idx, _)) = define_map.get(name) {
                // Clone the predicate from the define (we keep the original span)
                defines[idx].predicate.value.clone()
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
) -> Result<(Vec<Rule>, DefineMap), Vec<ResolutionError>> {
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

    Ok((resolved_rules, define_map))
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::v2::ast::{Define, Effect, Rule};
    use may_i_core::v2::pattern::CommandPattern;

    fn dummy_span() -> Span {
        Span::new(0, 0)
    }

    fn create_rule(predicates: Vec<Predicate>) -> Rule {
        Rule {
            command: Spanned::new(CommandPattern::Literal("test".to_string()), dummy_span()),
            predicates: predicates
                .into_iter()
                .map(|p| Spanned::new(p, dummy_span()))
                .collect(),
            effect: Spanned::new(Effect::Allow(None), dummy_span()),
            span: dummy_span(),
        }
    }

    fn create_define(name: &str, predicate: Predicate) -> Define {
        Define {
            name: name.to_string(),
            predicate: Spanned::new(predicate, dummy_span()),
            span: dummy_span(),
        }
    }

    #[test]
    fn detect_duplicate_defines() {
        let defines = vec![
            create_define("foo", Predicate::has_presence(":x")),
            create_define("foo", Predicate::has_presence(":y")),
        ];

        let result = DefineMap::from_defines(&defines);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("duplicate"));
    }

    #[test]
    fn detect_undefined_reference() {
        let defines = vec![];
        let rules = vec![create_rule(vec![Predicate::Named("undefined".to_string())])];
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
        let defines = vec![create_define("safe", Predicate::has_presence(":safe"))];
        let rules = vec![create_rule(vec![Predicate::Named("safe".to_string())])];
        let define_map = DefineMap::from_defines(&defines).unwrap();

        let resolved = resolve_predicates(&rules, &defines, &define_map).unwrap();
        assert_eq!(resolved.len(), 1);
        // After resolution, the Named predicate should be replaced with Has
        assert!(matches!(resolved[0].predicates[0].value, Predicate::Has(_)));
    }

    #[test]
    fn resolve_nested_predicate() {
        let defines = vec![
            create_define("a", Predicate::has_presence(":a")),
            create_define(
                "b",
                Predicate::And(vec![
                    Predicate::Named("a".to_string()),
                    Predicate::has_presence(":b"),
                ]),
            ),
        ];
        let rules = vec![create_rule(vec![Predicate::Named("b".to_string())])];
        let define_map = DefineMap::from_defines(&defines).unwrap();

        let resolved = resolve_predicates(&rules, &defines, &define_map).unwrap();
        assert!(matches!(resolved[0].predicates[0].value, Predicate::And(_)));
    }
}
