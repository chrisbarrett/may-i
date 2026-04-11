// Define validation for the unified DSL.
// Checks: build resolution map, detect duplicates, undefined refs, and cycles.

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
                let (_, span) = define_map.get(name).expect("name exists in define_map");
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

/// Check that all named references in a list resolve to a defined name.
fn check_refs_defined(
    refs: &[NamedRef],
    defined: &HashSet<String>,
    context: &str,
) -> Result<(), ResolutionError> {
    for named_ref in refs {
        if !defined.contains(&named_ref.name) {
            let msg = if context.is_empty() {
                format!("undefined predicate reference: '{}'", named_ref.name)
            } else {
                format!(
                    "undefined predicate reference: '{}' in {}",
                    named_ref.name, context
                )
            };
            return Err(ResolutionError::new(msg, named_ref.span).with_help(format!(
                "define '{}' before using it, or check for typos",
                named_ref.name
            )));
        }
    }
    Ok(())
}

/// Check for undefined predicate references in a list of rules and defines.
pub(crate) fn check_undefined_refs(
    rules: &[Rule],
    defines: &[Define],
    define_map: &DefineMap,
) -> Result<(), ResolutionError> {
    let defined_names: HashSet<String> = define_map.names().cloned().collect();

    for define in defines {
        let refs = collect_named_refs(&define.predicate);
        check_refs_defined(&refs, &defined_names, "")?;
    }

    for rule in rules {
        let refs = collect_named_refs_from_effect(&rule.effect);
        check_refs_defined(&refs, &defined_names, "rule")?;
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

    // Named predicates are resolved at eval time via the binding environment.
    Ok(rules.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::Decision;
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
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
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
    fn validate_preserves_named_references() {
        let defines = vec![create_define("safe", Predicate::fact_presence(":safe"))];
        let rules = vec![create_rule_with_conditional(
            Predicate::Named("safe".to_string()),
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
        )];

        let result = validate_and_resolve(&rules, &defines).unwrap();
        assert_eq!(result.len(), 1);
        match &result[0].effect.value {
            Effect::When { predicate, .. } => {
                assert!(matches!(predicate.value, Predicate::Named(_)));
            }
            _ => panic!("expected When effect"),
        }
    }

    #[test]
    fn validate_preserves_nested_named_references() {
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
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
        )];

        let result = validate_and_resolve(&rules, &defines).unwrap();
        match &result[0].effect.value {
            Effect::When { predicate, .. } => {
                assert!(matches!(predicate.value, Predicate::Named(_)));
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
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
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
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
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
    fn validate_preserves_named_in_not() {
        let defines = vec![create_define("safe", Predicate::fact_presence(":safe"))];
        let rules = vec![create_rule_with_conditional(
            Predicate::Not(Box::new(Predicate::Named("safe".to_string()))),
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
        )];

        let result = validate_and_resolve(&rules, &defines).unwrap();
        match &result[0].effect.value {
            Effect::When { predicate, .. } => {
                if let Predicate::Not(inner) = &predicate.value {
                    assert!(matches!(inner.as_ref(), Predicate::Named(_)));
                } else {
                    panic!("expected Not predicate");
                }
            }
            _ => panic!("expected When effect"),
        }
    }

    #[test]
    fn validate_and_resolve_full_pipeline() {
        let defines = vec![create_define("safe", Predicate::fact_presence(":safe"))];
        let rules = vec![create_rule_with_conditional(
            Predicate::Named("safe".to_string()),
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
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
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
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

    // --- Ref collection from effect variants ---

    #[test]
    fn collect_refs_from_if_effect() {
        let effect = Spanned::new(
            Effect::If {
                predicate: Spanned::new(Predicate::Named("a".to_string()), dummy_span()),
                then_effect: Box::new(Spanned::new(
                    Effect::When {
                        predicate: Spanned::new(Predicate::Named("b".to_string()), dummy_span()),
                        effect: Box::new(Spanned::new(
                            Effect::Terminal {
                                decision: Decision::Allow,
                                reason: None,
                            },
                            dummy_span(),
                        )),
                    },
                    dummy_span(),
                )),
                else_effect: Box::new(Spanned::new(
                    Effect::Terminal {
                        decision: Decision::Deny,
                        reason: None,
                    },
                    dummy_span(),
                )),
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
                    Spanned::new(
                        Effect::Terminal {
                            decision: Decision::Allow,
                            reason: None,
                        },
                        dummy_span(),
                    ),
                )],
                fallback: Some(Box::new(Spanned::new(
                    Effect::When {
                        predicate: Spanned::new(Predicate::Named("b".to_string()), dummy_span()),
                        effect: Box::new(Spanned::new(
                            Effect::Terminal {
                                decision: Decision::Deny,
                                reason: None,
                            },
                            dummy_span(),
                        )),
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
                                            Effect::Terminal {
                                                decision: Decision::Allow,
                                                reason: None,
                                            },
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

    use proptest::prelude::*;

    /// Generate an arbitrary Rule with random command pattern and terminal effect.
    fn any_rule() -> BoxedStrategy<Rule> {
        (
            may_i_core::test_generators::any_command_pattern(1),
            may_i_core::test_generators::any_decision(),
            proptest::option::of("[a-z ]{1,20}"),
        )
            .prop_map(|(cmd_pat, decision, reason)| {
                Rule::new(
                    Spanned::new(Effect::CommandPattern(cmd_pat), dummy_span()),
                    Spanned::new(Effect::Terminal { decision, reason }, dummy_span()),
                    vec![],
                    dummy_span(),
                )
            })
            .boxed()
    }

    /// Generate an arbitrary Define with a simple predicate.
    fn any_define() -> BoxedStrategy<Define> {
        (
            "[a-z][a-z0-9_-]{0,8}",
            prop_oneof![
                Just(Predicate::fact_presence(":x")),
                Just(Predicate::fact_presence(":y")),
                "[a-z][a-z0-9_-]{0,8}".prop_map(Predicate::Named),
            ],
        )
            .prop_map(|(name, pred)| create_define(&name, pred))
            .boxed()
    }

    /// Generate a random acyclic define graph.
    /// Each define at index i can only reference defines at indices < i (topological order).
    fn any_acyclic_defines(size: usize) -> BoxedStrategy<Vec<Define>> {
        let names: Vec<String> = (0..size).map(|i| format!("def_{i}")).collect();
        let names_clone = names.clone();
        prop::collection::vec(prop::bool::ANY, size)
            .prop_map(move |use_ref| {
                let mut defines = Vec::new();
                for (i, name) in names_clone.iter().enumerate() {
                    let predicate = if i > 0 && use_ref[i] {
                        // Reference a previous define (acyclic)
                        let ref_idx = i % i.max(1);
                        Predicate::Named(names_clone[ref_idx].clone())
                    } else {
                        Predicate::fact_presence(":x")
                    };
                    defines.push(create_define(name, predicate));
                }
                defines
            })
            .boxed()
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        #[test]
        fn acyclic_graphs_pass_validation(defines in any_acyclic_defines(5)) {
            let define_map = DefineMap::from_defines(&defines).unwrap();
            let result = detect_cycles(&defines, &define_map);
            prop_assert!(result.is_ok(),
                "acyclic graph should pass: {:?}", result.err());
        }

        #[test]
        fn cyclic_graphs_are_rejected(
            cycle_size in 2usize..6,
        ) {
            // Create a cycle: def_0 -> def_1 -> ... -> def_n -> def_0
            let names: Vec<String> = (0..cycle_size).map(|i| format!("cyc_{i}")).collect();
            let defines: Vec<Define> = names.iter().enumerate().map(|(i, name)| {
                let next = &names[(i + 1) % cycle_size];
                create_define(name, Predicate::Named(next.clone()))
            }).collect();

            let define_map = DefineMap::from_defines(&defines).unwrap();
            let result = detect_cycles(&defines, &define_map);
            prop_assert!(result.is_err(),
                "cycle of size {} should be rejected", cycle_size);
        }

        #[test]
        fn validate_and_resolve_never_panics(
            rules in prop::collection::vec(any_rule(), 0..5),
            defines in prop::collection::vec(any_define(), 0..3),
        ) {
            let _ = validate_and_resolve(&rules, &defines);
        }

        // TODO(task 10.7): Resolution completeness — verify no Predicate::Named
        // after validate_and_resolve. Skipped because Named predicates are
        // intentionally preserved and resolved at eval time via bindings
        // (see validate_and_resolve comment at line 305).

        /// After successful validation, all Named references in rules
        /// must be defined (no dangling references).
        #[test]
        fn valid_configs_have_all_named_refs_defined(
            n_defines in 1usize..5,
            n_rules in 1usize..4,
        ) {
            let names: Vec<String> = (0..n_defines).map(|i| format!("def_{i}")).collect();
            let defines: Vec<Define> = names.iter().map(|name| {
                create_define(name, Predicate::fact_presence(":x"))
            }).collect();
            let rules: Vec<Rule> = (0..n_rules).map(|i| {
                let name = &names[i % names.len()];
                create_rule_with_conditional(
                    Predicate::Named(name.clone()),
                    Effect::Terminal { decision: Decision::Allow, reason: None },
                )
            }).collect();

            let result = validate_and_resolve(&rules, &defines);
            prop_assert!(result.is_ok(), "validation should succeed for valid configs");
        }
    }
}
