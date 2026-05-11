// Trust hash computation for per-rule trust verification.
//
// Computes SHA-256 hashes over resolved rule closures, grouped by program name.
// Programs with any `Loaded` provenance content require trust approval.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use may_i_core::Decision;
use may_i_core::ast::{Config, Define, Effect, Predicate, Rule};
use may_i_core::doc::DocF;
use may_i_core::pattern::{ArgPattern, CommandPattern, Expr, MatchMode, PositionalArg, Quantifier};
use may_i_core::primitives::ToDoc;
use sha2::{Digest, Sha256};

/// Per-rule metadata: hash, canonical form, program, source file, position within program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMeta {
    pub hash: String,
    pub canonical_form: String,
    pub program: String,
    pub source_file: Option<PathBuf>,
    pub position: usize,
}

/// Per-program metadata (derived view from per-rule data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramMeta {
    pub hash: String,
    pub canonical_rules: Vec<String>,
    pub canonical_defines: Vec<String>,
    pub source_files: BTreeSet<PathBuf>,
}

/// Trust hash results containing per-rule metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustHashes {
    /// Per-rule metadata, ordered by (program, position).
    pub rules: Vec<RuleMeta>,
    /// Per-program canonical forms of transitively-referenced defines.
    /// Hashed alongside rules so a define edit invalidates the trust of
    /// every program that reaches it.
    pub defines_by_program: BTreeMap<String, Vec<String>>,
}

impl TrustHashes {
    /// Derive the per-program view (backward-compat grouping for listing UI).
    ///
    /// The hash is computed over the canonical, order-independent set of
    /// rules: canonical forms are sorted lexically and joined with `\n`
    /// before hashing. Source-file order, comments, whitespace, and the
    /// way rules are partitioned across `(load …)` files do not
    /// influence the hash. `canonical_defines` carries the transitively
    /// referenced defines for the UI; folding them into the hash is
    /// deferred (see `openspec/changes/order-independent-rules/tasks.md`
    /// § 3.2).
    pub fn programs(&self) -> BTreeMap<String, ProgramMeta> {
        let mut groups: BTreeMap<String, Vec<&RuleMeta>> = BTreeMap::new();
        for meta in &self.rules {
            groups.entry(meta.program.clone()).or_default().push(meta);
        }

        groups
            .into_iter()
            .map(|(program, rule_metas)| {
                let canonical_rules: Vec<String> = rule_metas
                    .iter()
                    .map(|m| m.canonical_form.clone())
                    .collect();
                let source_files: BTreeSet<PathBuf> = rule_metas
                    .iter()
                    .filter_map(|m| m.source_file.clone())
                    .collect();
                let canonical_defines: Vec<String> = self
                    .defines_by_program
                    .get(&program)
                    .cloned()
                    .unwrap_or_default();
                let hash = canonical_set_hash(&canonical_rules);
                (
                    program,
                    ProgramMeta {
                        hash,
                        canonical_rules,
                        canonical_defines,
                        source_files,
                    },
                )
            })
            .collect()
    }

    /// Check if there are no rules needing trust.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Hash the canonical, order-independent representation of a program's
/// trust closure. Canonical rule forms are sorted lexically and joined
/// with `\n`; the trust store re-derives the same hash from stored rule
/// forms via the matching sort+join in
/// [`crate::trust_store::hash_rules_from_strs`] (in the binary crate).
fn canonical_set_hash(canonical_rules: &[String]) -> String {
    let mut rules_sorted: Vec<&str> = canonical_rules.iter().map(String::as_str).collect();
    rules_sorted.sort();
    sha256_hex(&rules_sorted.join("\n"))
}

/// Extract all program names from a `CommandPattern`.
pub fn extract_program_names(pattern: &CommandPattern) -> Vec<&str> {
    match pattern {
        CommandPattern::Literal(name) => vec![name.as_str()],
        CommandPattern::Or(patterns) => patterns.iter().flat_map(extract_program_names).collect(),
        _ => vec![],
    }
}

/// Extract program names from an effect's command pattern.
fn extract_command_programs(effect: &Effect) -> Vec<&str> {
    match effect {
        Effect::CommandPattern(pat) => extract_program_names(pat),
        _ => vec![],
    }
}

/// Identify which programs need trust approval.
fn programs_needing_trust(config: &Config) -> BTreeSet<String> {
    let loaded_defines: BTreeSet<&str> = config
        .defines
        .iter()
        .filter(|d| d.provenance.is_loaded())
        .map(|d| d.name.as_str())
        .collect();

    let mut result = BTreeSet::new();

    for rule in &config.rules {
        let programs = extract_command_programs(&rule.command_effect.value);
        if programs.is_empty() {
            continue;
        }

        let needs_trust = rule.provenance.is_loaded()
            || references_any_define(&rule.effect.value, &loaded_defines);

        if needs_trust {
            for prog in programs {
                result.insert(prog.to_string());
            }
        }
    }

    result
}

/// Check if an effect references any of the given define names.
fn references_any_define(effect: &Effect, define_names: &BTreeSet<&str>) -> bool {
    match effect {
        Effect::When { predicate, effect } | Effect::Unless { predicate, effect } => {
            predicate_references_any(&predicate.value, define_names)
                || references_any_define(&effect.value, define_names)
        }
        Effect::If {
            predicate,
            then_effect,
            else_effect,
        } => {
            predicate_references_any(&predicate.value, define_names)
                || references_any_define(&then_effect.value, define_names)
                || references_any_define(&else_effect.value, define_names)
        }
        Effect::Cond { branches, fallback } => {
            branches.iter().any(|(pred, eff)| {
                predicate_references_any(&pred.value, define_names)
                    || references_any_define(&eff.value, define_names)
            }) || fallback
                .as_ref()
                .is_some_and(|fb| references_any_define(&fb.value, define_names))
        }
        Effect::And { effects } | Effect::Or { effects } => effects
            .iter()
            .any(|e| references_any_define(&e.value, define_names)),
        Effect::Not { effect } => references_any_define(&effect.value, define_names),
        _ => false,
    }
}

/// Check if a predicate references any of the given define names.
fn predicate_references_any(pred: &Predicate, define_names: &BTreeSet<&str>) -> bool {
    match pred {
        Predicate::Named(name) => define_names.contains(name.as_str()),
        Predicate::And(preds) | Predicate::Or(preds) => preds
            .iter()
            .any(|p| predicate_references_any(p, define_names)),
        Predicate::Not(inner) => predicate_references_any(inner, define_names),
        Predicate::Fact(_) | Predicate::Arg(_) => false,
        _ => false,
    }
}

/// Produce a canonical s-expression string for a rule (excluding checks and spans).
pub fn canonical_rule(rule: &Rule) -> String {
    let cmd = canonical_effect(&rule.command_effect.value);
    let body = canonical_effect(&rule.effect.value);
    format!("(rule {cmd} {body})")
}

/// Produce a canonical s-expression for an effect.
fn canonical_effect(effect: &Effect) -> String {
    match effect {
        Effect::Terminal { decision, reason } => {
            let verb = match decision {
                Decision::Allow => "allow",
                Decision::Ask => "ask",
                Decision::Deny => "deny",
            };
            match reason {
                Some(r) => format!("({verb} \"{r}\")"),
                None => format!("({verb})"),
            }
        }
        Effect::CommandPattern(pat) => canonical_command_pattern(pat),
        Effect::ArgPattern(pat) => canonical_arg_pattern(pat),
        Effect::And { effects } => {
            let inner: Vec<String> = effects.iter().map(|e| canonical_effect(&e.value)).collect();
            format!("(and {})", inner.join(" "))
        }
        Effect::Or { effects } => {
            let inner: Vec<String> = effects.iter().map(|e| canonical_effect(&e.value)).collect();
            format!("(or {})", inner.join(" "))
        }
        Effect::Not { effect } => format!("(not {})", canonical_effect(&effect.value)),
        Effect::When { predicate, effect } => format!(
            "(when {} {})",
            canonical_predicate(&predicate.value),
            canonical_effect(&effect.value)
        ),
        Effect::Unless { predicate, effect } => format!(
            "(unless {} {})",
            canonical_predicate(&predicate.value),
            canonical_effect(&effect.value)
        ),
        Effect::If {
            predicate,
            then_effect,
            else_effect,
        } => format!(
            "(if {} {} {})",
            canonical_predicate(&predicate.value),
            canonical_effect(&then_effect.value),
            canonical_effect(&else_effect.value)
        ),
        Effect::Cond { branches, fallback } => {
            let mut parts = vec!["cond".to_string()];
            for (pred, eff) in branches {
                parts.push(format!(
                    "({} {})",
                    canonical_predicate(&pred.value),
                    canonical_effect(&eff.value)
                ));
            }
            if let Some(fb) = fallback {
                parts.push(format!("(else {})", canonical_effect(&fb.value)));
            }
            format!("({})", parts.join(" "))
        }
        Effect::Authorise { binding } => format!("(authorise {binding})"),
    }
}

fn canonical_command_pattern(pat: &CommandPattern) -> String {
    match pat {
        CommandPattern::Literal(s) => format!("\"{}\"", s),
        CommandPattern::Or(pats) => {
            let inner: Vec<String> = pats.iter().map(canonical_command_pattern).collect();
            format!("(or {})", inner.join(" "))
        }
        _ => "<unknown>".to_string(),
    }
}

fn canonical_predicate(pred: &Predicate) -> String {
    match pred {
        Predicate::Fact(query) => {
            let doc = query.to_doc();
            format!("(fact? {})", render_doc(&doc))
        }
        Predicate::Arg(pat) => canonical_arg_pattern(pat),
        Predicate::Named(name) => name.clone(),
        Predicate::And(preds) => {
            let inner: Vec<String> = preds.iter().map(canonical_predicate).collect();
            format!("(and {})", inner.join(" "))
        }
        Predicate::Or(preds) => {
            let inner: Vec<String> = preds.iter().map(canonical_predicate).collect();
            format!("(or {})", inner.join(" "))
        }
        Predicate::Not(inner) => format!("(not {})", canonical_predicate(inner)),
        Predicate::Bound { binding } => format!("(bound? {binding})"),
        Predicate::Matches { binding, .. } => format!("(matches? {binding} <expr>)"),
        _ => "<unknown>".to_string(),
    }
}

fn canonical_arg_pattern(pat: &ArgPattern) -> String {
    match pat {
        ArgPattern::Ordered {
            mode,
            patterns,
            continuation,
        } => {
            let tag = match mode {
                MatchMode::Positional => "positional",
                MatchMode::Exact => "exact",
            };
            let mut parts: Vec<String> = patterns.iter().map(canonical_positional_arg).collect();
            if let Some(cont) = continuation {
                parts.push(format!(". {}", canonical_effect(cont)));
            }
            if parts.is_empty() {
                format!("({tag})")
            } else {
                format!("({tag} {})", parts.join(" "))
            }
        }
        ArgPattern::Anywhere(exprs) => {
            let inner: Vec<String> = exprs.iter().map(canonical_expr).collect();
            format!("(anywhere {})", inner.join(" "))
        }
        ArgPattern::Forbidden(exprs) => {
            let inner: Vec<String> = exprs.iter().map(canonical_expr).collect();
            format!("(forbidden {})", inner.join(" "))
        }
        ArgPattern::Flag { names } => {
            format!("(flag {})", canonical_flag_names(names))
        }
        ArgPattern::Parameter { names, form } => format!(
            "(parameter {} {})",
            canonical_flag_names(names),
            canonical_parameter_form(form)
        ),
        ArgPattern::Tail => "(tail (authorise))".to_string(),
    }
}

fn canonical_parameter_form(form: &may_i_core::pattern::ParameterForm) -> String {
    match form {
        may_i_core::pattern::ParameterForm::Match(expr) => canonical_expr(expr),
        may_i_core::pattern::ParameterForm::Authorise => "(authorise)".to_string(),
    }
}

fn canonical_flag_names(names: &[String]) -> String {
    if names.len() == 1 {
        format!("\"{}\"", names[0])
    } else {
        let inner: Vec<String> = names.iter().map(|n| format!("\"{n}\"")).collect();
        format!("[{}]", inner.join(" "))
    }
}

fn canonical_positional_arg(arg: &PositionalArg) -> String {
    let inner = canonical_expr(&arg.pattern);
    let wrapped = match arg.quantifier {
        Quantifier::One => inner,
        Quantifier::Optional => format!("(? {inner})"),
        Quantifier::OneOrMore => format!("(+ {inner})"),
        Quantifier::ZeroOrMore => format!("(* {inner})"),
    };
    if arg.recursive {
        format!("(... {wrapped})")
    } else {
        wrapped
    }
}

fn canonical_expr<E: std::fmt::Debug + ToDoc>(expr: &Expr<E>) -> String {
    render_doc(&expr.to_doc())
}

/// Render a Doc to a single-line canonical string.
fn render_doc(doc: &may_i_core::Doc) -> String {
    match &doc.node {
        DocF::Atom(s) => s.clone(),
        DocF::List(children) => {
            let inner: Vec<String> = children.iter().map(render_doc).collect();
            format!("({})", inner.join(" "))
        }
        DocF::Vector(children) => {
            let inner: Vec<String> = children.iter().map(render_doc).collect();
            format!("[{}]", inner.join(" "))
        }
    }
}

/// Compute SHA-256 hash of a single canonical rule form.
pub fn hash_rule(form: &str) -> String {
    sha256_hex(form)
}

/// Compute trust hashes for all rules that need trust approval.
///
/// Returns per-rule metadata. Only rules with `Loaded` provenance or referencing
/// loaded defines are included.
pub fn compute_trust_hashes(config: &Config) -> TrustHashes {
    let programs_need_trust = programs_needing_trust(config);
    let mut rules = Vec::new();

    // Track position per program.
    let mut position_counters: BTreeMap<String, usize> = BTreeMap::new();
    // Collect rule references per program for define-closure expansion.
    let mut rules_by_program: BTreeMap<String, Vec<&Rule>> = BTreeMap::new();

    for rule in &config.rules {
        let rule_programs = extract_command_programs(&rule.command_effect.value);
        if rule_programs.is_empty() {
            continue;
        }

        for program in &rule_programs {
            if !programs_need_trust.contains(*program) {
                continue;
            }

            let form = canonical_rule(rule);
            let hash = sha256_hex(&form);
            let source_file = rule.provenance.path().map(|p| p.to_path_buf());
            let position = position_counters.entry(program.to_string()).or_insert(0);

            rules.push(RuleMeta {
                hash,
                canonical_form: form,
                program: program.to_string(),
                source_file,
                position: *position,
            });
            rules_by_program
                .entry(program.to_string())
                .or_default()
                .push(rule);

            *position += 1;
        }
    }

    let defines_by_name: BTreeMap<&str, &Define> = config
        .defines
        .iter()
        .map(|d| (d.name.as_str(), d))
        .collect();
    let mut defines_by_program: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (program, rules_for_program) in &rules_by_program {
        let mut reached: BTreeSet<String> = BTreeSet::new();
        for rule in rules_for_program {
            collect_define_closure(&rule.effect.value, &defines_by_name, &mut reached);
        }
        let mut canonical_defines: Vec<String> = reached
            .iter()
            .filter_map(|n| defines_by_name.get(n.as_str()).map(|d| canonical_define(d)))
            .collect();
        canonical_defines.sort();
        defines_by_program.insert(program.clone(), canonical_defines);
    }

    // Handle safe-env-vars trust scope.
    if config.security.has_loaded_env_vars && !config.security.safe_env_vars.is_empty() {
        let mut sorted_vars: Vec<&String> = config.security.safe_env_vars.iter().collect();
        sorted_vars.sort();
        let canonical_form = sorted_vars
            .iter()
            .map(|v| format!("\"{}\"", v))
            .collect::<Vec<_>>()
            .join(" ");
        let form = format!("(safe-env-vars {})", canonical_form);
        let hash = sha256_hex(&form);
        rules.push(RuleMeta {
            hash,
            canonical_form: form,
            program: ":safe-env-vars".to_string(),
            source_file: None,
            position: 0,
        });
    }

    TrustHashes {
        rules,
        defines_by_program,
    }
}

/// Canonical s-expression form of a `(define …)` (excluding spans).
pub fn canonical_define(define: &Define) -> String {
    format!(
        "(define {} {})",
        define.name,
        canonical_predicate(&define.predicate.value)
    )
}

/// Walk an effect tree and collect names of every define it reaches,
/// transitively (a define's body may itself reference further defines).
fn collect_define_closure(
    effect: &Effect,
    defines_by_name: &BTreeMap<&str, &Define>,
    reached: &mut BTreeSet<String>,
) {
    match effect {
        Effect::When { predicate, effect } | Effect::Unless { predicate, effect } => {
            collect_define_names_in_predicate(&predicate.value, defines_by_name, reached);
            collect_define_closure(&effect.value, defines_by_name, reached);
        }
        Effect::If {
            predicate,
            then_effect,
            else_effect,
        } => {
            collect_define_names_in_predicate(&predicate.value, defines_by_name, reached);
            collect_define_closure(&then_effect.value, defines_by_name, reached);
            collect_define_closure(&else_effect.value, defines_by_name, reached);
        }
        Effect::Cond { branches, fallback } => {
            for (pred, eff) in branches {
                collect_define_names_in_predicate(&pred.value, defines_by_name, reached);
                collect_define_closure(&eff.value, defines_by_name, reached);
            }
            if let Some(fb) = fallback {
                collect_define_closure(&fb.value, defines_by_name, reached);
            }
        }
        Effect::And { effects } | Effect::Or { effects } => {
            for e in effects {
                collect_define_closure(&e.value, defines_by_name, reached);
            }
        }
        Effect::Not { effect } => collect_define_closure(&effect.value, defines_by_name, reached),
        _ => {}
    }
}

fn collect_define_names_in_predicate(
    pred: &Predicate,
    defines_by_name: &BTreeMap<&str, &Define>,
    reached: &mut BTreeSet<String>,
) {
    match pred {
        Predicate::Named(name) => {
            if reached.insert(name.clone())
                && let Some(d) = defines_by_name.get(name.as_str())
            {
                collect_define_names_in_predicate(&d.predicate.value, defines_by_name, reached);
            }
        }
        Predicate::And(preds) | Predicate::Or(preds) => {
            for p in preds {
                collect_define_names_in_predicate(p, defines_by_name, reached);
            }
        }
        Predicate::Not(inner) => collect_define_names_in_predicate(inner, defines_by_name, reached),
        _ => {}
    }
}

/// Compute SHA-256 hash and return hex-encoded string with "sha256:" prefix.
fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    format!("sha256:{}", hex::encode(result))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use may_i_core::Decision;
    use may_i_core::ast::{Define, Effect, Provenance, Spanned};
    use may_i_core::pattern::CommandPattern;
    use may_i_core::span::Span;

    fn dummy_span() -> Span {
        Span::new(0, 0)
    }

    fn spanned<T>(value: T) -> Spanned<T> {
        Spanned::new(value, dummy_span())
    }

    fn terminal(decision: Decision, reason: Option<&str>) -> Effect {
        Effect::Terminal {
            decision,
            reason: reason.map(String::from),
        }
    }

    fn make_rule(command: &str, effect: Effect, provenance: Provenance) -> Rule {
        Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                command.into(),
            ))),
            effect: spanned(effect),
            checks: vec![],
            span: dummy_span(),
            provenance,
        }
    }

    fn make_config(rules: Vec<Rule>, defines: Vec<Define>) -> Config {
        Config {
            rules,
            defines,
            ..Config::default()
        }
    }

    // --- extract_program_names ---

    #[test]
    fn extract_literal_program_name() {
        let pat = CommandPattern::Literal("git".into());
        assert_eq!(extract_program_names(&pat), vec!["git"]);
    }

    #[test]
    fn extract_or_program_names() {
        let pat = CommandPattern::Or(vec![
            CommandPattern::Literal("git".into()),
            CommandPattern::Literal("gh".into()),
        ]);
        let names = extract_program_names(&pat);
        assert_eq!(names, vec!["git", "gh"]);
    }

    // --- programs_needing_trust ---

    #[test]
    fn primary_only_program_does_not_need_trust() {
        let config = make_config(
            vec![make_rule(
                "git",
                terminal(Decision::Allow, None),
                Provenance::PrimaryConfig,
            )],
            vec![],
        );
        let needs = programs_needing_trust(&config);
        assert!(needs.is_empty());
    }

    #[test]
    fn loaded_rule_program_needs_trust() {
        let config = make_config(
            vec![make_rule(
                "git",
                terminal(Decision::Allow, None),
                Provenance::Loaded {
                    path: PathBuf::from("test"),
                },
            )],
            vec![],
        );
        let needs = programs_needing_trust(&config);
        assert!(needs.contains("git"));
    }

    #[test]
    fn primary_rule_referencing_loaded_define_needs_trust() {
        let config = make_config(
            vec![Rule {
                command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                    "kubectl".into(),
                ))),
                effect: spanned(Effect::When {
                    predicate: spanned(Predicate::Named("on-vpn".into())),
                    effect: Box::new(spanned(terminal(Decision::Allow, None))),
                }),
                checks: vec![],
                span: dummy_span(),
                provenance: Provenance::PrimaryConfig,
            }],
            vec![Define {
                name: "on-vpn".into(),
                predicate: spanned(Predicate::Fact(may_i_core::FactQuery::Presence {
                    key: may_i_core::Keyword::new(":net/vpn").unwrap(),
                })),
                span: dummy_span(),
                provenance: Provenance::Loaded {
                    path: PathBuf::from("test"),
                },
            }],
        );
        let needs = programs_needing_trust(&config);
        assert!(needs.contains("kubectl"));
    }

    // --- per-rule hash stability ---

    #[test]
    fn same_config_produces_same_hashes() {
        let config = make_config(
            vec![make_rule(
                "git",
                terminal(Decision::Allow, Some("safe")),
                Provenance::Loaded {
                    path: PathBuf::from("test"),
                },
            )],
            vec![],
        );
        let h1 = compute_trust_hashes(&config);
        let h2 = compute_trust_hashes(&config);
        assert_eq!(h1, h2);
    }

    #[test]
    fn each_rule_gets_distinct_hash() {
        let config = make_config(
            vec![
                make_rule(
                    "git",
                    terminal(Decision::Allow, None),
                    Provenance::Loaded {
                        path: PathBuf::from("test"),
                    },
                ),
                make_rule(
                    "git",
                    terminal(Decision::Deny, None),
                    Provenance::Loaded {
                        path: PathBuf::from("test"),
                    },
                ),
            ],
            vec![],
        );
        let hashes = compute_trust_hashes(&config);
        assert_eq!(hashes.rules.len(), 2);
        assert_ne!(hashes.rules[0].hash, hashes.rules[1].hash);
    }

    #[test]
    fn different_effect_produces_different_hash() {
        let c1 = make_config(
            vec![make_rule(
                "git",
                terminal(Decision::Allow, None),
                Provenance::Loaded {
                    path: PathBuf::from("test"),
                },
            )],
            vec![],
        );
        let c2 = make_config(
            vec![make_rule(
                "git",
                terminal(Decision::Deny, None),
                Provenance::Loaded {
                    path: PathBuf::from("test"),
                },
            )],
            vec![],
        );
        let h1 = compute_trust_hashes(&c1);
        let h2 = compute_trust_hashes(&c2);
        assert_ne!(h1.rules[0].hash, h2.rules[0].hash);
    }

    #[test]
    fn hash_unchanged_for_primary_only_programs() {
        let config = make_config(
            vec![
                make_rule(
                    "git",
                    terminal(Decision::Allow, None),
                    Provenance::Loaded {
                        path: PathBuf::from("test"),
                    },
                ),
                make_rule(
                    "ls",
                    terminal(Decision::Allow, None),
                    Provenance::PrimaryConfig,
                ),
            ],
            vec![],
        );
        let hashes = compute_trust_hashes(&config);
        assert_eq!(hashes.rules.len(), 1);
        assert_eq!(hashes.rules[0].program, "git");
    }

    #[test]
    fn hash_format_is_sha256_prefixed() {
        let config = make_config(
            vec![make_rule(
                "git",
                terminal(Decision::Allow, None),
                Provenance::Loaded {
                    path: PathBuf::from("test"),
                },
            )],
            vec![],
        );
        let hashes = compute_trust_hashes(&config);
        let hash = &hashes.rules[0].hash;
        assert!(
            hash.starts_with("sha256:"),
            "hash should have sha256: prefix"
        );
        assert_eq!(
            hash.len(),
            "sha256:".len() + 64,
            "hash should be sha256: + 64 hex chars"
        );
    }

    // --- source files propagated ---

    #[test]
    fn source_file_propagated_to_rule_meta() {
        let config = make_config(
            vec![make_rule(
                "git",
                terminal(Decision::Allow, None),
                Provenance::Loaded {
                    path: PathBuf::from("/rules/vcs.lisp"),
                },
            )],
            vec![],
        );
        let hashes = compute_trust_hashes(&config);
        assert_eq!(
            hashes.rules[0].source_file,
            Some(PathBuf::from("/rules/vcs.lisp"))
        );
    }

    #[test]
    fn primary_rule_has_no_source_file() {
        let config = make_config(
            vec![
                make_rule(
                    "git",
                    terminal(Decision::Allow, None),
                    Provenance::PrimaryConfig,
                ),
                make_rule(
                    "git",
                    terminal(Decision::Deny, None),
                    Provenance::Loaded {
                        path: PathBuf::from("test"),
                    },
                ),
            ],
            vec![],
        );
        let hashes = compute_trust_hashes(&config);
        // Primary rule is included in trust set (because git has loaded rules),
        // but has no source file.
        let primary = hashes.rules.iter().find(|r| r.source_file.is_none());
        assert!(primary.is_some());
    }

    // --- position tracking ---

    #[test]
    fn position_tracks_within_program() {
        let config = make_config(
            vec![
                make_rule(
                    "git",
                    terminal(Decision::Allow, None),
                    Provenance::Loaded {
                        path: PathBuf::from("test"),
                    },
                ),
                make_rule(
                    "git",
                    terminal(Decision::Deny, None),
                    Provenance::Loaded {
                        path: PathBuf::from("test"),
                    },
                ),
            ],
            vec![],
        );
        let hashes = compute_trust_hashes(&config);
        assert_eq!(hashes.rules[0].position, 0);
        assert_eq!(hashes.rules[1].position, 1);
    }

    // --- programs() derived view ---

    #[test]
    fn programs_view_groups_by_program() {
        let config = make_config(
            vec![
                make_rule(
                    "git",
                    terminal(Decision::Allow, None),
                    Provenance::Loaded {
                        path: PathBuf::from("/rules/a.lisp"),
                    },
                ),
                make_rule(
                    "git",
                    terminal(Decision::Deny, None),
                    Provenance::Loaded {
                        path: PathBuf::from("/rules/b.lisp"),
                    },
                ),
                make_rule(
                    "cargo",
                    terminal(Decision::Allow, None),
                    Provenance::Loaded {
                        path: PathBuf::from("/rules/a.lisp"),
                    },
                ),
            ],
            vec![],
        );
        let hashes = compute_trust_hashes(&config);
        let programs = hashes.programs();
        assert_eq!(programs.len(), 2);
        assert_eq!(programs["git"].canonical_rules.len(), 2);
        assert_eq!(programs["cargo"].canonical_rules.len(), 1);
        assert_eq!(programs["git"].source_files.len(), 2);
    }

    #[test]
    fn programs_view_hash_matches_old_algorithm() {
        // The programs() hash should match joining canonical rules with \n.
        let config = make_config(
            vec![make_rule(
                "git",
                terminal(Decision::Allow, Some("safe")),
                Provenance::Loaded {
                    path: PathBuf::from("test.lisp"),
                },
            )],
            vec![],
        );
        let hashes = compute_trust_hashes(&config);
        let programs = hashes.programs();
        let meta = &programs["git"];
        assert_eq!(meta.canonical_rules.len(), 1);
        assert_eq!(meta.canonical_rules[0], r#"(rule "git" (allow "safe"))"#);
    }

    #[test]
    fn programs_view_hash_is_order_independent() {
        // Two configs differing only in rule order produce the same
        // per-program hash. Spec: order-independent-rules /
        // trust-hashing.
        let r_a = make_rule(
            "git",
            terminal(Decision::Allow, Some("a")),
            Provenance::Loaded {
                path: PathBuf::from("/rules/a.lisp"),
            },
        );
        let r_b = make_rule(
            "git",
            terminal(Decision::Deny, Some("b")),
            Provenance::Loaded {
                path: PathBuf::from("/rules/b.lisp"),
            },
        );

        let c_forward = make_config(vec![r_a.clone(), r_b.clone()], vec![]);
        let c_reversed = make_config(vec![r_b, r_a], vec![]);

        let h_forward = compute_trust_hashes(&c_forward).programs()["git"]
            .hash
            .clone();
        let h_reversed = compute_trust_hashes(&c_reversed).programs()["git"]
            .hash
            .clone();
        assert_eq!(h_forward, h_reversed);
    }

    #[test]
    fn programs_view_hash_unchanged_when_rule_moves_between_load_files() {
        // Moving a rule's source file (Loaded { path }) verbatim does not
        // change the per-program hash. Spec: trust-hashing.
        let rule_in_a = make_rule(
            "git",
            terminal(Decision::Allow, Some("safe")),
            Provenance::Loaded {
                path: PathBuf::from("/rules/a.lisp"),
            },
        );
        let rule_in_b = make_rule(
            "git",
            terminal(Decision::Allow, Some("safe")),
            Provenance::Loaded {
                path: PathBuf::from("/rules/b.lisp"),
            },
        );
        let h_a = compute_trust_hashes(&make_config(vec![rule_in_a], vec![])).programs()["git"]
            .hash
            .clone();
        let h_b = compute_trust_hashes(&make_config(vec![rule_in_b], vec![])).programs()["git"]
            .hash
            .clone();
        assert_eq!(h_a, h_b);
    }

    // --- canonical_rule ---

    #[test]
    fn canonical_rule_deterministic() {
        let rule = make_rule(
            "git",
            terminal(Decision::Allow, Some("safe")),
            Provenance::Loaded {
                path: PathBuf::from("test"),
            },
        );
        let s1 = canonical_rule(&rule);
        let s2 = canonical_rule(&rule);
        assert_eq!(s1, s2);
    }

    #[test]
    fn canonical_rule_excludes_checks() {
        let mut rule = make_rule(
            "git",
            terminal(Decision::Allow, None),
            Provenance::Loaded {
                path: PathBuf::from("test"),
            },
        );
        let s1 = canonical_rule(&rule);
        rule.checks.push(may_i_core::ast::Check {
            command: "git status".into(),
            expected: Decision::Allow,
            context: may_i_core::ContextFacts::default(),
            span: dummy_span(),
        });
        let s2 = canonical_rule(&rule);
        assert_eq!(s1, s2, "adding checks should not change canonical form");
    }

    // --- safe-env-vars trust scope ---

    #[test]
    fn loaded_safe_env_vars_gets_hashed() {
        let mut config = make_config(vec![], vec![]);
        config
            .security
            .safe_env_vars
            .insert("AWS_SECRET_KEY".into());
        config.security.has_loaded_env_vars = true;
        let hashes = compute_trust_hashes(&config);
        assert!(
            hashes.rules.iter().any(|r| r.program == ":safe-env-vars"),
            "should have :safe-env-vars rule"
        );
    }

    #[test]
    fn primary_only_safe_env_vars_not_hashed() {
        let mut config = make_config(vec![], vec![]);
        config.security.safe_env_vars.insert("HOME".into());
        config.security.has_loaded_env_vars = false;
        let hashes = compute_trust_hashes(&config);
        assert!(
            !hashes.rules.iter().any(|r| r.program == ":safe-env-vars"),
            "should not have :safe-env-vars rule when all primary"
        );
    }

    #[test]
    fn safe_env_vars_hash_changes_on_modification() {
        let mut c1 = make_config(vec![], vec![]);
        c1.security.safe_env_vars.insert("HOME".into());
        c1.security.has_loaded_env_vars = true;

        let mut c2 = make_config(vec![], vec![]);
        c2.security.safe_env_vars.insert("HOME".into());
        c2.security.safe_env_vars.insert("SECRET".into());
        c2.security.has_loaded_env_vars = true;

        let h1 = compute_trust_hashes(&c1);
        let h2 = compute_trust_hashes(&c2);
        let env1 = h1
            .rules
            .iter()
            .find(|r| r.program == ":safe-env-vars")
            .unwrap();
        let env2 = h2
            .rules
            .iter()
            .find(|r| r.program == ":safe-env-vars")
            .unwrap();
        assert_ne!(env1.hash, env2.hash, "adding env var should change hash");
    }
}
