// Trust hash computation for per-rule trust verification.
//
// Computes SHA-256 hashes over resolved rule closures, grouped by program name.
// Programs with any `Loaded` provenance content require trust approval.

use std::collections::BTreeSet;
use std::path::PathBuf;

use may_i_core::Decision;
use may_i_core::ast::{Config, Define, Effect, Predicate, Rule};
use may_i_core::doc::DocF;
use may_i_core::pattern::{
    ArgPattern, CommandPattern, Expr, MatchMode, PosTerm, PosTermView, Quantifier,
};
use may_i_core::primitives::ToDoc;
use sha2::{Digest, Sha256};

/// Per-rule trust descriptor: hash, canonical form, program, source file,
/// position within program. The engine produces these as the *input* to the
/// CLI's trust-store join — it carries no approval state. Callers join with
/// [`crate::trust::store::TrustStore`] via [`crate::trust::view::build_catalog`]
/// to obtain the unified `TrustView`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustViewMeta {
    pub hash: String,
    pub canonical_form: String,
    pub program: String,
    pub source_file: Option<PathBuf>,
    pub position: usize,
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
        Effect::Authorise { binding, .. } => format!("(authorise {binding})"),
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
        Predicate::Bound { binding, .. } => format!("(bound? {binding})"),
        Predicate::Matches { binding, .. } => format!("(matches? {binding} <expr>)"),
        Predicate::Every { binding, .. } => format!("(every? {binding} <expr>)"),
        Predicate::Some { binding, .. } => format!("(some? {binding} <expr>)"),
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
            let mut parts: Vec<String> = patterns.iter().map(canonical_pos_term).collect();
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

/// Canonical s-expression for a positional term. A `Single` with
/// `Quantifier::One` is the bare pattern; other singles wrap as `(Q expr)`;
/// a group wraps its sub-sequence as `(Q elem …)`. Group-free configs render
/// exactly as before, so existing trust hashes are unchanged.
fn canonical_pos_term(term: &PosTerm) -> String {
    fn glyph(q: Quantifier) -> &'static str {
        match q {
            Quantifier::One => "",
            Quantifier::Optional => "?",
            Quantifier::OneOrMore => "+",
            Quantifier::ZeroOrMore => "*",
        }
    }
    match term.view() {
        PosTermView::Single {
            quantifier: Quantifier::One,
            pattern,
        } => canonical_expr(pattern),
        PosTermView::Single {
            quantifier,
            pattern,
        } => format!("({} {})", glyph(quantifier), canonical_expr(pattern)),
        PosTermView::Group { quantifier, seq } => {
            let inner: Vec<String> = seq.iter().map(canonical_pos_term).collect();
            format!("({} {})", glyph(quantifier), inner.join(" "))
        }
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

/// Compute per-rule trust descriptors for all rules that need trust approval.
///
/// Only rules with `Loaded` provenance or referencing loaded defines are
/// included. The returned `Vec` is the join *input* — see
/// [`crate::trust::view::build_catalog`] in the CLI crate for the join with
/// trust-store state.
pub fn compute_trust_views(config: &Config) -> Vec<TrustViewMeta> {
    let programs_need_trust = programs_needing_trust(config);
    let mut views = Vec::new();

    // Track position per program.
    let mut position_counters: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();

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

            views.push(TrustViewMeta {
                hash,
                canonical_form: form,
                program: program.to_string(),
                source_file,
                position: *position,
            });

            *position += 1;
        }
    }

    // Handle safe-env-vars trust scope. The hashed set is the union of
    // primary and loaded entries (preserving the pre-split canonical
    // form, where both parsed into one set).
    if config.security.has_loaded_env_vars
        && !(config.security.safe_env_vars.is_empty()
            && config.security.loaded_safe_env_vars.is_empty())
    {
        let mut sorted_vars: Vec<&String> = config
            .security
            .safe_env_vars
            .iter()
            .chain(config.security.loaded_safe_env_vars.iter())
            .collect();
        sorted_vars.sort();
        sorted_vars.dedup();
        let canonical_form = sorted_vars
            .iter()
            .map(|v| format!("\"{}\"", v))
            .collect::<Vec<_>>()
            .join(" ");
        let form = format!("(safe-env-vars {})", canonical_form);
        let hash = sha256_hex(&form);
        views.push(TrustViewMeta {
            hash,
            canonical_form: form,
            program: ":safe-env-vars".to_string(),
            source_file: None,
            position: 0,
        });
    }

    // `:env` capability trust scope — the ask/deny/conditional `(env …)`
    // forms (an unconditional `(env NAME (allow))` lowers to safe-env-vars
    // instead). Hash the union of primary + loaded, gated on any loaded.
    if config.security.has_loaded_env_caps {
        let mut forms: Vec<String> = config
            .security
            .env_caps
            .iter()
            .chain(config.security.loaded_env_caps.iter())
            .map(|c| {
                format!(
                    "(env \"{}\" {})",
                    c.name,
                    canonical_effect(&c.decision.value)
                )
            })
            .collect();
        forms.sort();
        forms.dedup();
        let form = forms.join(" ");
        let hash = sha256_hex(&form);
        views.push(TrustViewMeta {
            hash,
            canonical_form: form,
            program: ":env".to_string(),
            source_file: None,
            position: 0,
        });
    }

    // `:redirect` capability trust scope.
    if config.security.has_loaded_redirect_caps {
        let mut forms: Vec<String> = config
            .security
            .redirect_caps
            .iter()
            .chain(config.security.loaded_redirect_caps.iter())
            .map(|c| match &c.pattern {
                Some(pat) => format!(
                    "(redirect {} {})",
                    canonical_expr(pat),
                    canonical_effect(&c.decision.value)
                ),
                None => format!("(redirect {})", canonical_effect(&c.decision.value)),
            })
            .collect();
        forms.sort();
        forms.dedup();
        let form = forms.join(" ");
        let hash = sha256_hex(&form);
        views.push(TrustViewMeta {
            hash,
            canonical_form: form,
            program: ":redirect".to_string(),
            source_file: None,
            position: 0,
        });
    }

    views
}

/// Canonical s-expression form of a `(define …)` (excluding spans).
pub fn canonical_define(define: &Define) -> String {
    format!(
        "(define {} {})",
        define.name,
        canonical_predicate(&define.predicate.value)
    )
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
        let h1 = compute_trust_views(&config);
        let h2 = compute_trust_views(&config);
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
        let views = compute_trust_views(&config);
        assert_eq!(views.len(), 2);
        assert_ne!(views[0].hash, views[1].hash);
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
        let h1 = compute_trust_views(&c1);
        let h2 = compute_trust_views(&c2);
        assert_ne!(h1[0].hash, h2[0].hash);
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
        let views = compute_trust_views(&config);
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].program, "git");
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
        let views = compute_trust_views(&config);
        let hash = &views[0].hash;
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
        let views = compute_trust_views(&config);
        assert_eq!(views[0].source_file, Some(PathBuf::from("/rules/vcs.lisp")));
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
        let views = compute_trust_views(&config);
        // Primary rule is included in trust set (because git has loaded rules),
        // but has no source file.
        let primary = views.iter().find(|r| r.source_file.is_none());
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
        let views = compute_trust_views(&config);
        assert_eq!(views[0].position, 0);
        assert_eq!(views[1].position, 1);
    }

    // --- rule-hash invariants (replacing the removed per-program hash) ---

    #[test]
    fn rule_hash_unchanged_when_rule_moves_between_load_files() {
        // Spec: trust-hashing — a rule's hash depends on its canonical form,
        // not its source file. Moving a rule between `(load …)` files
        // therefore preserves the hash.
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
        let h_a = compute_trust_views(&make_config(vec![rule_in_a], vec![]))[0]
            .hash
            .clone();
        let h_b = compute_trust_views(&make_config(vec![rule_in_b], vec![]))[0]
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

    /// Documents the upstream condition the review-prompt dedup defends
    /// against: an OR-of-programs rule resolves to one view per program, and
    /// because `canonical_rule` stringifies the whole rule (including the
    /// `(or …)` command), those views share both `hash` and `canonical_form`.
    /// They differ only in `program`. Not a regression assert — pins the
    /// duplication that `build_pending` deduplicates one layer up.
    #[test]
    fn or_of_programs_emits_duplicate_hash_views() {
        let rule = Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Or(vec![
                CommandPattern::Literal("git".into()),
                CommandPattern::Literal("gh".into()),
            ]))),
            effect: spanned(terminal(Decision::Allow, None)),
            checks: vec![],
            span: dummy_span(),
            provenance: Provenance::Loaded {
                path: PathBuf::from("test"),
            },
        };
        let views = compute_trust_views(&make_config(vec![rule], vec![]));

        assert_eq!(views.len(), 2, "one view per program in the (or …)");
        assert_eq!(views[0].program, "git");
        assert_eq!(views[1].program, "gh");
        assert_eq!(
            views[0].hash, views[1].hash,
            "both programs share the rule's hash"
        );
        assert_eq!(
            views[0].canonical_form, views[1].canonical_form,
            "both programs share the rule's canonical form"
        );
        assert_eq!(views[0].canonical_form, r#"(rule (or "git" "gh") (allow))"#);
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
        let views = compute_trust_views(&config);
        assert!(
            views.iter().any(|r| r.program == ":safe-env-vars"),
            "should have :safe-env-vars rule"
        );
    }

    #[test]
    fn primary_only_safe_env_vars_not_hashed() {
        let mut config = make_config(vec![], vec![]);
        config.security.safe_env_vars.insert("HOME".into());
        config.security.has_loaded_env_vars = false;
        let views = compute_trust_views(&config);
        assert!(
            !views.iter().any(|r| r.program == ":safe-env-vars"),
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

        let h1 = compute_trust_views(&c1);
        let h2 = compute_trust_views(&c2);
        let env1 = h1.iter().find(|r| r.program == ":safe-env-vars").unwrap();
        let env2 = h2.iter().find(|r| r.program == ":safe-env-vars").unwrap();
        assert_ne!(env1.hash, env2.hash, "adding env var should change hash");
    }
}

#[cfg(test)]
mod sequence_group_canonical {
    use super::*;
    use may_i_config::parse_config;

    /// Task 6.3/6.4: a sequence-group quantifier serialises canonically as
    /// `(Q elem …)` with nested groups.
    #[test]
    fn group_serialises_canonically() {
        let config = parse_config(r#"(rule "tool" (positional (? "run" (? "--"))))"#)
            .expect("config parses");
        let canonical = canonical_rule(&config.rules[0]);
        assert_eq!(
            canonical,
            r#"(rule "tool" (positional (? "run" (? "--"))))"#
        );
    }

    /// A group-free config's canonical form (and therefore hash) is unchanged
    /// by the migration to `PosTerm`: single quantified terms still render as
    /// the bare pattern / `(Q expr)` exactly as before.
    #[test]
    fn group_free_canonical_unchanged() {
        let config = parse_config(r#"(rule "git" (positional "push" (? "origin") (* *)))"#)
            .expect("config parses");
        let canonical = canonical_rule(&config.rules[0]);
        assert_eq!(
            canonical,
            r#"(rule "git" (positional "push" (? "origin") (* *)))"#
        );
    }
}

#[cfg(test)]
mod canonical_form_snapshot {
    use super::*;
    use may_i_config::parse_config;

    // Hand-crafted fixture covering every rule-body Effect variant
    // (Terminal × {Allow, Ask, Deny} with/without reason, And, Or, Not,
    // When, Unless, If, Cond, ArgPattern, CommandPattern, Authorise),
    // every Predicate variant (Fact, NamedRef, And, Or, Not), and every
    // ArgPattern shape (positional, exact, anywhere, forbidden, flag,
    // parameter). Also exercises `(define …)` for the canonical-define
    // path.
    //
    // The starter config was rejected as a fixture source: it still
    // carries legacy `(check :deny …)` syntax that no longer parses.
    // The prelude was rejected: it has zero rules and zero defines.
    const RULE_BODY_FIXTURE: &str = r#"
(define safe-positional
  (or (positional "status") (positional "log")))

(rule "git"
  (cond ((fact? [:env "prod"]) (deny "no git in prod"))
        (safe-positional (allow))
        ((and (flag ["v" "verbose"]) (not (positional "push")))
         (ask "verbose non-push"))
        ((or (positional "commit") (positional "rebase"))
         (when (fact? [:ci "true"]) (ask "ci write op")))
        (else (allow))))

(rule (or "rm" "shred")
  (if (and (flag ["r" "recursive"]) (positional "/"))
      (deny "recursive root delete")
    (unless (fact? [:user "root"]) (allow))))

(rule "kubectl"
  (and (anywhere "delete") (deny "no deletes")))

(rule "curl"
  (or (exact "--insecure") (forbidden "--data-binary")))

(rule "make"
  (parameter "j" *))
"#;

    // Snapshots the canonical-form output for every rule and define in
    // the fixture. Guards rule-body parsers against an accidental
    // parse-time normalisation slip during the
    // consolidate-rule-body-parser change: any drift in `canonical_rule`
    // / `canonical_define` output for the same surface syntax would
    // silently invalidate user trust entries that depend on the same
    // rule shapes.
    #[test]
    fn rule_body_fixture_canonical_form_is_stable() {
        let config = parse_config(RULE_BODY_FIXTURE).expect("fixture parses");

        let mut lines: Vec<String> = config.rules.iter().map(canonical_rule).collect();
        lines.extend(config.defines.iter().map(canonical_define));

        insta::assert_snapshot!(lines.join("\n"));
    }
}
