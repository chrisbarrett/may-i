// Trust hash computation for per-program trust verification.
//
// Computes SHA-256 hashes over resolved rule closures, grouped by program name.
// Programs with any `Loaded` provenance content require trust approval.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use may_i_core::ast::{Config, Effect, Predicate, Rule};
use may_i_core::doc::DocF;
use may_i_core::pattern::{ArgPattern, CommandPattern, Expr, MatchMode, PositionalArg, Quantifier};
use may_i_core::primitives::ToDoc;
use sha2::{Digest, Sha256};

/// Per-program metadata including hash, canonical rule forms, and source files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramMeta {
    pub hash: String,
    pub canonical_rules: Vec<String>,
    pub source_files: BTreeSet<PathBuf>,
}

/// Per-program trust hash results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustHashes {
    /// Map of program name (or `:safe-env-vars`) to metadata.
    pub programs: BTreeMap<String, ProgramMeta>,
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
///
/// A program needs trust if any of its rules has `Loaded` provenance,
/// or any of its rules references a define with `Loaded` provenance.
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
fn canonical_rule(rule: &Rule) -> String {
    let cmd = canonical_effect(&rule.command_effect.value);
    let body = canonical_effect(&rule.effect.value);
    format!("(rule {cmd} {body})")
}

/// Produce a canonical s-expression for an effect.
fn canonical_effect(effect: &Effect) -> String {
    match effect {
        Effect::Terminal { decision, reason } => match reason {
            Some(r) => format!("(effect {} \"{}\")", decision.keyword(), r),
            None => format!("(effect {})", decision.keyword()),
        },
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
        Effect::MayI { pattern } => format!("(may-i {})", canonical_arg_pattern(pattern)),
        _ => "<unknown>".to_string(),
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
        _ => "<unknown>".to_string(),
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

/// Compute trust hashes for all programs that need trust approval.
///
/// Returns a map of program name (or `:safe-env-vars`) to hex-encoded SHA-256 hash.
/// Only programs with at least one `Loaded` rule or referencing a `Loaded` define
/// are included.
pub fn compute_trust_hashes(config: &Config) -> TrustHashes {
    let programs_need_trust = programs_needing_trust(config);
    let mut programs = BTreeMap::new();

    for program in &programs_need_trust {
        let rules_for_program: Vec<&Rule> = config
            .rules
            .iter()
            .filter(|r| {
                extract_command_programs(&r.command_effect.value)
                    .iter()
                    .any(|p| p == program)
            })
            .collect();

        if rules_for_program.is_empty() {
            continue;
        }

        let canonical_rules: Vec<String> = rules_for_program
            .iter()
            .map(|r| canonical_rule(r))
            .collect();
        let combined = canonical_rules.join("\n");
        let hash = sha256_hex(&combined);

        let source_files: BTreeSet<PathBuf> = rules_for_program
            .iter()
            .filter_map(|r| r.provenance.path())
            .map(|p| p.to_path_buf())
            .collect();

        programs.insert(
            program.clone(),
            ProgramMeta {
                hash,
                canonical_rules,
                source_files,
            },
        );
    }

    // Handle safe-env-vars trust scope
    if config.security.has_loaded_env_vars && !config.security.safe_env_vars.is_empty() {
        let mut sorted_vars: Vec<&String> = config.security.safe_env_vars.iter().collect();
        sorted_vars.sort();
        let canonical_form = sorted_vars
            .iter()
            .map(|v| format!("\"{}\"", v))
            .collect::<Vec<_>>()
            .join(" ");
        let canonical_str = format!("(safe-env-vars {})", canonical_form);
        let hash = sha256_hex(&canonical_str);
        programs.insert(
            ":safe-env-vars".to_string(),
            ProgramMeta {
                hash,
                canonical_rules: vec![canonical_str],
                source_files: BTreeSet::new(),
            },
        );
    }

    TrustHashes { programs }
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
            security: may_i_core::ast::SecurityConfig::default(),
            checks: vec![],
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

    // --- hash stability ---

    #[test]
    fn same_config_produces_same_hash() {
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
        assert_ne!(h1.programs["git"].hash, h2.programs["git"].hash);
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
        assert!(hashes.programs.contains_key("git"));
        assert!(!hashes.programs.contains_key("ls"));
    }

    #[test]
    fn hash_covers_full_closure_both_provenances() {
        let c1 = make_config(
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
        let c2 = make_config(
            vec![
                make_rule(
                    "git",
                    terminal(Decision::Deny, None),
                    Provenance::Loaded {
                        path: PathBuf::from("test"),
                    },
                ),
                make_rule(
                    "git",
                    terminal(Decision::Allow, None),
                    Provenance::PrimaryConfig,
                ),
            ],
            vec![],
        );
        let h1 = compute_trust_hashes(&c1);
        let h2 = compute_trust_hashes(&c2);
        assert_ne!(
            h1.programs["git"].hash, h2.programs["git"].hash,
            "reordering rules should change hash"
        );
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
        let hash = &hashes.programs["git"].hash;
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
            hashes.programs.contains_key(":safe-env-vars"),
            "should have :safe-env-vars key"
        );
    }

    #[test]
    fn primary_only_safe_env_vars_not_hashed() {
        let mut config = make_config(vec![], vec![]);
        config.security.safe_env_vars.insert("HOME".into());
        config.security.has_loaded_env_vars = false;
        let hashes = compute_trust_hashes(&config);
        assert!(
            !hashes.programs.contains_key(":safe-env-vars"),
            "should not have :safe-env-vars key when all primary"
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
        assert_ne!(
            h1.programs[":safe-env-vars"].hash, h2.programs[":safe-env-vars"].hash,
            "adding env var should change hash"
        );
    }

    // --- metadata content ---

    #[test]
    fn metadata_includes_canonical_rule_forms() {
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
        let meta = &hashes.programs["git"];
        assert_eq!(meta.canonical_rules.len(), 1);
        assert_eq!(
            meta.canonical_rules[0],
            r#"(rule "git" (effect :allow "safe"))"#
        );
    }

    #[test]
    fn metadata_includes_source_file_paths() {
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
        let meta = &hashes.programs["git"];
        assert!(
            meta.source_files
                .contains(&PathBuf::from("/rules/vcs.lisp"))
        );
    }

    #[test]
    fn metadata_collects_multiple_source_files() {
        let config = make_config(
            vec![
                Rule {
                    command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                        "git".into(),
                    ))),
                    effect: spanned(terminal(Decision::Allow, None)),
                    checks: vec![],
                    span: dummy_span(),
                    provenance: Provenance::Loaded {
                        path: PathBuf::from("/rules/a.lisp"),
                    },
                },
                Rule {
                    command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                        "git".into(),
                    ))),
                    effect: spanned(terminal(Decision::Deny, None)),
                    checks: vec![],
                    span: dummy_span(),
                    provenance: Provenance::Loaded {
                        path: PathBuf::from("/rules/b.lisp"),
                    },
                },
            ],
            vec![],
        );
        let hashes = compute_trust_hashes(&config);
        let meta = &hashes.programs["git"];
        assert_eq!(meta.source_files.len(), 2);
        assert!(meta.source_files.contains(&PathBuf::from("/rules/a.lisp")));
        assert!(meta.source_files.contains(&PathBuf::from("/rules/b.lisp")));
    }

    #[test]
    fn primary_only_program_excluded_from_metadata() {
        let config = make_config(
            vec![make_rule(
                "ls",
                terminal(Decision::Allow, None),
                Provenance::PrimaryConfig,
            )],
            vec![],
        );
        let hashes = compute_trust_hashes(&config);
        assert!(!hashes.programs.contains_key("ls"));
    }
}
