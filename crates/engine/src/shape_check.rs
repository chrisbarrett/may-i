//! Shape-checking pass over rule bodies (decision D2, D9 phase 2).
//!
//! After parser resolution, every rule body is walked and each `#var`
//! reference is checked against the shape its parser declared. A
//! reference whose shape is rejected by the consuming operator's
//! signature becomes a [`ShapeMismatch`] — surfaced as a load-time
//! diagnostic rather than a silent no-match at evaluation time.
//!
//! The vocabulary here (`Shape`, "operator signature") is
//! contributor-facing; the rendered diagnostics use the user-facing
//! phrases — see `crate::shape` and the miette renderer.

use std::collections::{HashMap, HashSet};

use may_i_core::Span;
use may_i_core::ast::{BindingName, Config, Effect, Predicate};

use crate::shape::{DeclKind, Shape, ShapeEnv};

/// A rule-body operator that consumes a `#var` binding, with the shapes
/// it accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    /// `(authorise #v)` — accepts `Command`.
    Authorise,
    /// `(matches? #v PAT)` — accepts `Token | Command`.
    Matches,
    /// `(every? #v PRED)` — accepts `Collection Token`.
    Every,
    /// `(some? #v PRED)` — accepts `Collection Token`.
    Some,
}

impl Operator {
    /// The verb as written in the surface syntax.
    pub fn verb(self) -> &'static str {
        match self {
            Operator::Authorise => "authorise",
            Operator::Matches => "matches?",
            Operator::Every => "every?",
            Operator::Some => "some?",
        }
    }

    /// The shapes this operator accepts. `(bound? …)` accepts every
    /// shape and so is not represented here (it never mismatches).
    pub fn accepts(self) -> &'static [Shape] {
        match self {
            Operator::Authorise => &[Shape::Command],
            Operator::Matches => &[Shape::Token, Shape::Command],
            Operator::Every | Operator::Some => &[Shape::CollectionToken],
        }
    }

    fn accepts_shape(self, shape: Shape) -> bool {
        self.accepts().contains(&shape)
    }
}

/// A detected shape mismatch: a rule-body operator applied to a binding
/// whose declared shape it does not accept.
#[derive(Debug, Clone)]
pub struct ShapeMismatch {
    pub operator: Operator,
    pub binding: BindingName,
    /// The binding's declared shape.
    pub found: Shape,
    /// Source span of the `#var` reference in the rule body.
    pub use_span: Span,
    /// Source span of the parser declaration that assigned `found`
    /// (absent for synthetic parsers).
    pub decl_span: Option<Span>,
    /// The kind of declaration that bound `binding`, for kind-aware
    /// rewrite hints.
    pub decl_kind: DeclKind,
}

/// Run the shape checker over every rule body in `config`. Returns the
/// mismatches in source order (rule order, then in-body walk order).
pub fn check_config(config: &Config) -> Vec<ShapeMismatch> {
    let defines: HashMap<&str, &Predicate> = config
        .defines
        .iter()
        .map(|d| (d.name.as_str(), &d.predicate.value))
        .collect();

    let mut out = Vec::new();
    for rule in &config.rules {
        let env = env_for_rule(config, rule);
        // Bindings only exist relative to a parser; with no resolvable
        // program (e.g. a wildcard command pattern) we cannot attribute
        // shapes, so skip rather than risk false positives.
        if env.is_empty() {
            continue;
        }
        let mut visited = HashSet::new();
        check_effect(&rule.effect.value, &env, &defines, &mut visited, &mut out);
    }
    out
}

/// Build the merged shape environment for a rule by unioning the
/// declared shapes of every program its command pattern can match.
fn env_for_rule(config: &Config, rule: &may_i_core::ast::Rule) -> ShapeEnv {
    let programs = crate::trust::extract_program_names(match &rule.command_effect.value {
        Effect::CommandPattern(p) => p,
        _ => return ShapeEnv::default(),
    });
    let mut merged = HashMap::new();
    for prog in programs {
        let parser = config.parser_for_with_rules(prog);
        let env = ShapeEnv::from_parser(&parser);
        for (name, decl) in env.iter() {
            merged.entry(name.clone()).or_insert_with(|| decl.clone());
        }
    }
    ShapeEnv::from_map(merged)
}

fn check_effect(
    effect: &Effect,
    env: &ShapeEnv,
    defines: &HashMap<&str, &Predicate>,
    visited: &mut HashSet<String>,
    out: &mut Vec<ShapeMismatch>,
) {
    match effect {
        Effect::Authorise {
            binding,
            binding_span,
        } => {
            check_use(Operator::Authorise, binding, *binding_span, env, out);
        }
        Effect::When { predicate, effect } | Effect::Unless { predicate, effect } => {
            check_predicate(&predicate.value, env, defines, visited, out);
            check_effect(&effect.value, env, defines, visited, out);
        }
        Effect::If {
            predicate,
            then_effect,
            else_effect,
        } => {
            check_predicate(&predicate.value, env, defines, visited, out);
            check_effect(&then_effect.value, env, defines, visited, out);
            check_effect(&else_effect.value, env, defines, visited, out);
        }
        Effect::Cond { branches, fallback } => {
            for (pred, eff) in branches {
                check_predicate(&pred.value, env, defines, visited, out);
                check_effect(&eff.value, env, defines, visited, out);
            }
            if let Some(fb) = fallback {
                check_effect(&fb.value, env, defines, visited, out);
            }
        }
        Effect::And { effects } | Effect::Or { effects } => {
            for e in effects {
                check_effect(&e.value, env, defines, visited, out);
            }
        }
        Effect::Not { effect } => check_effect(&effect.value, env, defines, visited, out),
        Effect::Terminal { .. } | Effect::CommandPattern(_) | Effect::ArgPattern(_) => {}
    }
}

fn check_predicate(
    pred: &Predicate,
    env: &ShapeEnv,
    defines: &HashMap<&str, &Predicate>,
    visited: &mut HashSet<String>,
    out: &mut Vec<ShapeMismatch>,
) {
    match pred {
        Predicate::Matches {
            binding,
            binding_span,
            ..
        } => check_use(Operator::Matches, binding, *binding_span, env, out),
        Predicate::Every {
            binding,
            binding_span,
            ..
        } => check_use(Operator::Every, binding, *binding_span, env, out),
        Predicate::Some {
            binding,
            binding_span,
            ..
        } => check_use(Operator::Some, binding, *binding_span, env, out),
        // `(bound? …)` accepts any shape — never a mismatch.
        Predicate::Bound { .. } => {}
        Predicate::And(preds) | Predicate::Or(preds) => {
            for p in preds {
                check_predicate(p, env, defines, visited, out);
            }
        }
        Predicate::Not(inner) => check_predicate(inner, env, defines, visited, out),
        Predicate::Named(name) => {
            // Resolve the define under the current rule's environment,
            // guarding against reference cycles.
            if visited.insert(name.clone())
                && let Some(body) = defines.get(name.as_str())
            {
                check_predicate(body, env, defines, visited, out);
            }
        }
        Predicate::Fact(_) | Predicate::Arg(_) => {}
        // `Predicate` is `#[non_exhaustive]`; unknown variants bind no
        // `#var` we can check.
        _ => {}
    }
}

/// Check one `#var` use against an operator's signature. A binding the
/// environment does not know is skipped (conservative — see
/// `check_config`).
fn check_use(
    operator: Operator,
    binding: &BindingName,
    use_span: Span,
    env: &ShapeEnv,
    out: &mut Vec<ShapeMismatch>,
) {
    let Some(decl) = env.get_decl(binding) else {
        return;
    };
    if !operator.accepts_shape(decl.shape) {
        out.push(ShapeMismatch {
            operator,
            binding: binding.clone(),
            found: decl.shape,
            use_span,
            decl_span: decl.decl_span,
            decl_kind: decl.decl_kind.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_config::parse_config;

    fn check(src: &str) -> Vec<ShapeMismatch> {
        let config = parse_config(src).expect("config parses");
        check_config(&config)
    }

    #[test]
    fn authorise_on_collection_rejects() {
        let m = check(
            r#"
            (parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)))
            (rule "ssh" (authorise #opts))
            "#,
        );
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(m[0].operator, Operator::Authorise);
        assert_eq!(m[0].found, Shape::CollectionToken);
        assert_eq!(m[0].binding.as_str(), "opts");
        assert!(m[0].decl_span.is_some(), "declaration span present");
    }

    #[test]
    fn every_on_token_rejects() {
        let m = check(
            r#"
            (parser "xargs" (style gnu) (flags posix) (parameter "n" #procs) (rest #cmd))
            (rule "xargs" (when (every? #procs (regex "^[0-9]+$")) (allow)))
            "#,
        );
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(m[0].operator, Operator::Every);
        assert_eq!(m[0].found, Shape::Token);
        assert_eq!(m[0].decl_kind, DeclKind::Parameter { name: "n".into() });
    }

    #[test]
    fn mismatch_carries_positional_decl_kind() {
        // every? over a single-token positional: the mismatch records the
        // declaration kind, with no parameter name to offer.
        let m = check(
            r#"
            (parser "rm" (style gnu) (flags posix) (positional #p (regex "^/tmp/")))
            (rule "rm" (when (every? #p (regex "^/tmp/")) (allow)))
            "#,
        );
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(m[0].found, Shape::Token);
        assert_eq!(m[0].decl_kind, DeclKind::Positional);
    }

    #[test]
    fn matches_on_command_is_accepted() {
        // (many-till …) capture is Command-shaped; matches? accepts it.
        let m = check(
            r#"
            (parser "find" (style single-dash-long) (flags permute) (parameter "exec" (many-till ";") #args))
            (rule "find" (when (matches? #args (regex "rm")) (ask)))
            "#,
        );
        assert!(m.is_empty(), "expected no mismatch, got {m:?}");
    }

    #[test]
    fn some_on_command_rejects() {
        let m = check(
            r#"
            (parser "bash" (style gnu) (flags posix) (parameter "c" (command #cmd)))
            (rule "bash" (when (some? #cmd (regex "rm")) (deny)))
            "#,
        );
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(m[0].operator, Operator::Some);
        assert_eq!(m[0].found, Shape::Command);
    }

    #[test]
    fn every_on_collection_is_accepted() {
        let m = check(
            r#"
            (parser "rm" (style gnu) (flags posix) (positional #paths (regex "^/tmp/") *))
            (rule "rm" (when (every? #paths (regex "^/tmp/")) (allow)))
            "#,
        );
        assert!(m.is_empty(), "expected no mismatch, got {m:?}");
    }

    #[test]
    fn authorise_on_rest_command_is_accepted() {
        let m = check(
            r#"
            (parser "sudo" (style gnu) (flags posix) (rest #cmd))
            (rule "sudo" (authorise #cmd))
            "#,
        );
        assert!(m.is_empty(), "expected no mismatch, got {m:?}");
    }

    #[test]
    fn bound_accepts_any_shape() {
        let m = check(
            r#"
            (parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)))
            (rule "ssh" (when (bound? #opts) (allow)))
            "#,
        );
        assert!(m.is_empty(), "bound? never mismatches, got {m:?}");
    }

    #[test]
    fn mismatch_inside_cond_if_and_or_not_arms() {
        // every? on a Token (#n) flagged wherever it appears in the
        // effect/predicate tree.
        let parser =
            "(parser \"xargs\" (style gnu) (flags posix) (parameter \"n\" #procs) (rest #c))";
        let bad = "(every? #procs (regex \"x\"))";
        for body in [
            format!("(cond ({bad} (allow)) (else (deny)))"),
            format!("(if {bad} (allow) (deny))"),
            format!("(when (and {bad} (flag \"v\")) (allow))"),
            format!("(when (or {bad} (flag \"v\")) (allow))"),
            format!("(when (not {bad}) (allow))"),
        ] {
            let m = check(&format!("{parser}\n(rule \"xargs\" {body})"));
            assert_eq!(m.len(), 1, "body `{body}` → {m:?}");
            assert_eq!(m[0].operator, Operator::Every);
        }
    }

    #[test]
    fn merges_env_across_or_command_programs() {
        // The rule matches two programs; the binding is declared by one.
        let m = check(
            r#"
            (parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)))
            (rule (or "ssh" "scp") (authorise #opts))
            "#,
        );
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(m[0].found, Shape::CollectionToken);
    }

    #[test]
    fn undeclared_binding_is_skipped() {
        // #nope is not declared by any parser for this rule → no
        // mismatch (conservative; avoids false positives).
        let m = check(
            r#"
            (parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)))
            (rule "ssh" (when (every? #nope (regex "x")) (allow)))
            "#,
        );
        assert!(m.is_empty(), "{m:?}");
    }

    #[test]
    fn rule_for_program_without_bindings_is_skipped() {
        // No parser declares bindings for this program → empty shape
        // environment → the rule is skipped (the `env.is_empty()` guard).
        let m = check("(rule \"totally-undeclared\" (when (every? #x (regex \"y\")) (allow)))");
        assert!(m.is_empty(), "{m:?}");
    }

    #[test]
    fn mismatch_inside_define_is_checked() {
        let m = check(
            r#"
            (define numeric? (every? #procs (regex "^[0-9]+$")))
            (parser "xargs" (style gnu) (flags posix) (parameter "n" #procs) (rest #cmd))
            (rule "xargs" (when numeric? (allow)))
            "#,
        );
        assert_eq!(m.len(), 1, "define body checked under rule env: {m:?}");
        assert_eq!(m[0].operator, Operator::Every);
    }
}
