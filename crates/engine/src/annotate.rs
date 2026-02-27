// Annotated document builder for rule evaluation.
//
// Produces `Doc<Option<EvalAnn>>` trees where each node carries an optional
// evaluation annotation. Nodes that the evaluator visited get `Some(ann)`;
// structural scaffolding gets `None`. The renderer can then fold these
// annotated trees to produce two-column trace output.

use may_i_core::{
    ArgMatcher, CommandMatcher, CondArm, Doc, DocF, Effect, EvalAnn, Expr, ExprBranch,
    LayoutHint, PosExpr, Rule, RuleBody,
};

use crate::matcher::{
    MatchOutcome, ResolvedArg, command_matches, expr_matches_resolved, extract_positional_args,
};

/// Annotated Doc: each node optionally carries an evaluation annotation.
pub(crate) type ADoc = Doc<Option<EvalAnn>>;

// ── Constructors ──────────────────────────────────────────────────

fn atom(s: impl Into<String>) -> ADoc {
    Doc { ann: None, node: DocF::Atom(s.into()), layout: LayoutHint::Auto }
}

fn list(children: Vec<ADoc>) -> ADoc {
    Doc { ann: None, node: DocF::List(children), layout: LayoutHint::Auto }
}

fn ann_list(ann: EvalAnn, children: Vec<ADoc>) -> ADoc {
    Doc { ann: Some(ann), node: DocF::List(children), layout: LayoutHint::Auto }
}

/// Convert an unannotated Doc<()> to Doc<Option<EvalAnn>> (all None).
fn unannotate(doc: Doc<()>) -> ADoc {
    doc.map(&|()| None)
}

fn arg_to_string(a: &ResolvedArg) -> String {
    match a {
        ResolvedArg::Literal(s) => format!("\"{s}\""),
        ResolvedArg::Opaque => "<opaque>".into(),
    }
}

// ── Rule annotation ───────────────────────────────────────────────

/// Annotate a single rule's evaluation against a command and its arguments.
///
/// Returns the annotated Doc tree for the rule and the matched effect (if any).
pub(crate) fn annotate_rule(
    rule: &Rule,
    cmd_name: &str,
    expanded_args: &[ResolvedArg],
) -> (ADoc, Option<Effect>) {
    let cmd_matched = command_matches(cmd_name, &rule.command);
    let cmd_doc = annotate_command(&rule.command, cmd_matched);

    if !cmd_matched {
        let mut cs = vec![atom("rule"), cmd_doc];
        for d in rule.body.to_doc() {
            cs.push(unannotate(d));
        }
        return (list(cs), None);
    }

    let (body_docs, effect) = annotate_body(&rule.body, expanded_args);
    let mut cs = vec![atom("rule"), cmd_doc];
    cs.extend(body_docs);

    let ann = effect.as_ref().map(|e| EvalAnn::RuleEffect {
        decision: e.decision,
        reason: e.reason.clone(),
    });
    (Doc { ann, node: DocF::List(cs), layout: LayoutHint::Auto }, effect)
}

fn annotate_command(matcher: &CommandMatcher, matched: bool) -> ADoc {
    let ann = EvalAnn::CommandMatch(matched);
    let children = match matcher {
        CommandMatcher::Exact(s) => {
            vec![atom("command"), atom(format!("\"{s}\""))]
        }
        CommandMatcher::Regex(re) => {
            vec![
                atom("command"),
                list(vec![atom("regex"), atom(format!("\"{}\"", re.as_str()))]),
            ]
        }
        CommandMatcher::List(names) => {
            let mut or_cs = vec![atom("or")];
            or_cs.extend(names.iter().map(|n| atom(format!("\"{n}\""))));
            vec![atom("command"), list(or_cs)]
        }
    };
    ann_list(ann, children)
}

fn annotate_body(
    body: &RuleBody,
    args: &[ResolvedArg],
) -> (Vec<ADoc>, Option<Effect>) {
    match body {
        RuleBody::Effect { matcher: None, effect } => {
            let effect_doc = annotate_effect(effect);
            (vec![effect_doc], Some(effect.clone()))
        }
        RuleBody::Effect { matcher: Some(m), effect } => {
            let (matcher_doc, outcome) = annotate_matcher(m, args);
            let matched = outcome.is_match();
            let args_doc = ann_list(
                EvalAnn::ArgsResult(matched),
                vec![atom("args"), matcher_doc],
            );
            let effect_doc = annotate_effect(effect);
            let final_effect = if matched {
                if let MatchOutcome::Matched(eff) = outcome {
                    Some(eff)
                } else {
                    Some(effect.clone())
                }
            } else {
                None
            };
            (vec![args_doc, effect_doc], final_effect)
        }
        RuleBody::Branching(m) => {
            let (matcher_doc, outcome) = annotate_matcher(m, args);
            let matched = outcome.is_match();
            let effect = if let MatchOutcome::Matched(eff) = outcome {
                Some(eff)
            } else {
                None
            };
            let args_doc = ann_list(
                EvalAnn::ArgsResult(matched),
                vec![atom("args"), matcher_doc],
            );
            (vec![args_doc], effect)
        }
    }
}

fn annotate_effect(effect: &Effect) -> ADoc {
    let mut cs = vec![
        atom("effect"),
        atom(format!(":{}", effect.decision)),
    ];
    if let Some(r) = &effect.reason {
        cs.push(atom(format!("\"{r}\"")));
    }
    ann_list(
        EvalAnn::RuleEffect {
            decision: effect.decision,
            reason: effect.reason.clone(),
        },
        cs,
    )
}

// ── Matcher annotation ────────────────────────────────────────────

fn annotate_matcher(
    matcher: &ArgMatcher,
    args: &[ResolvedArg],
) -> (ADoc, MatchOutcome) {
    match matcher {
        ArgMatcher::Positional(patterns) => annotate_positional(patterns, args, false),
        ArgMatcher::ExactPositional(patterns) => annotate_positional(patterns, args, true),
        ArgMatcher::Anywhere(tokens) => annotate_anywhere(tokens, args),
        ArgMatcher::And(matchers) => annotate_matcher_and(matchers, args),
        ArgMatcher::Or(matchers) => annotate_matcher_or(matchers, args),
        ArgMatcher::Not(inner) => annotate_matcher_not(inner, args),
        ArgMatcher::Cond(arm) => annotate_matcher_cond(arm, args),
    }
}

fn annotate_matcher_and(
    matchers: &[ArgMatcher],
    args: &[ResolvedArg],
) -> (ADoc, MatchOutcome) {
    let mut cs = vec![atom("and")];
    let mut first_effect: Option<Effect> = None;
    let mut all_matched = true;

    for m in matchers {
        if all_matched {
            let (doc, outcome) = annotate_matcher(m, args);
            cs.push(doc);
            match outcome {
                MatchOutcome::NoMatch => {
                    all_matched = false;
                }
                MatchOutcome::Matched(eff) if first_effect.is_none() => {
                    first_effect = Some(eff);
                }
                _ => {}
            }
        } else {
            cs.push(unannotate(m.to_doc()));
        }
    }

    let outcome = if all_matched {
        match first_effect {
            Some(eff) => MatchOutcome::Matched(eff),
            None => MatchOutcome::MatchedNoEffect,
        }
    } else {
        MatchOutcome::NoMatch
    };
    (list(cs), outcome)
}

fn annotate_matcher_or(
    matchers: &[ArgMatcher],
    args: &[ResolvedArg],
) -> (ADoc, MatchOutcome) {
    let mut cs = vec![atom("or")];
    let mut result = MatchOutcome::NoMatch;
    let mut found = false;

    for m in matchers {
        if !found {
            let (doc, outcome) = annotate_matcher(m, args);
            cs.push(doc);
            if outcome.is_match() {
                result = outcome;
                found = true;
            }
        } else {
            cs.push(unannotate(m.to_doc()));
        }
    }
    (list(cs), result)
}

fn annotate_matcher_not(
    inner: &ArgMatcher,
    args: &[ResolvedArg],
) -> (ADoc, MatchOutcome) {
    let (inner_doc, inner_outcome) = annotate_matcher(inner, args);
    let outcome = if inner_outcome.is_match() {
        MatchOutcome::NoMatch
    } else {
        MatchOutcome::MatchedNoEffect
    };
    (list(vec![atom("not"), inner_doc]), outcome)
}

fn annotate_matcher_cond(
    arm: &CondArm,
    args: &[ResolvedArg],
) -> (ADoc, MatchOutcome) {
    let mut cs = vec![atom("cond")];

    for branch in &arm.branches {
        let (matcher_doc, outcome) = annotate_matcher(&branch.matcher, args);
        let matched = outcome.is_match();
        let effect_doc = annotate_effect(&branch.effect);
        let branch_ann = if matched {
            Some(EvalAnn::CondBranch { decision: branch.effect.decision })
        } else {
            None
        };
        cs.push(Doc {
            ann: branch_ann,
            node: DocF::List(vec![matcher_doc, effect_doc]),
            layout: LayoutHint::Auto,
        });
        if matched {
            // Remaining branches unannotated
            return (list(cs), MatchOutcome::Matched(branch.effect.clone()));
        }
    }

    if let Some(fallback) = &arm.fallback {
        let effect_doc = annotate_effect(fallback);
        cs.push(ann_list(
            EvalAnn::CondElse { decision: fallback.decision },
            vec![atom("else"), effect_doc],
        ));
        return (list(cs), MatchOutcome::Matched(fallback.clone()));
    }

    (list(cs), MatchOutcome::NoMatch)
}

// ── Positional annotation ─────────────────────────────────────────

fn annotate_positional(
    patterns: &[PosExpr],
    args: &[ResolvedArg],
    exact: bool,
) -> (ADoc, MatchOutcome) {
    let positional = extract_positional_args(args);
    let mut pos = 0;
    let mut first_effect: Option<Effect> = None;
    let head = if exact { "exact" } else { "positional" };
    let mut cs = vec![atom(head)];

    for pexpr in patterns {
        let e = &pexpr.expr;

        if pexpr.quantifier.is_repeating() {
            let start = pos;
            while let Some(arg) = positional.get(pos) {
                if !expr_matches_resolved(e, arg) {
                    break;
                }
                if first_effect.is_none()
                    && let ResolvedArg::Literal(s) = arg
                    && let Some(eff) = e.find_effect(s)
                {
                    first_effect = Some(eff.clone());
                }
                pos += 1;
            }
            let count = pos - start;
            let matched = count >= pexpr.quantifier.min();
            let inner = unannotate(pexpr.to_doc());
            cs.push(Doc {
                ann: Some(EvalAnn::Quantifier { count, matched }),
                ..inner
            });
            if !matched {
                return (list(cs), MatchOutcome::NoMatch);
            }
        } else {
            match positional.get(pos) {
                Some(arg) => {
                    let (expr_doc, outcome) = annotate_expr_arg(e, arg);
                    let pexpr_doc = wrap_quantifier(pexpr.quantifier, expr_doc);
                    cs.push(pexpr_doc);
                    if outcome.is_match() {
                        if let MatchOutcome::Matched(eff) = outcome
                            && first_effect.is_none()
                        {
                            first_effect = Some(eff);
                        }
                        pos += 1;
                    } else if pexpr.quantifier.min() > 0 {
                        return (list(cs), MatchOutcome::NoMatch);
                    }
                }
                None => {
                    if pexpr.quantifier.min() > 0 {
                        let inner = unannotate(pexpr.to_doc());
                        cs.push(Doc { ann: Some(EvalAnn::Missing), ..inner });
                        return (list(cs), MatchOutcome::NoMatch);
                    }
                }
            }
        }
    }

    if exact && pos != positional.len() {
        let remainder = positional.len() - pos;
        let doc = Doc {
            ann: Some(EvalAnn::ExactRemainder { count: remainder }),
            node: DocF::List(cs),
            layout: LayoutHint::Auto,
        };
        return (doc, MatchOutcome::NoMatch);
    }

    let outcome = match first_effect {
        Some(eff) => MatchOutcome::Matched(eff),
        None => MatchOutcome::MatchedNoEffect,
    };
    (list(cs), outcome)
}

fn wrap_quantifier(q: may_i_core::Quantifier, inner: ADoc) -> ADoc {
    match q {
        may_i_core::Quantifier::One => inner,
        may_i_core::Quantifier::Optional => list(vec![atom("?"), inner]),
        may_i_core::Quantifier::OneOrMore => list(vec![atom("+"), inner]),
        may_i_core::Quantifier::ZeroOrMore => list(vec![atom("*"), inner]),
    }
}

// ── Anywhere annotation ───────────────────────────────────────────

fn annotate_anywhere(
    tokens: &[Expr],
    args: &[ResolvedArg],
) -> (ADoc, MatchOutcome) {
    let mut cs = vec![atom("anywhere")];
    let args_strs: Vec<String> = args.iter().map(arg_to_string).collect();

    for token in tokens {
        let matched = args.iter().any(|a| expr_matches_resolved(token, a));
        let token_doc_inner = unannotate(token.to_doc());
        let token_doc = Doc {
            ann: Some(EvalAnn::Anywhere { args: args_strs.clone(), matched }),
            ..token_doc_inner
        };
        cs.push(token_doc);
        if matched {
            // Extract effect if present
            if let Expr::Cond(branches) = token {
                for a in args {
                    if let ResolvedArg::Literal(s) = a {
                        for branch in branches {
                            if branch.test.is_match(s) {
                                return (list(cs), MatchOutcome::Matched(branch.effect.clone()));
                            }
                        }
                    }
                }
            }
            for a in args {
                if let ResolvedArg::Literal(s) = a
                    && let Some(eff) = token.find_effect(s)
                {
                    return (list(cs), MatchOutcome::Matched(eff.clone()));
                }
            }
            return (list(cs), MatchOutcome::MatchedNoEffect);
        }
    }

    (list(cs), MatchOutcome::NoMatch)
}

// ── Expression annotation ─────────────────────────────────────────

fn annotate_expr_arg(expr: &Expr, arg: &ResolvedArg) -> (ADoc, MatchOutcome) {
    if let Expr::Cond(branches) = expr {
        return annotate_expr_cond(branches, arg);
    }

    match expr {
        Expr::And(children) => {
            let mut cs = vec![atom("and")];
            for (i, child) in children.iter().enumerate() {
                let (doc, outcome) = annotate_expr_arg(child, arg);
                cs.push(doc);
                match outcome {
                    MatchOutcome::NoMatch => {
                        // Remaining children unannotated
                        for remaining in &children[i + 1..] {
                            cs.push(unannotate(remaining.to_doc()));
                        }
                        return (list(cs), MatchOutcome::NoMatch);
                    }
                    MatchOutcome::Matched(eff) => {
                        for remaining in &children[i + 1..] {
                            cs.push(unannotate(remaining.to_doc()));
                        }
                        return (list(cs), MatchOutcome::Matched(eff));
                    }
                    MatchOutcome::MatchedNoEffect => {}
                }
            }
            // Check for nested Cond effects
            if let ResolvedArg::Literal(s) = arg
                && let Some(eff) = expr.find_effect(s)
            {
                return (list(cs), MatchOutcome::Matched(eff.clone()));
            }
            (list(cs), MatchOutcome::MatchedNoEffect)
        }
        Expr::Or(children) => {
            let mut cs = vec![atom("or")];
            for (i, child) in children.iter().enumerate() {
                let (doc, outcome) = annotate_expr_arg(child, arg);
                cs.push(doc);
                if outcome.is_match() {
                    // Remaining children unannotated
                    for remaining in &children[i + 1..] {
                        cs.push(unannotate(remaining.to_doc()));
                    }
                    return (list(cs), outcome);
                }
            }
            (list(cs), MatchOutcome::NoMatch)
        }
        Expr::Not(inner) => {
            let (inner_doc, _) = annotate_expr_arg(inner, arg);
            let matched = expr_matches_resolved(expr, arg);
            let arg_str = arg_to_string(arg);
            let doc = Doc {
                ann: Some(EvalAnn::ExprVsArg { arg: arg_str, matched }),
                node: DocF::List(vec![atom("not"), inner_doc]),
                layout: LayoutHint::Auto,
            };
            if !matched {
                return (doc, MatchOutcome::NoMatch);
            }
            if let ResolvedArg::Literal(s) = arg
                && let Some(eff) = expr.find_effect(s)
            {
                return (doc, MatchOutcome::Matched(eff.clone()));
            }
            (doc, MatchOutcome::MatchedNoEffect)
        }
        _ => {
            // Leaf: Literal, Regex, Wildcard
            let matched = expr_matches_resolved(expr, arg);
            let arg_str = arg_to_string(arg);
            let inner = unannotate(expr.to_doc());
            let doc = Doc {
                ann: Some(EvalAnn::ExprVsArg { arg: arg_str, matched }),
                ..inner
            };
            if !matched {
                return (doc, MatchOutcome::NoMatch);
            }
            // Check for nested Cond effects (shouldn't happen for leaves, but be safe)
            if let ResolvedArg::Literal(s) = arg
                && let Some(eff) = expr.find_effect(s)
            {
                return (doc, MatchOutcome::Matched(eff.clone()));
            }
            (doc, MatchOutcome::MatchedNoEffect)
        }
        // Cond handled at the top of the function
    }
}

fn annotate_expr_cond(
    branches: &[ExprBranch],
    arg: &ResolvedArg,
) -> (ADoc, MatchOutcome) {
    let mut cs = vec![atom("cond")];

    match arg {
        ResolvedArg::Literal(s) => {
            for branch in branches {
                let matched = branch.test.is_match(s);
                let test_doc = unannotate(branch.test.to_doc());
                let effect_doc = annotate_effect(&branch.effect);
                let branch_doc = if matched {
                    ann_list(
                        EvalAnn::CondBranch { decision: branch.effect.decision },
                        vec![test_doc, effect_doc],
                    )
                } else {
                    list(vec![test_doc, effect_doc])
                };
                cs.push(branch_doc);
                if matched {
                    return (list(cs), MatchOutcome::Matched(branch.effect.clone()));
                }
            }
            (list(cs), MatchOutcome::NoMatch)
        }
        ResolvedArg::Opaque => {
            // Opaque args can't match specific cond branches
            for branch in branches {
                let test_doc = unannotate(branch.test.to_doc());
                let effect_doc = annotate_effect(&branch.effect);
                cs.push(list(vec![test_doc, effect_doc]));
            }
            (list(cs), MatchOutcome::NoMatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::{CondBranch, Decision, Quantifier, Span};

    fn lit(s: &str) -> ResolvedArg {
        ResolvedArg::Literal(s.into())
    }

    fn allow(reason: &str) -> Effect {
        Effect { decision: Decision::Allow, reason: Some(reason.into()) }
    }

    fn deny(reason: &str) -> Effect {
        Effect { decision: Decision::Deny, reason: Some(reason.into()) }
    }

    /// Collect all annotations from an annotated Doc tree.
    fn collect_annotations(doc: &ADoc) -> Vec<EvalAnn> {
        doc.fold(&|node, ann: &Option<EvalAnn>| {
            let mut result: Vec<EvalAnn> = Vec::new();
            if let Some(a) = ann {
                result.push(a.clone());
            }
            if let DocF::List(children) = node {
                for child_anns in children {
                    result.extend(child_anns);
                }
            }
            result
        })
    }

    /// Check that the annotated Doc pretty-prints to the same structure as to_doc.
    fn assert_same_structure(annotated: &ADoc, plain: &Doc<()>) {
        let ann_str = annotated.fold(&|node, _ann: &Option<EvalAnn>| match node {
            DocF::Atom(s) => s,
            DocF::List(cs) => format!("({})", cs.join(" ")),
        });
        let plain_str = plain.fold(&|node, _: &()| match node {
            DocF::Atom(s) => s,
            DocF::List(cs) => format!("({})", cs.join(" ")),
        });
        assert_eq!(ann_str, plain_str);
    }

    // ── Simple rule (no args) ───────────────────────────────────────

    #[test]
    fn simple_allow_rule() {
        let rule = Rule {
            command: CommandMatcher::Exact("ls".into()),
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (doc, effect) = annotate_rule(&rule, "ls", &[]);
        assert!(effect.is_some());
        assert_eq!(effect.unwrap().decision, Decision::Allow);

        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|a| matches!(a, EvalAnn::CommandMatch(true))));
        assert!(anns.iter().any(|a| matches!(a, EvalAnn::RuleEffect { decision: Decision::Allow, .. })));
    }

    #[test]
    fn command_no_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("ls".into()),
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (doc, effect) = annotate_rule(&rule, "cat", &[]);
        assert!(effect.is_none());

        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|a| matches!(a, EvalAnn::CommandMatch(false))));
    }

    // ── Positional matching ─────────────────────────────────────────

    #[test]
    fn positional_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![
                    PosExpr::one(Expr::Literal("push".into())),
                ])),
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let args = vec![lit("push")];
        let (doc, effect) = annotate_rule(&rule, "git", &args);
        assert!(effect.is_some());

        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|a| matches!(a, EvalAnn::ExprVsArg { matched: true, .. })));
        assert!(anns.iter().any(|a| matches!(a, EvalAnn::ArgsResult(true))));
    }

    #[test]
    fn positional_no_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![
                    PosExpr::one(Expr::Literal("push".into())),
                ])),
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let args = vec![lit("pull")];
        let (doc, effect) = annotate_rule(&rule, "git", &args);
        assert!(effect.is_none());

        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|a| matches!(a, EvalAnn::ExprVsArg { matched: false, .. })));
        assert!(anns.iter().any(|a| matches!(a, EvalAnn::ArgsResult(false))));
    }

    #[test]
    fn positional_missing_arg() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![
                    PosExpr::one(Expr::Literal("push".into())),
                ])),
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (_, effect) = annotate_rule(&rule, "git", &[]);
        assert!(effect.is_none());
    }

    // ── Quantifier matching ─────────────────────────────────────────

    #[test]
    fn quantifier_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![
                    PosExpr::one(Expr::Literal("push".into())),
                    PosExpr { quantifier: Quantifier::ZeroOrMore, expr: Expr::Wildcard },
                ])),
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let args = vec![lit("push"), lit("origin"), lit("main")];
        let (doc, effect) = annotate_rule(&rule, "git", &args);
        assert!(effect.is_some());

        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|a| matches!(a, EvalAnn::Quantifier { count: 2, matched: true })));
    }

    // ── Anywhere matching ───────────────────────────────────────────

    #[test]
    fn anywhere_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Anywhere(vec![
                    Expr::Literal("--force".into()),
                ])),
                effect: Effect { decision: Decision::Deny, reason: Some("force push".into()) },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let args = vec![lit("push"), lit("--force")];
        let (doc, effect) = annotate_rule(&rule, "git", &args);
        // Anywhere match doesn't produce its own effect; rule-level effect applies
        assert!(effect.is_some());

        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|a| matches!(a, EvalAnn::Anywhere { matched: true, .. })));
    }

    // ── Branching (cond) matching ───────────────────────────────────

    #[test]
    fn branching_cond_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            body: RuleBody::Branching(ArgMatcher::Cond(CondArm {
                branches: vec![CondBranch {
                    matcher: ArgMatcher::Anywhere(vec![Expr::Literal("--force".into())]),
                    effect: deny("force push"),
                }],
                fallback: Some(allow("safe")),
            })),
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let args = vec![lit("push"), lit("origin")];
        let (doc, effect) = annotate_rule(&rule, "git", &args);
        assert!(effect.is_some());
        assert_eq!(effect.unwrap().decision, Decision::Allow);

        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|a| matches!(a, EvalAnn::CondElse { decision: Decision::Allow })));
    }

    #[test]
    fn branching_cond_branch_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            body: RuleBody::Branching(ArgMatcher::Cond(CondArm {
                branches: vec![CondBranch {
                    matcher: ArgMatcher::Anywhere(vec![Expr::Literal("--force".into())]),
                    effect: deny("force push"),
                }],
                fallback: Some(allow("safe")),
            })),
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let args = vec![lit("push"), lit("--force")];
        let (doc, effect) = annotate_rule(&rule, "git", &args);
        assert!(effect.is_some());
        assert_eq!(effect.unwrap().decision, Decision::Deny);

        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|a| matches!(a, EvalAnn::CondBranch { decision: Decision::Deny })));
    }

    // ── Expr-level cond ─────────────────────────────────────────────

    #[test]
    fn expr_cond_branch_match() {
        let cond_expr = Expr::Cond(vec![
            ExprBranch {
                test: Expr::Literal("safe".into()),
                effect: allow("safe arg"),
            },
            ExprBranch {
                test: Expr::Wildcard,
                effect: deny("fallback"),
            },
        ]);
        let rule = Rule {
            command: CommandMatcher::Exact("cmd".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![PosExpr::one(cond_expr)])),
                effect: Effect { decision: Decision::Ask, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (_, effect) = annotate_rule(&rule, "cmd", &[lit("safe")]);
        assert_eq!(effect.unwrap().decision, Decision::Allow);
    }

    // ── Regex command matching ────────────────────────────────────────

    #[test]
    fn regex_command_match() {
        let rule = Rule {
            command: CommandMatcher::Regex(regex::Regex::new("^git").unwrap()),
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (_, effect) = annotate_rule(&rule, "git-lfs", &[]);
        assert!(effect.is_some());
    }

    #[test]
    fn list_command_match() {
        let rule = Rule {
            command: CommandMatcher::List(vec!["cat".into(), "bat".into()]),
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (_, effect) = annotate_rule(&rule, "bat", &[]);
        assert!(effect.is_some());
    }

    // ── Or/Not matcher ──────────────────────────────────────────────

    #[test]
    fn or_matcher_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Or(vec![
                    ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal("push".into()))]),
                    ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal("pull".into()))]),
                ])),
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (_, effect) = annotate_rule(&rule, "git", &[lit("pull")]);
        assert!(effect.is_some());
    }

    #[test]
    fn not_matcher_inverts() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Not(Box::new(
                    ArgMatcher::Anywhere(vec![Expr::Literal("--force".into())]),
                ))),
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (_, effect) = annotate_rule(&rule, "git", &[lit("push")]);
        assert!(effect.is_some()); // no --force, so not(anywhere --force) matches
    }

    // ── And matcher ─────────────────────────────────────────────────

    #[test]
    fn and_matcher_both_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::And(vec![
                    ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal("push".into()))]),
                    ArgMatcher::Anywhere(vec![Expr::Literal("--force".into())]),
                ])),
                effect: Effect { decision: Decision::Deny, reason: Some("force push".into()) },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (_, effect) = annotate_rule(&rule, "git", &[lit("push"), lit("--force")]);
        assert_eq!(effect.unwrap().decision, Decision::Deny);
    }

    #[test]
    fn and_matcher_first_fails() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::And(vec![
                    ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal("push".into()))]),
                    ArgMatcher::Anywhere(vec![Expr::Literal("--force".into())]),
                ])),
                effect: Effect { decision: Decision::Deny, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (_, effect) = annotate_rule(&rule, "git", &[lit("pull")]);
        assert!(effect.is_none());
    }

    // ── Exact positional ────────────────────────────────────────────

    #[test]
    fn exact_positional_extra_args() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::ExactPositional(vec![
                    PosExpr::one(Expr::Literal("push".into())),
                ])),
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let args = vec![lit("push"), lit("origin")];
        let (doc, effect) = annotate_rule(&rule, "git", &args);
        assert!(effect.is_none()); // extra arg "origin"

        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|a| matches!(a, EvalAnn::ExactRemainder { count: 1 })));
    }

    // ── Optional quantifier ─────────────────────────────────────────

    #[test]
    fn optional_arg_present() {
        let rule = Rule {
            command: CommandMatcher::Exact("cmd".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![
                    PosExpr { quantifier: Quantifier::Optional, expr: Expr::Literal("opt".into()) },
                    PosExpr::one(Expr::Literal("req".into())),
                ])),
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (_, effect) = annotate_rule(&rule, "cmd", &[lit("opt"), lit("req")]);
        assert!(effect.is_some());
    }

    #[test]
    fn optional_arg_absent() {
        let rule = Rule {
            command: CommandMatcher::Exact("cmd".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![
                    PosExpr { quantifier: Quantifier::Optional, expr: Expr::Literal("opt".into()) },
                    PosExpr::one(Expr::Literal("req".into())),
                ])),
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (_, effect) = annotate_rule(&rule, "cmd", &[lit("req")]);
        assert!(effect.is_some());
    }

    // ── Opaque args ─────────────────────────────────────────────────

    #[test]
    fn opaque_arg_matches_wildcard() {
        let rule = Rule {
            command: CommandMatcher::Exact("cmd".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![
                    PosExpr::one(Expr::Wildcard),
                ])),
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (_, effect) = annotate_rule(&rule, "cmd", &[ResolvedArg::Opaque]);
        assert!(effect.is_some());
    }

    #[test]
    fn opaque_arg_rejects_literal() {
        let rule = Rule {
            command: CommandMatcher::Exact("cmd".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![
                    PosExpr::one(Expr::Literal("specific".into())),
                ])),
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (_, effect) = annotate_rule(&rule, "cmd", &[ResolvedArg::Opaque]);
        assert!(effect.is_none());
    }

    // ── Expr Or/Not ─────────────────────────────────────────────────

    #[test]
    fn expr_or_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("cmd".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![
                    PosExpr::one(Expr::Or(vec![
                        Expr::Literal("a".into()),
                        Expr::Literal("b".into()),
                    ])),
                ])),
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (_, effect) = annotate_rule(&rule, "cmd", &[lit("b")]);
        assert!(effect.is_some());
    }

    #[test]
    fn expr_not_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("cmd".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![
                    PosExpr::one(Expr::Not(Box::new(Expr::Literal("bad".into())))),
                ])),
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (_, effect) = annotate_rule(&rule, "cmd", &[lit("good")]);
        assert!(effect.is_some());
    }

    // ── Branching (body-level) ──────────────────────────────────────

    #[test]
    fn branching_no_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            body: RuleBody::Branching(ArgMatcher::Cond(CondArm {
                branches: vec![CondBranch {
                    matcher: ArgMatcher::Anywhere(vec![Expr::Literal("--force".into())]),
                    effect: deny("force push"),
                }],
                fallback: None,
            })),
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (_, effect) = annotate_rule(&rule, "git", &[lit("push")]);
        assert!(effect.is_none());
    }

    // ── Expr-level cond with opaque ─────────────────────────────────

    #[test]
    fn expr_cond_opaque_no_match() {
        let cond_expr = Expr::Cond(vec![
            ExprBranch {
                test: Expr::Literal("safe".into()),
                effect: allow("safe arg"),
            },
        ]);
        let rule = Rule {
            command: CommandMatcher::Exact("cmd".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![PosExpr::one(cond_expr)])),
                effect: Effect { decision: Decision::Ask, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (_, effect) = annotate_rule(&rule, "cmd", &[ResolvedArg::Opaque]);
        assert!(effect.is_none());
    }

    // ── Structure preservation ───────────────────────────────────────

    #[test]
    fn structure_matches_to_doc() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![
                    PosExpr::one(Expr::Literal("push".into())),
                    PosExpr { quantifier: Quantifier::ZeroOrMore, expr: Expr::Wildcard },
                ])),
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let args = vec![lit("push"), lit("origin")];
        let (annotated, _) = annotate_rule(&rule, "git", &args);

        // The annotated doc should have the same structure as the plain to_doc
        assert_same_structure(&annotated, &rule.to_doc());
    }
}
