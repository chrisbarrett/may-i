// Annotated document builder for rule evaluation.
//
// Produces `Doc<Option<EvalAnn>>` trees where each node carries an optional
// evaluation annotation. Nodes that the evaluator visited get `Some(ann)`;
// structural scaffolding gets `None`. The renderer can then fold these
// annotated trees to produce two-column trace output.

use may_i_core::legacy::{
    ArgMatcher, BoolExpr, CommandMatcher, CondArm, ContextExpr, ContextFacts, ContextFailureReason,
    ContextValue, Effect, EvalAnn, Expr, ExprBranch, FactPattern, FactPatternEval, FactQuery,
    MatcherCondPredicate, PolymorphicCondArm, PosExpr, Rule, RuleBody,
};
use may_i_core::{Doc, DocF, LayoutHint};

use crate::matcher::{
    MatchOutcome, ResolvedArg, command_matches, expr_matches_resolved, extract_positional_args,
};

/// Annotated Doc: each node optionally carries an evaluation annotation.
pub(crate) type ADoc = Doc<Option<EvalAnn>>;

// ── Constructors ──────────────────────────────────────────────────

fn atom(s: impl Into<String>) -> ADoc {
    Doc {
        ann: None,
        node: DocF::Atom(s.into()),
        layout: LayoutHint::Auto,
        dimmed: false,
    }
}

fn list(children: Vec<ADoc>) -> ADoc {
    Doc {
        ann: None,
        node: DocF::List(children),
        layout: LayoutHint::Auto,
        dimmed: false,
    }
}

fn vector(children: Vec<ADoc>) -> ADoc {
    Doc {
        ann: None,
        node: DocF::Vector(children),
        layout: LayoutHint::Auto,
        dimmed: false,
    }
}

fn ann_list(ann: EvalAnn, children: Vec<ADoc>) -> ADoc {
    Doc {
        ann: Some(ann),
        node: DocF::List(children),
        layout: LayoutHint::Auto,
        dimmed: false,
    }
}

/// Convert an unannotated Doc<()> to Doc<Option<EvalAnn>> (all None).
fn unannotate(doc: Doc<()>) -> ADoc {
    doc.map(&|()| None)
}

/// Post-process an annotated Doc tree: mark any list as AlwaysBreak
/// when multiple children (or their subtrees) carry visible annotations,
/// so the pp keeps each annotated subtree on its own line for trace alignment.
fn propagate_break_hints(doc: ADoc) -> ADoc {
    let ann = doc.ann;
    let layout_hint = doc.layout;
    match doc.node {
        DocF::Atom(text) => Doc {
            ann,
            node: DocF::Atom(text),
            layout: layout_hint,
            dimmed: false,
        },
        DocF::List(children) => {
            let children: Vec<ADoc> = children.into_iter().map(propagate_break_hints).collect();
            let visible_ann_count = children
                .iter()
                .filter(|c| subtree_has_visible_annotation(c))
                .count();
            let layout = if visible_ann_count > 1 {
                LayoutHint::AlwaysBreak
            } else {
                layout_hint
            };
            Doc {
                ann,
                node: DocF::List(children),
                layout,
                dimmed: false,
            }
        }
        DocF::Vector(children) => {
            let children: Vec<ADoc> = children.into_iter().map(propagate_break_hints).collect();
            let visible_ann_count = children
                .iter()
                .filter(|c| subtree_has_visible_annotation(c))
                .count();
            let layout = if visible_ann_count > 1 {
                LayoutHint::AlwaysBreak
            } else {
                layout_hint
            };
            Doc {
                ann,
                node: DocF::Vector(children),
                layout,
                dimmed: false,
            }
        }
    }
}

/// True if this annotation produces right-column output in the trace.
fn is_visible_annotation(ann: &EvalAnn) -> bool {
    !matches!(
        ann,
        EvalAnn::CommandMatch(_) | EvalAnn::ArgsResult(_) | EvalAnn::RuleEffect { .. }
    )
}

/// True if this node or any descendant carries a visible annotation.
fn subtree_has_visible_annotation(doc: &ADoc) -> bool {
    if doc.ann.as_ref().is_some_and(is_visible_annotation) {
        return true;
    }
    if let DocF::List(children) | DocF::Vector(children) = &doc.node {
        children.iter().any(subtree_has_visible_annotation)
    } else {
        false
    }
}

fn arg_to_string(a: &ResolvedArg) -> String {
    match a {
        ResolvedArg::Literal(s) => format!("\"{s}\""),
        ResolvedArg::Opaque => "<opaque>".into(),
    }
}

fn dim_doc(doc: ADoc) -> ADoc {
    let children = match doc.node {
        DocF::Atom(text) => {
            return Doc {
                ann: doc.ann,
                node: DocF::Atom(text),
                layout: doc.layout,
                dimmed: true,
            };
        }
        DocF::List(children) => DocF::List(children.into_iter().map(dim_doc).collect()),
        DocF::Vector(children) => DocF::Vector(children.into_iter().map(dim_doc).collect()),
    };

    Doc {
        ann: doc.ann,
        node: children,
        layout: doc.layout,
        dimmed: true,
    }
}

fn fact_pattern_doc(pattern: &FactPattern) -> ADoc {
    unannotate(pattern.to_doc())
}

fn unevaluated_pattern_eval(pattern: &FactPattern) -> FactPatternEval {
    match pattern {
        FactPattern::Literal(value) => FactPatternEval::Literal {
            value: value.clone(),
            evaluated: false,
            matched: false,
        },
        FactPattern::Wildcard => FactPatternEval::Wildcard {
            evaluated: false,
            matched: false,
        },
        FactPattern::Regex(regex) => FactPatternEval::Regex {
            pattern: regex.as_str().to_string(),
            evaluated: false,
            matched: false,
        },
        FactPattern::And(patterns) => FactPatternEval::And {
            evaluated: false,
            matched: false,
            children: patterns.iter().map(unevaluated_pattern_eval).collect(),
        },
        FactPattern::Or(patterns) => FactPatternEval::Or {
            evaluated: false,
            matched: false,
            children: patterns.iter().map(unevaluated_pattern_eval).collect(),
        },
        FactPattern::Not(pattern) => FactPatternEval::Not {
            evaluated: false,
            matched: false,
            child: Box::new(unevaluated_pattern_eval(pattern)),
        },
    }
}

struct PatternOutcome {
    doc: ADoc,
    eval: FactPatternEval,
    matched: bool,
    decisive_source: String,
}

fn annotate_fact_pattern(pattern: &FactPattern, actual: &str) -> PatternOutcome {
    match pattern {
        FactPattern::Literal(value) => PatternOutcome {
            doc: fact_pattern_doc(pattern),
            eval: FactPatternEval::Literal {
                value: value.clone(),
                evaluated: true,
                matched: actual == value,
            },
            matched: actual == value,
            decisive_source: pattern.to_source(),
        },
        FactPattern::Wildcard => PatternOutcome {
            doc: fact_pattern_doc(pattern),
            eval: FactPatternEval::Wildcard {
                evaluated: true,
                matched: true,
            },
            matched: true,
            decisive_source: pattern.to_source(),
        },
        FactPattern::Regex(regex) => PatternOutcome {
            doc: fact_pattern_doc(pattern),
            eval: FactPatternEval::Regex {
                pattern: regex.as_str().to_string(),
                evaluated: true,
                matched: regex.is_match(actual),
            },
            matched: regex.is_match(actual),
            decisive_source: pattern.to_source(),
        },
        FactPattern::And(patterns) => {
            let mut docs = vec![atom("and")];
            let mut evals = Vec::with_capacity(patterns.len());
            let mut decisive = String::new();
            let mut matched = true;

            for (idx, child) in patterns.iter().enumerate() {
                if matched {
                    let outcome = annotate_fact_pattern(child, actual);
                    matched = outcome.matched;
                    decisive = outcome.decisive_source.clone();
                    docs.push(outcome.doc);
                    evals.push(outcome.eval);
                    if !matched {
                        for remaining in &patterns[idx + 1..] {
                            docs.push(dim_doc(fact_pattern_doc(remaining)));
                            evals.push(unevaluated_pattern_eval(remaining));
                        }
                        break;
                    }
                }
            }

            PatternOutcome {
                doc: list(docs),
                eval: FactPatternEval::And {
                    evaluated: true,
                    matched,
                    children: evals,
                },
                matched,
                decisive_source: decisive,
            }
        }
        FactPattern::Or(patterns) => {
            let mut docs = vec![atom("or")];
            let mut evals = Vec::with_capacity(patterns.len());
            let mut decisive = String::new();
            let mut matched = false;

            for (idx, child) in patterns.iter().enumerate() {
                if !matched {
                    let outcome = annotate_fact_pattern(child, actual);
                    matched = outcome.matched;
                    decisive = outcome.decisive_source.clone();
                    docs.push(outcome.doc);
                    evals.push(outcome.eval);
                    if matched {
                        for remaining in &patterns[idx + 1..] {
                            docs.push(dim_doc(fact_pattern_doc(remaining)));
                            evals.push(unevaluated_pattern_eval(remaining));
                        }
                        break;
                    }
                }
            }

            PatternOutcome {
                doc: list(docs),
                eval: FactPatternEval::Or {
                    evaluated: true,
                    matched,
                    children: evals,
                },
                matched,
                decisive_source: decisive,
            }
        }
        FactPattern::Not(child) => {
            let outcome = annotate_fact_pattern(child, actual);
            PatternOutcome {
                doc: list(vec![atom("not"), outcome.doc]),
                eval: FactPatternEval::Not {
                    evaluated: true,
                    matched: !outcome.matched,
                    child: Box::new(outcome.eval),
                },
                matched: !outcome.matched,
                decisive_source: outcome.decisive_source,
            }
        }
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
    context: &ContextFacts,
) -> (ADoc, Option<Effect>) {
    let cmd_matched = command_matches(cmd_name, &rule.command);
    let cmd_doc = annotate_command(&rule.command, cmd_name, cmd_matched);

    if !cmd_matched {
        let mut cs = vec![atom("rule"), cmd_doc];
        if let Some(context_expr) = &rule.context {
            cs.push(list(vec![
                atom("context"),
                unannotate(context_expr.to_doc()),
            ]));
        }
        for d in rule.body.to_doc() {
            cs.push(unannotate(d));
        }
        return (list(cs), None);
    }

    let (context_doc, context_matched) = if let Some(context_expr) = &rule.context {
        let (doc, matched) = annotate_context_expr(context_expr, context);
        (
            Some(ann_list(
                EvalAnn::ContextResult(matched),
                vec![atom("context"), doc],
            )),
            matched,
        )
    } else {
        (None, true)
    };

    if !context_matched {
        let mut cs = vec![atom("rule"), cmd_doc];
        if let Some(doc) = context_doc {
            cs.push(doc);
        }
        for d in rule.body.to_doc() {
            cs.push(unannotate(d));
        }
        return (propagate_break_hints(list(cs)), None);
    }

    let (body_docs, effect) = annotate_body(&rule.body, expanded_args, context);
    let mut cs = vec![atom("rule"), cmd_doc];
    if let Some(doc) = context_doc {
        cs.push(doc);
    }
    cs.extend(body_docs);

    let ann = effect.as_ref().map(|e| EvalAnn::RuleEffect {
        decision: e.decision,
        reason: e.reason.clone(),
    });
    let doc = Doc {
        ann,
        node: DocF::List(cs),
        layout: LayoutHint::Auto,
        dimmed: false,
    };
    (propagate_break_hints(doc), effect)
}

fn annotate_context_expr(expr: &ContextExpr, facts: &ContextFacts) -> (ADoc, bool) {
    match expr {
        ContextExpr::Alias(name) => {
            // Aliases should be resolved during parsing (see parse/mod.rs:resolve_context_expr).
            // Reaching here indicates the config was constructed programmatically without
            // resolution, or there's a bug in the parser. We treat it as non-matching.
            let matched = false;
            (
                Doc {
                    ann: Some(EvalAnn::ContextResult(matched)),
                    node: DocF::Atom(name.clone()),
                    layout: LayoutHint::Auto,
                    dimmed: false,
                },
                matched,
            )
        }
        ContextExpr::Has(query) => annotate_context_has(query, facts),
        ContextExpr::And(exprs) => {
            let mut matched = true;
            let mut children = vec![atom("and")];
            for expr in exprs {
                let (doc, child_match) = annotate_context_expr(expr, facts);
                matched &= child_match;
                children.push(doc);
            }
            (
                Doc {
                    ann: Some(EvalAnn::ContextResult(matched)),
                    node: DocF::List(children),
                    layout: LayoutHint::Auto,
                    dimmed: false,
                },
                matched,
            )
        }
        ContextExpr::Or(exprs) => {
            let mut matched = false;
            let mut children = vec![atom("or")];
            for expr in exprs {
                let (doc, child_match) = annotate_context_expr(expr, facts);
                matched |= child_match;
                children.push(doc);
            }
            (
                Doc {
                    ann: Some(EvalAnn::ContextResult(matched)),
                    node: DocF::List(children),
                    layout: LayoutHint::Auto,
                    dimmed: false,
                },
                matched,
            )
        }
        ContextExpr::Not(expr) => {
            let (doc, child_match) = annotate_context_expr(expr, facts);
            let matched = !child_match;
            (
                Doc {
                    ann: Some(EvalAnn::ContextResult(matched)),
                    node: DocF::List(vec![atom("not"), doc]),
                    layout: LayoutHint::Auto,
                    dimmed: false,
                },
                matched,
            )
        }
    }
}

fn annotate_context_has(query: &FactQuery, facts: &ContextFacts) -> (ADoc, bool) {
    let source = format!("(has {})", query.to_source());
    match query {
        FactQuery::Presence { key, vector_syntax } => {
            let matched = facts.has(key);
            let query_doc = if *vector_syntax {
                vector(vec![atom(key.clone())])
            } else {
                atom(key.clone())
            };
            (
                ann_list(
                    EvalAnn::ContextHasPresence {
                        key: key.clone(),
                        source,
                        matched,
                    },
                    vec![atom("has"), query_doc],
                ),
                matched,
            )
        }
        FactQuery::Value { key, pattern } => {
            let fact = facts.get(key);
            match fact {
                Some(ContextValue::Scalar(actual)) => {
                    if pattern.is_literal() {
                        let expected = match pattern {
                            FactPattern::Literal(value) => value.clone(),
                            _ => unreachable!(),
                        };
                        let matched = actual == &expected;
                        (
                            ann_list(
                                EvalAnn::ContextHasExact {
                                    key: key.clone(),
                                    source,
                                    expected: expected.clone(),
                                    actual: Some(actual.clone()),
                                    matched,
                                    reason: (!matched)
                                        .then_some(ContextFailureReason::ValueMismatch),
                                    search_needle: format!("\"{expected}\""),
                                },
                                vec![
                                    atom("has"),
                                    vector(vec![
                                        atom(key.clone()),
                                        atom(format!("\"{expected}\"")),
                                    ]),
                                ],
                            ),
                            matched,
                        )
                    } else {
                        let outcome = annotate_fact_pattern(pattern, actual);
                        (
                            ann_list(
                                EvalAnn::ContextHasPattern {
                                    key: key.clone(),
                                    source,
                                    pattern_source: pattern.to_source(),
                                    pattern: pattern.clone(),
                                    pattern_eval: outcome.eval,
                                    actual: Some(actual.clone()),
                                    matched: outcome.matched,
                                    reason: (!outcome.matched)
                                        .then_some(ContextFailureReason::PatternMismatch),
                                    search_needle: outcome.decisive_source,
                                },
                                vec![atom("has"), vector(vec![atom(key.clone()), outcome.doc])],
                            ),
                            outcome.matched,
                        )
                    }
                }
                Some(ContextValue::Present) | None => {
                    let reason = match fact {
                        Some(ContextValue::Present) => ContextFailureReason::PresentWithoutScalar,
                        None => ContextFailureReason::Absent,
                        Some(ContextValue::Scalar(_)) => unreachable!(),
                    };
                    let pattern_doc = if pattern.is_literal() {
                        atom(format!(
                            "\"{}\"",
                            match pattern {
                                FactPattern::Literal(value) => value,
                                _ => unreachable!(),
                            }
                        ))
                    } else {
                        dim_doc(fact_pattern_doc(pattern))
                    };
                    let ann = if pattern.is_literal() {
                        EvalAnn::ContextHasExact {
                            key: key.clone(),
                            source,
                            expected: match pattern {
                                FactPattern::Literal(value) => value.clone(),
                                _ => unreachable!(),
                            },
                            actual: None,
                            matched: false,
                            reason: Some(reason),
                            search_needle: key.clone(),
                        }
                    } else {
                        EvalAnn::ContextHasPattern {
                            key: key.clone(),
                            source,
                            pattern_source: pattern.to_source(),
                            pattern: pattern.clone(),
                            pattern_eval: unevaluated_pattern_eval(pattern),
                            actual: None,
                            matched: false,
                            reason: Some(reason),
                            search_needle: key.clone(),
                        }
                    };
                    (
                        ann_list(
                            ann,
                            vec![atom("has"), vector(vec![atom(key.clone()), pattern_doc])],
                        ),
                        false,
                    )
                }
            }
        }
    }
}

fn annotate_command(matcher: &CommandMatcher, cmd_name: &str, matched: bool) -> ADoc {
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
            let mut or_cs: Vec<ADoc> = vec![atom("or")];
            or_cs.extend(names.iter().map(|n| {
                let a = atom(format!("\"{n}\""));
                if matched && n == cmd_name {
                    // Mark the matching entry so it survives truncation
                    // and shows which command was matched.
                    Doc {
                        ann: Some(EvalAnn::CommandMatch(true)),
                        ..a
                    }
                } else {
                    a
                }
            }));
            vec![atom("command"), list(or_cs)]
        }
    };
    ann_list(ann, children)
}

fn annotate_body(
    body: &RuleBody,
    args: &[ResolvedArg],
    facts: &ContextFacts,
) -> (Vec<ADoc>, Option<Effect>) {
    match body {
        RuleBody::Effect {
            matcher: None,
            effect,
        } => {
            let effect_doc = annotate_effect(effect);
            (vec![effect_doc], Some(effect.clone()))
        }
        RuleBody::Effect {
            matcher: Some(m),
            effect,
        } => {
            let (matcher_doc, outcome) = annotate_matcher(m, args, facts);
            let matched = outcome.is_match();
            let args_doc = ann_list(
                EvalAnn::ArgsResult(matched),
                vec![atom("args"), matcher_doc],
            );
            let (effect_doc, final_effect) = if matched {
                let eff = if let MatchOutcome::Matched(eff) = outcome {
                    eff
                } else {
                    effect.clone()
                };
                (annotate_effect(&eff), Some(eff))
            } else {
                (unannotate_effect(effect), None)
            };
            (vec![args_doc, effect_doc], final_effect)
        }
        RuleBody::Branching(m) => {
            let (matcher_doc, outcome) = annotate_matcher(m, args, facts);
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
    let mut cs = vec![atom("effect"), atom(format!(":{}", effect.decision))];
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

/// Build an unannotated effect node (for display when the effect was never reached).
fn unannotate_effect(effect: &Effect) -> ADoc {
    let mut cs = vec![atom("effect"), atom(format!(":{}", effect.decision))];
    if let Some(r) = &effect.reason {
        cs.push(atom(format!("\"{r}\"")));
    }
    list(cs)
}

// ── Matcher annotation ────────────────────────────────────────────

pub(crate) fn annotate_matcher(
    matcher: &ArgMatcher,
    args: &[ResolvedArg],
    facts: &ContextFacts,
) -> (ADoc, MatchOutcome) {
    match matcher {
        ArgMatcher::Positional(patterns) => annotate_positional(patterns, args, false),
        ArgMatcher::ExactPositional(patterns) => annotate_positional(patterns, args, true),
        ArgMatcher::Anywhere(tokens) => annotate_anywhere(tokens, args),
        ArgMatcher::And(matchers) => annotate_matcher_and(matchers, args, facts),
        ArgMatcher::Or(matchers) => annotate_matcher_or(matchers, args, facts),
        ArgMatcher::Not(inner) => annotate_matcher_not(inner, args, facts),
        ArgMatcher::Cond(arm) => annotate_matcher_cond(arm, args, facts),
        ArgMatcher::Has(bool_expr) => annotate_matcher_has(bool_expr, facts),
        ArgMatcher::When(arm) => annotate_matcher_when(arm, args, facts),
        ArgMatcher::Unless(arm) => annotate_matcher_unless(arm, args, facts),
        ArgMatcher::If {
            test,
            then_effect,
            else_effect,
        } => annotate_matcher_if(test, then_effect, else_effect.as_ref(), args, facts),
    }
}

fn annotate_matcher_and(
    matchers: &[ArgMatcher],
    args: &[ResolvedArg],
    facts: &ContextFacts,
) -> (ADoc, MatchOutcome) {
    let mut cs = vec![atom("and")];
    let mut first_effect: Option<Effect> = None;
    let mut all_matched = true;

    for m in matchers {
        if all_matched {
            let (doc, outcome) = annotate_matcher(m, args, facts);
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
    facts: &ContextFacts,
) -> (ADoc, MatchOutcome) {
    let mut cs = vec![atom("or")];
    let mut result = MatchOutcome::NoMatch;
    let mut found = false;

    for m in matchers {
        if !found {
            let (doc, outcome) = annotate_matcher(m, args, facts);
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
    facts: &ContextFacts,
) -> (ADoc, MatchOutcome) {
    let (inner_doc, inner_outcome) = annotate_matcher(inner, args, facts);
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
    facts: &ContextFacts,
) -> (ADoc, MatchOutcome) {
    let mut cs = vec![atom("cond")];

    for branch in &arm.branches {
        let (matcher_doc, outcome) = annotate_matcher(&branch.matcher, args, facts);
        let matched = outcome.is_match();
        let effect_doc = annotate_effect(&branch.effect);
        let branch_ann = if matched {
            Some(EvalAnn::CondBranch {
                decision: branch.effect.decision,
            })
        } else {
            None
        };
        cs.push(Doc {
            ann: branch_ann,
            node: DocF::List(vec![matcher_doc, effect_doc]),
            layout: LayoutHint::Auto,
            dimmed: false,
        });
        if matched {
            // Remaining branches unannotated
            return (list(cs), MatchOutcome::Matched(branch.effect.clone()));
        }
    }

    if let Some(fallback) = &arm.fallback {
        let effect_doc = annotate_effect(fallback);
        cs.push(ann_list(
            EvalAnn::CondElse {
                decision: fallback.decision,
            },
            vec![atom("else"), effect_doc],
        ));
        return (list(cs), MatchOutcome::Matched(fallback.clone()));
    }

    (list(cs), MatchOutcome::NoMatch)
}

/// Evaluate a BoolExpr against context facts.
fn bool_expr_matches(expr: &BoolExpr, facts: &ContextFacts) -> bool {
    match expr {
        BoolExpr::Has(query) => match query {
            FactQuery::Presence { key, .. } => facts.has(key),
            FactQuery::Value { key, pattern } => {
                if let Some(ContextValue::Scalar(value)) = facts.get(key) {
                    match pattern {
                        FactPattern::Literal(s) => value == s,
                        FactPattern::Wildcard => true,
                        FactPattern::Regex(re) => re.is_match(value),
                        _ => false, // And/Or/Not patterns not supported in BoolExpr context
                    }
                } else {
                    false
                }
            }
        },
        BoolExpr::And(exprs) => exprs.iter().all(|e| bool_expr_matches(e, facts)),
        BoolExpr::Or(exprs) => exprs.iter().any(|e| bool_expr_matches(e, facts)),
        BoolExpr::Not(expr) => !bool_expr_matches(expr, facts),
    }
}

fn annotate_matcher_has(bool_expr: &BoolExpr, facts: &ContextFacts) -> (ADoc, MatchOutcome) {
    let matched = bool_expr_matches(bool_expr, facts);
    // BoolExpr::Has already renders as (has ...), so don't wrap it again
    let doc = unannotate(bool_expr.to_doc());
    // Has doesn't carry an effect - it's just a boolean check
    let outcome = if matched {
        MatchOutcome::MatchedNoEffect
    } else {
        MatchOutcome::NoMatch
    };
    (doc, outcome)
}

fn annotate_matcher_when(
    arm: &PolymorphicCondArm,
    args: &[ResolvedArg],
    facts: &ContextFacts,
) -> (ADoc, MatchOutcome) {
    let mut cs = vec![atom("when")];

    for branch in &arm.branches {
        let (pred_doc, matched) = annotate_polymorphic_predicate(&branch.predicate, args, facts);
        let effect_doc = annotate_effect(&branch.effect);
        let branch_ann = if matched {
            Some(EvalAnn::CondBranch {
                decision: branch.effect.decision,
            })
        } else {
            None
        };
        cs.push(Doc {
            ann: branch_ann,
            node: DocF::List(vec![pred_doc, effect_doc]),
            layout: LayoutHint::Auto,
            dimmed: false,
        });
        if matched {
            return (list(cs), MatchOutcome::Matched(branch.effect.clone()));
        }
    }

    if let Some(fallback) = &arm.fallback {
        let effect_doc = annotate_effect(fallback);
        cs.push(ann_list(
            EvalAnn::CondElse {
                decision: fallback.decision,
            },
            vec![atom("else"), effect_doc],
        ));
        return (list(cs), MatchOutcome::Matched(fallback.clone()));
    }

    (list(cs), MatchOutcome::NoMatch)
}

fn annotate_matcher_unless(
    arm: &PolymorphicCondArm,
    args: &[ResolvedArg],
    facts: &ContextFacts,
) -> (ADoc, MatchOutcome) {
    let mut cs = vec![atom("unless")];

    for branch in &arm.branches {
        let (pred_doc, matched) = annotate_polymorphic_predicate(&branch.predicate, args, facts);
        let effect_doc = annotate_effect(&branch.effect);
        // Unless matches when predicate is FALSE
        let branch_matched = !matched;
        let branch_ann = if branch_matched {
            Some(EvalAnn::CondBranch {
                decision: branch.effect.decision,
            })
        } else {
            None
        };
        cs.push(Doc {
            ann: branch_ann,
            node: DocF::List(vec![pred_doc, effect_doc]),
            layout: LayoutHint::Auto,
            dimmed: false,
        });
        if branch_matched {
            return (list(cs), MatchOutcome::Matched(branch.effect.clone()));
        }
    }

    if let Some(fallback) = &arm.fallback {
        let effect_doc = annotate_effect(fallback);
        cs.push(ann_list(
            EvalAnn::CondElse {
                decision: fallback.decision,
            },
            vec![atom("else"), effect_doc],
        ));
        return (list(cs), MatchOutcome::Matched(fallback.clone()));
    }

    (list(cs), MatchOutcome::NoMatch)
}

fn annotate_matcher_if(
    test: &MatcherCondPredicate,
    then_effect: &Effect,
    else_effect: Option<&Effect>,
    args: &[ResolvedArg],
    facts: &ContextFacts,
) -> (ADoc, MatchOutcome) {
    let (test_doc, test_matched) = annotate_polymorphic_predicate(test, args, facts);
    let then_doc = annotate_effect(then_effect);

    let mut cs = vec![atom("if"), test_doc, then_doc];

    if test_matched {
        (list(cs), MatchOutcome::Matched(then_effect.clone()))
    } else if let Some(else_eff) = else_effect {
        let else_doc = annotate_effect(else_eff);
        cs.push(else_doc);
        (list(cs), MatchOutcome::Matched(else_eff.clone()))
    } else {
        (list(cs), MatchOutcome::NoMatch)
    }
}

/// Annotate a polymorphic predicate and return whether it matched.
fn annotate_polymorphic_predicate(
    predicate: &MatcherCondPredicate,
    args: &[ResolvedArg],
    facts: &ContextFacts,
) -> (ADoc, bool) {
    match predicate {
        MatcherCondPredicate::Matcher(m) => {
            let (doc, outcome) = annotate_matcher(m, args, facts);
            (doc, outcome.is_match())
        }
        MatcherCondPredicate::Expr(e) => {
            // For Expr predicates in matcher context, we check if any arg matches
            // This is a bit ambiguous - for now, check if any arg matches the expression
            let matched = args.iter().any(|arg| match arg {
                ResolvedArg::Literal(s) => e.is_match(s),
                ResolvedArg::Opaque => e.is_wildcard(),
            });
            let doc = unannotate(e.to_doc());
            (doc, matched)
        }
        MatcherCondPredicate::BoolExpr(b) => {
            let matched = bool_expr_matches(b, facts);
            let doc = unannotate(b.to_doc());
            (doc, matched)
        }
    }
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
                        cs.push(Doc {
                            ann: Some(EvalAnn::Missing),
                            ..inner
                        });
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
            dimmed: false,
        };
        return (doc, MatchOutcome::NoMatch);
    }

    let outcome = match first_effect {
        Some(eff) => MatchOutcome::Matched(eff),
        None => MatchOutcome::MatchedNoEffect,
    };

    if exact {
        let pattern_strs: Vec<String> = patterns.iter().map(|p| p.expr.to_string()).collect();
        let arg_strs: Vec<String> = positional.iter().map(arg_to_string).collect();
        let matched = outcome.is_match();
        let doc = ann_list(
            EvalAnn::ExactArgs {
                patterns: pattern_strs,
                args: arg_strs,
                matched,
            },
            cs,
        );
        return (doc, outcome);
    }

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

fn annotate_anywhere(tokens: &[Expr], args: &[ResolvedArg]) -> (ADoc, MatchOutcome) {
    let mut cs = vec![atom("anywhere")];
    let args_strs: Vec<String> = args.iter().map(arg_to_string).collect();

    for token in tokens {
        let matched = args.iter().any(|a| expr_matches_resolved(token, a));
        let token_doc_inner = unannotate(token.to_doc());
        let token_doc = Doc {
            ann: Some(EvalAnn::Anywhere {
                args: args_strs.clone(),
                matched,
            }),
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

pub(crate) fn annotate_expr_arg(expr: &Expr, arg: &ResolvedArg) -> (ADoc, MatchOutcome) {
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
                ann: Some(EvalAnn::ExprVsArg {
                    arg: arg_str,
                    matched,
                }),
                node: DocF::List(vec![atom("not"), inner_doc]),
                layout: LayoutHint::Auto,
                dimmed: false,
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
                ann: Some(EvalAnn::ExprVsArg {
                    arg: arg_str,
                    matched,
                }),
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
        } // Cond handled at the top of the function
    }
}

fn annotate_expr_cond(branches: &[ExprBranch], arg: &ResolvedArg) -> (ADoc, MatchOutcome) {
    let mut cs = vec![atom("cond")];

    match arg {
        ResolvedArg::Literal(s) => {
            for branch in branches {
                let matched = branch.test.is_match(s);
                let test_doc = unannotate(branch.test.to_doc());
                let effect_doc = annotate_effect(&branch.effect);
                let branch_doc = if matched {
                    ann_list(
                        EvalAnn::CondBranch {
                            decision: branch.effect.decision,
                        },
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
    use may_i_core::{
        CondBranch, Decision, MatcherCondPredicate, PolymorphicCondBranch, Quantifier, Span,
    };

    fn lit(s: &str) -> ResolvedArg {
        ResolvedArg::Literal(s.into())
    }

    fn allow(reason: &str) -> Effect {
        Effect {
            decision: Decision::Allow,
            reason: Some(reason.into()),
        }
    }

    fn deny(reason: &str) -> Effect {
        Effect {
            decision: Decision::Deny,
            reason: Some(reason.into()),
        }
    }

    /// Collect all annotations from an annotated Doc tree.
    fn collect_annotations(doc: &ADoc) -> Vec<EvalAnn> {
        doc.fold(&|node, ann: &Option<EvalAnn>| {
            let mut result: Vec<EvalAnn> = Vec::new();
            if let Some(a) = ann {
                result.push(a.clone());
            }
            if let DocF::List(children) | DocF::Vector(children) = node {
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
            DocF::Vector(cs) => format!("[{}]", cs.join(" ")),
        });
        let plain_str = plain.fold(&|node, _: &()| match node {
            DocF::Atom(s) => s,
            DocF::List(cs) => format!("({})", cs.join(" ")),
            DocF::Vector(cs) => format!("[{}]", cs.join(" ")),
        });
        assert_eq!(ann_str, plain_str);
    }

    fn empty_context() -> ContextFacts {
        ContextFacts::default()
    }

    fn annotate_rule(
        rule: &Rule,
        cmd_name: &str,
        expanded_args: &[ResolvedArg],
    ) -> (ADoc, Option<Effect>) {
        super::annotate_rule(rule, cmd_name, expanded_args, &empty_context())
    }

    fn annotate_rule_with_context(
        rule: &Rule,
        cmd_name: &str,
        expanded_args: &[ResolvedArg],
        context: &ContextFacts,
    ) -> (ADoc, Option<Effect>) {
        super::annotate_rule(rule, cmd_name, expanded_args, context)
    }

    // ── Simple rule (no args) ───────────────────────────────────────

    #[test]
    fn simple_allow_rule() {
        let rule = Rule {
            command: CommandMatcher::Exact("ls".into()),
            context: None,
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (doc, effect) = annotate_rule(&rule, "ls", &[]);
        assert!(effect.is_some());
        assert_eq!(effect.unwrap().decision, Decision::Allow);

        let anns = collect_annotations(&doc);
        assert!(
            anns.iter()
                .any(|a| matches!(a, EvalAnn::CommandMatch(true)))
        );
        assert!(anns.iter().any(|a| matches!(
            a,
            EvalAnn::RuleEffect {
                decision: Decision::Allow,
                ..
            }
        )));
    }

    #[test]
    fn command_no_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("ls".into()),
            context: None,
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (doc, effect) = annotate_rule(&rule, "cat", &[]);
        assert!(effect.is_none());

        let anns = collect_annotations(&doc);
        assert!(
            anns.iter()
                .any(|a| matches!(a, EvalAnn::CommandMatch(false)))
        );
    }

    #[test]
    fn context_presence_query_annotation() {
        let rule = Rule {
            command: CommandMatcher::Exact("echo".into()),
            context: Some(ContextExpr::Has(FactQuery::Presence {
                key: ":via/ssh".into(),
                vector_syntax: true,
            })),
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let mut facts = ContextFacts::default();
        facts.insert_present(":via/ssh");
        let (doc, effect) = annotate_rule_with_context(&rule, "echo", &[], &facts);
        assert!(effect.is_some());
        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|ann| matches!(
            ann,
            EvalAnn::ContextHasPresence {
                key,
                matched: true,
                ..
            } if key == ":via/ssh"
        )));
    }

    #[test]
    fn context_alias_returns_not_matched() {
        // Aliases should be resolved during parsing. If we encounter one here,
        // it means the config was constructed programmatically without resolution.
        let rule = Rule {
            command: CommandMatcher::Exact("echo".into()),
            context: Some(ContextExpr::Alias("unresolved-alias".into())),
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (doc, effect) = annotate_rule(&rule, "echo", &[]);
        // Alias context should not match, so rule evaluation should fail
        assert!(effect.is_none());
        // Check the annotation shows matched: false
        let anns = collect_annotations(&doc);
        assert!(
            anns.iter()
                .any(|ann| matches!(ann, EvalAnn::ContextResult(false)))
        );
    }

    #[test]
    fn context_exact_query_marks_absent_reason() {
        let rule = Rule {
            command: CommandMatcher::Exact("echo".into()),
            context: Some(ContextExpr::Has(FactQuery::Value {
                key: ":opencode/agent".into(),
                pattern: FactPattern::Literal("build".into()),
            })),
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (doc, effect) = annotate_rule(&rule, "echo", &[]);
        assert!(effect.is_none());
        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|ann| matches!(
            ann,
            EvalAnn::ContextHasExact {
                reason: Some(ContextFailureReason::Absent),
                matched: false,
                ..
            }
        )));
    }

    #[test]
    fn context_pattern_query_marks_present_without_scalar() {
        let rule = Rule {
            command: CommandMatcher::Exact("echo".into()),
            context: Some(ContextExpr::Has(FactQuery::Value {
                key: ":ssh/host".into(),
                pattern: FactPattern::Regex(regex::Regex::new("^prod-").unwrap()),
            })),
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let mut facts = ContextFacts::default();
        facts.insert_present(":ssh/host");
        let (doc, effect) = annotate_rule_with_context(&rule, "echo", &[], &facts);
        assert!(effect.is_none());
        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|ann| matches!(
            ann,
            EvalAnn::ContextHasPattern {
                reason: Some(ContextFailureReason::PresentWithoutScalar),
                matched: false,
                ..
            }
        )));
    }

    #[test]
    fn context_pattern_query_short_circuits_or_children() {
        let rule = Rule {
            command: CommandMatcher::Exact("echo".into()),
            context: Some(ContextExpr::Has(FactQuery::Value {
                key: ":opencode/agent".into(),
                pattern: FactPattern::Or(vec![
                    FactPattern::Literal("build".into()),
                    FactPattern::Regex(regex::Regex::new("^plan-").unwrap()),
                ]),
            })),
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let mut facts = ContextFacts::default();
        facts.insert_scalar(":opencode/agent", "build");
        let (doc, effect) = annotate_rule_with_context(&rule, "echo", &[], &facts);
        assert!(effect.is_some());
        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|ann| matches!(
            ann,
            EvalAnn::ContextHasPattern {
                pattern_eval: FactPatternEval::Or { children, .. },
                search_needle,
                matched: true,
                ..
            } if children.len() == 2
                && matches!(children[1], FactPatternEval::Regex { evaluated: false, .. })
                && search_needle == "\"build\""
        )));
    }

    #[test]
    fn context_exact_query_matches_scalar_value() {
        let rule = Rule {
            command: CommandMatcher::Exact("echo".into()),
            context: Some(ContextExpr::Has(FactQuery::Value {
                key: ":opencode/agent".into(),
                pattern: FactPattern::Literal("build".into()),
            })),
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let mut facts = ContextFacts::default();
        facts.insert_scalar(":opencode/agent", "build");
        let (doc, effect) = annotate_rule_with_context(&rule, "echo", &[], &facts);
        assert!(effect.is_some());
        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|ann| matches!(
            ann,
            EvalAnn::ContextHasExact {
                actual: Some(actual),
                matched: true,
                search_needle,
                ..
            } if actual == "build" && search_needle == "\"build\""
        )));
    }

    #[test]
    fn context_pattern_and_short_circuits_after_failure() {
        let rule = Rule {
            command: CommandMatcher::Exact("echo".into()),
            context: Some(ContextExpr::Has(FactQuery::Value {
                key: ":ssh/host".into(),
                pattern: FactPattern::And(vec![
                    FactPattern::Regex(regex::Regex::new("^prod-").unwrap()),
                    FactPattern::Literal("prod-1".into()),
                ]),
            })),
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let mut facts = ContextFacts::default();
        facts.insert_scalar(":ssh/host", "dev-1");
        let (doc, effect) = annotate_rule_with_context(&rule, "echo", &[], &facts);
        assert!(effect.is_none());
        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|ann| matches!(
            ann,
            EvalAnn::ContextHasPattern {
                pattern_eval: FactPatternEval::And { children, .. },
                search_needle,
                matched: false,
                ..
            } if children.len() == 2
                && matches!(children[1], FactPatternEval::Literal { evaluated: false, .. })
                && search_needle == "(regex \"^prod-\")"
        )));
    }

    #[test]
    fn context_pattern_not_inverts_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("echo".into()),
            context: Some(ContextExpr::Has(FactQuery::Value {
                key: ":opencode/agent".into(),
                pattern: FactPattern::Not(Box::new(FactPattern::Literal("build".into()))),
            })),
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let mut facts = ContextFacts::default();
        facts.insert_scalar(":opencode/agent", "plan");
        let (doc, effect) = annotate_rule_with_context(&rule, "echo", &[], &facts);
        assert!(effect.is_some());
        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|ann| matches!(
            ann,
            EvalAnn::ContextHasPattern {
                pattern_eval: FactPatternEval::Not { matched: true, .. },
                search_needle,
                matched: true,
                ..
            } if search_needle == "\"build\""
        )));
    }

    #[test]
    fn context_pattern_wildcard_matches_any_scalar() {
        let rule = Rule {
            command: CommandMatcher::Exact("echo".into()),
            context: Some(ContextExpr::Has(FactQuery::Value {
                key: ":ssh/host".into(),
                pattern: FactPattern::Wildcard,
            })),
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let mut facts = ContextFacts::default();
        facts.insert_scalar(":ssh/host", "prod-9");
        let (doc, effect) = annotate_rule_with_context(&rule, "echo", &[], &facts);
        assert!(effect.is_some());
        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|ann| matches!(
            ann,
            EvalAnn::ContextHasPattern {
                pattern_eval: FactPatternEval::Wildcard { matched: true, .. },
                matched: true,
                search_needle,
                ..
            } if search_needle == "*"
        )));
    }

    // ── Positional matching ─────────────────────────────────────────

    #[test]
    fn positional_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal(
                    "push".into(),
                ))])),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let args = vec![lit("push")];
        let (doc, effect) = annotate_rule(&rule, "git", &args);
        assert!(effect.is_some());

        let anns = collect_annotations(&doc);
        assert!(
            anns.iter()
                .any(|a| matches!(a, EvalAnn::ExprVsArg { matched: true, .. }))
        );
        assert!(anns.iter().any(|a| matches!(a, EvalAnn::ArgsResult(true))));
    }

    #[test]
    fn positional_no_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal(
                    "push".into(),
                ))])),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let args = vec![lit("pull")];
        let (doc, effect) = annotate_rule(&rule, "git", &args);
        assert!(effect.is_none());

        let anns = collect_annotations(&doc);
        assert!(
            anns.iter()
                .any(|a| matches!(a, EvalAnn::ExprVsArg { matched: false, .. }))
        );
        assert!(anns.iter().any(|a| matches!(a, EvalAnn::ArgsResult(false))));
    }

    #[test]
    fn positional_missing_arg() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal(
                    "push".into(),
                ))])),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
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
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![
                    PosExpr::one(Expr::Literal("push".into())),
                    PosExpr {
                        quantifier: Quantifier::ZeroOrMore,
                        expr: Expr::Wildcard,
                    },
                ])),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let args = vec![lit("push"), lit("origin"), lit("main")];
        let (doc, effect) = annotate_rule(&rule, "git", &args);
        assert!(effect.is_some());

        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|a| matches!(
            a,
            EvalAnn::Quantifier {
                count: 2,
                matched: true
            }
        )));
    }

    // ── Anywhere matching ───────────────────────────────────────────

    #[test]
    fn anywhere_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Anywhere(vec![Expr::Literal("--force".into())])),
                effect: Effect {
                    decision: Decision::Deny,
                    reason: Some("force push".into()),
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let args = vec![lit("push"), lit("--force")];
        let (doc, effect) = annotate_rule(&rule, "git", &args);
        // Anywhere match doesn't produce its own effect; rule-level effect applies
        assert!(effect.is_some());

        let anns = collect_annotations(&doc);
        assert!(
            anns.iter()
                .any(|a| matches!(a, EvalAnn::Anywhere { matched: true, .. }))
        );
    }

    // ── Branching (cond) matching ───────────────────────────────────

    #[test]
    fn branching_cond_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            context: None,
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
        assert!(anns.iter().any(|a| matches!(
            a,
            EvalAnn::CondElse {
                decision: Decision::Allow
            }
        )));
    }

    #[test]
    fn branching_cond_branch_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            context: None,
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
        assert!(anns.iter().any(|a| matches!(
            a,
            EvalAnn::CondBranch {
                decision: Decision::Deny
            }
        )));
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
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![PosExpr::one(cond_expr)])),
                effect: Effect {
                    decision: Decision::Ask,
                    reason: None,
                },
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
            context: None,
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
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
            context: None,
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
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
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Or(vec![
                    ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal("push".into()))]),
                    ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal("pull".into()))]),
                ])),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
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
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Not(Box::new(ArgMatcher::Anywhere(vec![
                    Expr::Literal("--force".into()),
                ])))),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
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
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::And(vec![
                    ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal("push".into()))]),
                    ArgMatcher::Anywhere(vec![Expr::Literal("--force".into())]),
                ])),
                effect: Effect {
                    decision: Decision::Deny,
                    reason: Some("force push".into()),
                },
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
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::And(vec![
                    ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal("push".into()))]),
                    ArgMatcher::Anywhere(vec![Expr::Literal("--force".into())]),
                ])),
                effect: Effect {
                    decision: Decision::Deny,
                    reason: None,
                },
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
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::ExactPositional(vec![PosExpr::one(
                    Expr::Literal("push".into()),
                )])),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let args = vec![lit("push"), lit("origin")];
        let (doc, effect) = annotate_rule(&rule, "git", &args);
        assert!(effect.is_none()); // extra arg "origin"

        let anns = collect_annotations(&doc);
        assert!(
            anns.iter()
                .any(|a| matches!(a, EvalAnn::ExactRemainder { count: 1 }))
        );
    }

    // ── Optional quantifier ─────────────────────────────────────────

    #[test]
    fn optional_arg_present() {
        let rule = Rule {
            command: CommandMatcher::Exact("cmd".into()),
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![
                    PosExpr {
                        quantifier: Quantifier::Optional,
                        expr: Expr::Literal("opt".into()),
                    },
                    PosExpr::one(Expr::Literal("req".into())),
                ])),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
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
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![
                    PosExpr {
                        quantifier: Quantifier::Optional,
                        expr: Expr::Literal("opt".into()),
                    },
                    PosExpr::one(Expr::Literal("req".into())),
                ])),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
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
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![PosExpr::one(Expr::Wildcard)])),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
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
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal(
                    "specific".into(),
                ))])),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
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
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![PosExpr::one(Expr::Or(vec![
                    Expr::Literal("a".into()),
                    Expr::Literal("b".into()),
                ]))])),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
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
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![PosExpr::one(Expr::Not(
                    Box::new(Expr::Literal("bad".into())),
                ))])),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
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
            context: None,
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
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("safe".into()),
            effect: allow("safe arg"),
        }]);
        let rule = Rule {
            command: CommandMatcher::Exact("cmd".into()),
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![PosExpr::one(cond_expr)])),
                effect: Effect {
                    decision: Decision::Ask,
                    reason: None,
                },
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
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Positional(vec![
                    PosExpr::one(Expr::Literal("push".into())),
                    PosExpr {
                        quantifier: Quantifier::ZeroOrMore,
                        expr: Expr::Wildcard,
                    },
                ])),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let args = vec![lit("push"), lit("origin")];
        let (annotated, _) = annotate_rule(&rule, "git", &args);

        // The annotated doc should have the same structure as the plain to_doc
        assert_same_structure(&annotated, &rule.to_doc());
    }

    // ── BoolExpr annotation ─────────────────────────────────────────

    #[test]
    fn bool_expr_has_presence_annotation() {
        let rule = Rule {
            command: CommandMatcher::Exact("kubectl".into()),
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Has(BoolExpr::Has(FactQuery::Presence {
                    key: ":via/ssh".into(),
                    vector_syntax: false,
                }))),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: Some("SSH session".into()),
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let mut facts = ContextFacts::default();
        facts.insert_present(":via/ssh");
        let (doc, effect) = annotate_rule_with_context(&rule, "kubectl", &[], &facts);
        assert!(effect.is_some());
        assert_eq!(effect.unwrap().decision, Decision::Allow);

        // Verify structure is preserved
        assert_same_structure(&doc, &rule.to_doc());
    }

    #[test]
    fn bool_expr_has_presence_no_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("kubectl".into()),
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Has(BoolExpr::Has(FactQuery::Presence {
                    key: ":via/ssh".into(),
                    vector_syntax: false,
                }))),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: Some("SSH session".into()),
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let facts = ContextFacts::default();
        let (_, effect) = annotate_rule_with_context(&rule, "kubectl", &[], &facts);
        // Should not match when fact is absent
        assert!(effect.is_none());
    }

    #[test]
    fn bool_expr_has_value_annotation() {
        let rule = Rule {
            command: CommandMatcher::Exact("deploy".into()),
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Has(BoolExpr::Has(FactQuery::Value {
                    key: ":env".into(),
                    pattern: FactPattern::Literal("prod".into()),
                }))),
                effect: Effect {
                    decision: Decision::Deny,
                    reason: Some("No prod deploys".into()),
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let mut facts = ContextFacts::default();
        facts.insert_scalar(":env", "prod");
        let (doc, effect) = annotate_rule_with_context(&rule, "deploy", &[], &facts);
        assert!(effect.is_some());
        assert_eq!(effect.unwrap().decision, Decision::Deny);

        // Verify structure is preserved
        assert_same_structure(&doc, &rule.to_doc());
    }

    #[test]
    fn bool_expr_and_annotation() {
        let rule = Rule {
            command: CommandMatcher::Exact("cmd".into()),
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Has(BoolExpr::And(vec![
                    BoolExpr::Has(FactQuery::Presence {
                        key: ":via/ssh".into(),
                        vector_syntax: false,
                    }),
                    BoolExpr::Has(FactQuery::Value {
                        key: ":env".into(),
                        pattern: FactPattern::Literal("prod".into()),
                    }),
                ]))),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let mut facts = ContextFacts::default();
        facts.insert_present(":via/ssh");
        facts.insert_scalar(":env", "prod");
        let (_, effect) = annotate_rule_with_context(&rule, "cmd", &[], &facts);
        // Should match when both conditions in the And are true
        assert!(effect.is_some());
    }

    // ── Polymorphic cond annotation (when/unless/if) ─────────────────

    #[test]
    fn when_matcher_annotation() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::When(PolymorphicCondArm {
                    branches: vec![PolymorphicCondBranch {
                        predicate: MatcherCondPredicate::Matcher(Box::new(ArgMatcher::Positional(
                            vec![PosExpr::one(Expr::Literal("push".into()))],
                        ))),
                        effect: allow("push allowed"),
                    }],
                    fallback: None,
                })),
                effect: Effect {
                    decision: Decision::Ask,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let (doc, effect) = annotate_rule(&rule, "git", &[lit("push")]);
        assert!(effect.is_some());

        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|a| matches!(
            a,
            EvalAnn::CondBranch {
                decision: Decision::Allow
            }
        )));
    }

    #[test]
    fn when_boolexpr_annotation() {
        let rule = Rule {
            command: CommandMatcher::Exact("kubectl".into()),
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::When(PolymorphicCondArm {
                    branches: vec![PolymorphicCondBranch {
                        predicate: MatcherCondPredicate::BoolExpr(BoolExpr::Has(
                            FactQuery::Presence {
                                key: ":via/ssh".into(),
                                vector_syntax: false,
                            },
                        )),
                        effect: deny("no kubectl via ssh"),
                    }],
                    fallback: None,
                })),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        let mut facts = ContextFacts::default();
        facts.insert_present(":via/ssh");
        let (doc, effect) = annotate_rule_with_context(&rule, "kubectl", &[], &facts);
        assert!(effect.is_some());

        let anns = collect_annotations(&doc);
        assert!(anns.iter().any(|a| matches!(
            a,
            EvalAnn::CondBranch {
                decision: Decision::Deny
            }
        )));
    }

    #[test]
    fn unless_matcher_annotation() {
        let rule = Rule {
            command: CommandMatcher::Exact("rm".into()),
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::Unless(PolymorphicCondArm {
                    branches: vec![PolymorphicCondBranch {
                        predicate: MatcherCondPredicate::Matcher(Box::new(ArgMatcher::Anywhere(
                            vec![Expr::Literal("-rf".into())],
                        ))),
                        effect: deny("dangerous"),
                    }],
                    fallback: None,
                })),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        // Without -rf, the unless matches (predicate fails, so unless succeeds)
        let (_, effect) = annotate_rule(&rule, "rm", &[lit("file.txt")]);
        // The unless matched since -rf is not present, so it should apply its effect
        assert!(effect.is_some());
    }

    #[test]
    fn if_matcher_annotation() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::If {
                    test: Box::new(MatcherCondPredicate::Matcher(Box::new(
                        ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal("push".into()))]),
                    ))),
                    then_effect: allow("pushing"),
                    else_effect: None,
                }),
                effect: Effect {
                    decision: Decision::Ask,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        // Should match the then branch
        let (_, effect) = annotate_rule(&rule, "git", &[lit("push")]);
        assert!(effect.is_some());
    }

    #[test]
    fn if_with_else_annotation() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::If {
                    test: Box::new(MatcherCondPredicate::Matcher(Box::new(
                        ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal("push".into()))]),
                    ))),
                    then_effect: allow("pushing"),
                    else_effect: Some(deny("not pushing")),
                }),
                effect: Effect {
                    decision: Decision::Ask,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        // Test else branch - doesn't match "push"
        let (_, effect) = annotate_rule(&rule, "git", &[lit("pull")]);
        // Should match the else branch
        assert!(effect.is_some());
    }

    #[test]
    fn mixed_predicate_when_annotation() {
        let rule = Rule {
            command: CommandMatcher::Exact("deploy".into()),
            context: None,
            body: RuleBody::Effect {
                matcher: Some(ArgMatcher::When(PolymorphicCondArm {
                    branches: vec![
                        // First branch: BoolExpr predicate
                        PolymorphicCondBranch {
                            predicate: MatcherCondPredicate::BoolExpr(BoolExpr::Has(
                                FactQuery::Value {
                                    key: ":env".into(),
                                    pattern: FactPattern::Literal("prod".into()),
                                },
                            )),
                            effect: deny("no prod deploys"),
                        },
                        // Second branch: Matcher predicate (using Anywhere to match flags)
                        PolymorphicCondBranch {
                            predicate: MatcherCondPredicate::Matcher(Box::new(
                                ArgMatcher::Anywhere(vec![Expr::Literal("--dry-run".into())]),
                            )),
                            effect: allow("dry run ok"),
                        },
                    ],
                    fallback: None,
                })),
                effect: Effect {
                    decision: Decision::Ask,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span::new(0, 0),
        };
        // Should match second branch via positional matcher
        let (_, effect) = annotate_rule(&rule, "deploy", &[lit("--dry-run")]);
        // Second branch should match and produce an effect
        assert!(effect.is_some());
    }
}
