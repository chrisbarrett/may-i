// Annotation types and TracingFold for producing annotated Doc trees.
//
// Lives in the CLI binary so `Doc` never enters the engine crate.

use may_i_core::ast::{Effect, EffectResult, Rule};
use may_i_core::doc::{Doc, DocF, LayoutHint};
use may_i_core::pattern::{ArgPattern, CommandPattern};
use may_i_core::{Decision, FactQuery};

use may_i_engine::eval::PredicateResult;
use may_i_engine::fold::{ArgMatchDetail, ChildResult, EvalFold, FactDetail};

/// Annotation carried on each Doc node in a trace.
#[derive(Debug, Clone)]
pub enum Ann {
    /// Command pattern matched or not.
    CommandMatch { matched: bool },
    /// Argument pattern matched with evidence.
    ArgMatch {
        search_tokens: Vec<String>,
        arg_set: Vec<String>,
        matched: bool,
    },
    /// Fact query result with evidence.
    FactQuery {
        query_source: String,
        matched: bool,
        observed: Option<Vec<String>>,
        failure_reason: Option<String>,
    },
    /// Effect decision.
    EffectDecision {
        decision: Decision,
        reason: Option<String>,
    },
    /// Quantifier/combinator result.
    Combinator { result_is_nil: bool },
    /// Rule-level annotation.
    RuleMatch { matched: bool, line: Option<usize> },
}

type ADoc = Doc<Option<Ann>>;

fn ann_atom(s: impl Into<String>, ann: Option<Ann>) -> ADoc {
    Doc {
        ann,
        node: DocF::Atom(s.into()),
        layout: LayoutHint::Auto,
        dimmed: false,
    }
}

fn ann_list(children: Vec<ADoc>, ann: Option<Ann>) -> ADoc {
    Doc {
        ann,
        node: DocF::List(children),
        layout: LayoutHint::Auto,
        dimmed: false,
    }
}

fn ann_list_break(children: Vec<ADoc>, ann: Option<Ann>) -> ADoc {
    Doc {
        ann,
        node: DocF::List(children),
        layout: LayoutHint::AlwaysBreak,
        dimmed: false,
    }
}

fn plain_atom(s: impl Into<String>) -> ADoc {
    ann_atom(s, None)
}

fn unannotated_to_ann(doc: Doc<()>) -> ADoc {
    doc.map(&|()| None)
}

fn dim(mut doc: ADoc) -> ADoc {
    doc.dimmed = true;
    doc
}

fn command_pattern_to_doc(pattern: &CommandPattern) -> Doc<()> {
    match pattern {
        CommandPattern::Literal(s) => Doc::atom(format!("\"{}\"", s)),
        CommandPattern::Regex(re) => Doc::list(vec![
            Doc::atom("regex"),
            Doc::atom(format!("\"{}\"", re.as_str())),
        ]),
        CommandPattern::Or(patterns) => {
            let mut cs = vec![Doc::atom("or")];
            cs.extend(patterns.iter().map(command_pattern_to_doc));
            if patterns.len() > 4 {
                Doc::broken_list(cs)
            } else {
                Doc::list(cs)
            }
        }
    }
}

fn arg_pattern_to_doc(pattern: &ArgPattern) -> Doc<()> {
    // Simplified doc representation
    match pattern {
        ArgPattern::Positional { patterns, .. } => {
            let mut cs = vec![Doc::atom("positional")];
            cs.extend(patterns.iter().map(|p| p.pattern.to_doc()));
            Doc::list(cs)
        }
        ArgPattern::Exact { patterns, .. } => {
            let mut cs = vec![Doc::atom("exact")];
            cs.extend(patterns.iter().map(|p| p.pattern.to_doc()));
            Doc::list(cs)
        }
        ArgPattern::Anywhere(exprs) => {
            let mut cs = vec![Doc::atom("anywhere")];
            cs.extend(exprs.iter().map(|e| e.to_doc()));
            Doc::list(cs)
        }
        ArgPattern::Forbidden(exprs) => {
            let mut cs = vec![Doc::atom("forbidden")];
            cs.extend(exprs.iter().map(|e| e.to_doc()));
            Doc::list(cs)
        }
    }
}

fn fact_query_to_doc(query: &FactQuery) -> Doc<()> {
    query.to_doc()
}

/// A single trace entry produced by the fold.
#[derive(Clone)]
pub enum TraceEntry {
    /// Header for a compound command segment.
    SegmentHeader { command: String, decision: Decision },
    /// A rule evaluation with its annotated doc tree.
    Rule { doc: ADoc, line: Option<usize> },
    /// No matching rule — default ask.
    DefaultAsk { reason: String },
}

/// Fold that produces `(EffectResult, Doc<Option<Ann>>)` pairs and
/// accumulates rule-level trace entries.
pub struct TracingFold {
    pub traces: Vec<TraceEntry>,
}

impl TracingFold {
    pub fn new() -> Self {
        Self { traces: Vec::new() }
    }
}

impl EvalFold for TracingFold {
    type EffectOut = (EffectResult, ADoc);
    type PredicateOut = (PredicateResult, ADoc);

    fn effect_result(out: &Self::EffectOut) -> &EffectResult {
        &out.0
    }

    fn predicate_result(out: &Self::PredicateOut) -> PredicateResult {
        out.0
    }

    fn effect_terminal(&mut self, effect: &Effect, result: EffectResult) -> Self::EffectOut {
        let keyword = match &result {
            EffectResult::Decision(Decision::Allow, _) => ":allow",
            EffectResult::Decision(Decision::Ask, _) => ":ask",
            EffectResult::Decision(Decision::Deny, _) => ":deny",
            EffectResult::Nil => ":nil",
        };

        let mut children = vec![plain_atom("effect"), plain_atom(keyword)];
        if let EffectResult::Decision(_, Some(reason)) = &result {
            children.push(plain_atom(format!("\"{}\"", reason)));
        }

        let ann = match &result {
            EffectResult::Decision(decision, reason) => Some(Ann::EffectDecision {
                decision: *decision,
                reason: reason.clone(),
            }),
            EffectResult::Nil => None,
        };

        let _ = effect;
        (result, ann_list(children, ann))
    }

    fn effect_nil(&mut self, _effect: &Effect) -> Self::EffectOut {
        (EffectResult::Nil, plain_atom("nil"))
    }

    fn effect_command_match(
        &mut self,
        pattern: &CommandPattern,
        cmd: &str,
        matched: bool,
    ) -> Self::EffectOut {
        let ann_doc = match pattern {
            CommandPattern::Or(sub_patterns) => {
                // Show only matching sub-patterns; dim and elide the rest.
                let mut cs: Vec<ADoc> = vec![plain_atom("or")];
                let mut has_pre_ellipsis = false;
                let mut has_post_match = false;
                let mut seen_match = false;
                for sub in sub_patterns {
                    let sub_matched = sub.is_match(cmd);
                    if sub_matched {
                        let sub_doc = unannotated_to_ann(command_pattern_to_doc(sub));
                        cs.push(Doc {
                            ann: Some(Ann::CommandMatch { matched: true }),
                            ..sub_doc
                        });
                        seen_match = true;
                        has_post_match = false;
                    } else if !seen_match {
                        if !has_pre_ellipsis {
                            cs.push(dim(plain_atom("…")));
                            has_pre_ellipsis = true;
                        }
                    } else {
                        has_post_match = true;
                    }
                }
                if has_post_match {
                    cs.push(dim(plain_atom("…")));
                }
                Doc {
                    ann: Some(Ann::CommandMatch { matched }),
                    node: DocF::List(cs),
                    layout: LayoutHint::Auto,
                    dimmed: false,
                }
            }
            _ => {
                let doc = unannotated_to_ann(command_pattern_to_doc(pattern));
                Doc {
                    ann: Some(Ann::CommandMatch { matched }),
                    ..doc
                }
            }
        };
        let result = if matched {
            EffectResult::Decision(Decision::Allow, None)
        } else {
            EffectResult::Nil
        };
        (result, ann_doc)
    }

    fn effect_arg_match(
        &mut self,
        pattern: &ArgPattern,
        _args: &[String],
        matched: bool,
        detail: ArgMatchDetail,
    ) -> Self::EffectOut {
        let doc = unannotated_to_ann(arg_pattern_to_doc(pattern));
        let ann_doc = Doc {
            ann: Some(Ann::ArgMatch {
                search_tokens: detail.search_tokens,
                arg_set: detail.arg_set,
                matched,
            }),
            ..doc
        };
        let result = if matched {
            EffectResult::Decision(Decision::Allow, None)
        } else {
            EffectResult::Nil
        };
        (result, ann_doc)
    }

    fn effect_and(
        &mut self,
        children: Vec<ChildResult<Self::EffectOut>>,
        result: EffectResult,
    ) -> Self::EffectOut {
        let mut docs = vec![plain_atom("and")];
        for child in children {
            match child {
                ChildResult::Evaluated((_, doc)) => docs.push(doc),
                ChildResult::Skipped => docs.push(dim(plain_atom("…"))),
            }
        }
        let ann = Some(Ann::Combinator {
            result_is_nil: result.is_nil(),
        });
        (result, ann_list_break(docs, ann))
    }

    fn effect_or(
        &mut self,
        children: Vec<ChildResult<Self::EffectOut>>,
        result: EffectResult,
    ) -> Self::EffectOut {
        let mut docs = vec![plain_atom("or")];
        for child in children {
            match child {
                ChildResult::Evaluated((_, doc)) => docs.push(doc),
                ChildResult::Skipped => docs.push(dim(plain_atom("…"))),
            }
        }
        let ann = Some(Ann::Combinator {
            result_is_nil: result.is_nil(),
        });
        (result, ann_list_break(docs, ann))
    }

    fn effect_not(&mut self, child: Self::EffectOut, result: EffectResult) -> Self::EffectOut {
        let docs = vec![plain_atom("not"), child.1];
        let ann = Some(Ann::Combinator {
            result_is_nil: result.is_nil(),
        });
        (result, ann_list(docs, ann))
    }

    fn effect_when(
        &mut self,
        pred: Self::PredicateOut,
        body: ChildResult<Self::EffectOut>,
        result: EffectResult,
    ) -> Self::EffectOut {
        let body_doc = match body {
            ChildResult::Evaluated((_, doc)) => doc,
            ChildResult::Skipped => dim(plain_atom("…")),
        };
        let docs = vec![plain_atom("when"), pred.1, body_doc];
        let ann = Some(Ann::Combinator {
            result_is_nil: result.is_nil(),
        });
        (result, ann_list_break(docs, ann))
    }

    fn effect_unless(
        &mut self,
        pred: Self::PredicateOut,
        body: ChildResult<Self::EffectOut>,
        result: EffectResult,
    ) -> Self::EffectOut {
        let body_doc = match body {
            ChildResult::Evaluated((_, doc)) => doc,
            ChildResult::Skipped => dim(plain_atom("…")),
        };
        let docs = vec![plain_atom("unless"), pred.1, body_doc];
        let ann = Some(Ann::Combinator {
            result_is_nil: result.is_nil(),
        });
        (result, ann_list_break(docs, ann))
    }

    fn effect_if(
        &mut self,
        pred: Self::PredicateOut,
        then_: ChildResult<Self::EffectOut>,
        else_: ChildResult<Self::EffectOut>,
        result: EffectResult,
    ) -> Self::EffectOut {
        let then_doc = match then_ {
            ChildResult::Evaluated((_, doc)) => doc,
            ChildResult::Skipped => dim(plain_atom("…")),
        };
        let else_doc = match else_ {
            ChildResult::Evaluated((_, doc)) => doc,
            ChildResult::Skipped => dim(plain_atom("…")),
        };
        let docs = vec![plain_atom("if"), pred.1, then_doc, else_doc];
        let ann = Some(Ann::Combinator {
            result_is_nil: result.is_nil(),
        });
        (result, ann_list_break(docs, ann))
    }

    fn effect_cond(
        &mut self,
        branches: Vec<(Self::PredicateOut, ChildResult<Self::EffectOut>)>,
        fallback: Option<ChildResult<Self::EffectOut>>,
        result: EffectResult,
    ) -> Self::EffectOut {
        let mut docs = vec![plain_atom("cond")];
        for (pred, body) in branches {
            let body_doc = match body {
                ChildResult::Evaluated((_, doc)) => doc,
                ChildResult::Skipped => dim(plain_atom("…")),
            };
            docs.push(ann_list(vec![pred.1, body_doc], None));
        }
        if let Some(fb) = fallback {
            match fb {
                ChildResult::Evaluated((_, doc)) => docs.push(doc),
                ChildResult::Skipped => docs.push(dim(plain_atom("…"))),
            }
        }
        let ann = Some(Ann::Combinator {
            result_is_nil: result.is_nil(),
        });
        (result, ann_list_break(docs, ann))
    }

    fn effect_may_i(
        &mut self,
        inner_cmd: &str,
        inner_args: &[String],
        inner_result: EffectResult,
        inner_out: Self::EffectOut,
    ) -> Self::EffectOut {
        let cmd_str = if inner_args.is_empty() {
            inner_cmd.to_string()
        } else {
            format!("{} {}", inner_cmd, inner_args.join(" "))
        };
        let docs = vec![
            plain_atom("may-i"),
            plain_atom(format!("\"{}\"", cmd_str)),
            inner_out.1,
        ];
        let ann = Some(Ann::Combinator {
            result_is_nil: inner_result.is_nil(),
        });
        (inner_result, ann_list_break(docs, ann))
    }

    fn effect_may_i_no_match(&mut self, pattern: &ArgPattern) -> Self::EffectOut {
        let doc = unannotated_to_ann(arg_pattern_to_doc(pattern));
        let docs = vec![plain_atom("may-i"), dim(doc)];
        (EffectResult::Nil, ann_list(docs, None))
    }

    fn predicate_fact(
        &mut self,
        query: &FactQuery,
        result: PredicateResult,
        detail: FactDetail,
    ) -> Self::PredicateOut {
        let source = query.to_source();
        let doc = unannotated_to_ann(fact_query_to_doc(query));
        let ann_doc = Doc {
            ann: Some(Ann::FactQuery {
                query_source: source,
                matched: result == PredicateResult::Match,
                observed: detail.observed,
                failure_reason: detail.failure_reason,
            }),
            ..doc
        };
        (result, ann_doc)
    }

    fn predicate_arg(
        &mut self,
        pattern: &ArgPattern,
        args: &[String],
        result: PredicateResult,
    ) -> Self::PredicateOut {
        let doc = unannotated_to_ann(arg_pattern_to_doc(pattern));
        let ann_doc = Doc {
            ann: Some(Ann::ArgMatch {
                search_tokens: vec![],
                arg_set: args.to_vec(),
                matched: result == PredicateResult::Match,
            }),
            ..doc
        };
        (result, ann_doc)
    }

    fn predicate_and(
        &mut self,
        children: Vec<ChildResult<Self::PredicateOut>>,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        let mut docs = vec![plain_atom("and")];
        for child in children {
            match child {
                ChildResult::Evaluated((_, doc)) => docs.push(doc),
                ChildResult::Skipped => docs.push(dim(plain_atom("…"))),
            }
        }
        (result, ann_list_break(docs, None))
    }

    fn predicate_or(
        &mut self,
        children: Vec<ChildResult<Self::PredicateOut>>,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        let mut docs = vec![plain_atom("or")];
        for child in children {
            match child {
                ChildResult::Evaluated((_, doc)) => docs.push(doc),
                ChildResult::Skipped => docs.push(dim(plain_atom("…"))),
            }
        }
        (result, ann_list_break(docs, None))
    }

    fn predicate_not(
        &mut self,
        child: Self::PredicateOut,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        let docs = vec![plain_atom("not"), child.1];
        (result, ann_list(docs, None))
    }

    fn predicate_named(
        &mut self,
        name: &str,
        resolved: Self::PredicateOut,
        _result: PredicateResult,
    ) -> Self::PredicateOut {
        let docs = vec![plain_atom(name), resolved.1];
        (resolved.0, ann_list(docs, None))
    }

    fn rule_matched(
        &mut self,
        _rule: &Rule,
        line: Option<usize>,
        command_out: Self::EffectOut,
        out: Self::EffectOut,
    ) -> Self::EffectOut {
        let ann = Some(Ann::RuleMatch {
            matched: true,
            line,
        });
        let docs = vec![plain_atom("rule"), command_out.1, out.1];
        let doc = ann_list_break(docs, ann);
        self.traces.push(TraceEntry::Rule {
            doc: doc.clone(),
            line,
        });
        (out.0, doc)
    }

    fn rule_skipped(&mut self, _rule: &Rule) -> Self::EffectOut {
        // Don't add skipped (non-matching) rules to the trace — they are
        // out of scope for the command being evaluated and just add noise.
        (EffectResult::Nil, plain_atom("…"))
    }

    fn default_ask(&mut self, reason: &str) -> Self::EffectOut {
        let docs = vec![
            plain_atom("default"),
            plain_atom(":ask"),
            plain_atom(format!("\"{}\"", reason)),
        ];
        let ann = Some(Ann::EffectDecision {
            decision: Decision::Ask,
            reason: Some(reason.to_string()),
        });
        let doc = ann_list(docs, ann);
        self.traces.push(TraceEntry::DefaultAsk {
            reason: reason.to_string(),
        });
        (
            EffectResult::Decision(Decision::Ask, Some(reason.to_string())),
            doc,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_engine::eval::{EvalContext, Evaluator};
    use may_i_engine::fold::PureFold;
    use may_i_engine::test_generators::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        // Property: TracingFold produces the same decision as PureFold.
        // The fold parameterisation must not alter evaluation semantics.
        #[test]
        fn tracing_fold_agrees_with_pure_fold(
            config in any_config(3),
            data in any_eval_context_data(),
        ) {
            let (cmd, args, facts) = data;
            let ctx = EvalContext::new(&cmd, &args, &facts);

            let evaluator = Evaluator::new(&config.rules);

            let pure_result = evaluator.evaluate(&mut PureFold, &ctx);
            let tracing_result = evaluator.evaluate(&mut TracingFold::new(), &ctx);

            prop_assert_eq!(
                pure_result.decision, tracing_result.decision,
                "TracingFold must produce the same decision as PureFold"
            );
            prop_assert_eq!(
                pure_result.reason, tracing_result.reason,
                "TracingFold must produce the same reason as PureFold"
            );
        }
    }
}
