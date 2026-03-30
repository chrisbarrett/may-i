// Annotation types and TracingFold for producing annotated Doc trees.
//
// Lives in the CLI binary so `Doc` never enters the engine crate.

use may_i_core::ast::{Effect, EffectResult, Rule};
use may_i_core::doc::{Doc, DocF, LayoutHint};
use may_i_core::pattern::{ArgPattern, CommandPattern, Quantifier};
use may_i_core::primitives::ToDoc;
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
    /// Recursive evaluation (may-i) with inner command and result.
    MayI {
        inner_command: String,
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

/// Convert an Effect to an annotated Doc, adding static EffectDecision
/// annotations on terminal effect nodes. Used for rendering unevaluated
/// (skipped) bodies in `when`/`unless`.
fn effect_to_static_ann_doc(effect: &Effect) -> ADoc {
    let doc = unannotated_to_ann(effect.to_doc());
    annotate_terminal_effects(doc, effect)
}

fn annotate_terminal_effects(doc: ADoc, effect: &Effect) -> ADoc {
    match effect {
        Effect::Allow(reason) | Effect::Ask(reason) | Effect::Deny(reason) => {
            let decision = match effect {
                Effect::Allow(_) => Decision::Allow,
                Effect::Ask(_) => Decision::Ask,
                Effect::Deny(_) => Decision::Deny,
                _ => unreachable!(),
            };
            Doc {
                ann: Some(Ann::EffectDecision {
                    decision,
                    reason: reason.clone(),
                }),
                ..doc
            }
        }
        _ => doc,
    }
}

fn dim(mut doc: ADoc) -> ADoc {
    doc.dimmed = true;
    doc
}

/// Build the children of a rule doc: (rule (command ...) [(context ...)] (args ...) [(effect ...)])
///
/// Separates arg predicates from terminal effects and context predicates.
/// The oracle shows these as siblings: (rule (command ...) (context ...) (args ...) (effect ...))
fn build_rule_doc_children(
    rule: &Rule,
    command_out: (EffectResult, ADoc),
    effects: Vec<(EffectResult, ADoc)>,
) -> Vec<ADoc> {
    use may_i_core::ast::Effect;
    let command_doc = ann_list(vec![plain_atom("command"), command_out.1], None);
    let mut docs = vec![plain_atom("rule"), command_doc];

    // Separate effects into arg predicates and terminal/other effects.
    // Context predicates (When/Unless wrapping a terminal) are extracted separately.
    let mut args_children = vec![plain_atom("args")];
    let mut terminal_doc: Option<ADoc> = None;
    let mut context_docs: Vec<ADoc> = Vec::new();

    for (i, effect_out) in effects.iter().enumerate() {
        let effect = rule.effects.get(i).map(|e| &e.value);
        match effect {
            Some(Effect::When {
                predicate,
                effect: body,
            }) if body.value.is_terminal() => {
                // Context predicate wrapping terminal effect — extract both.
                // The fold produced a single doc for the when(...) form.
                // We need to split it into (context ...) and (effect ...) siblings.
                // For now, extract from the evaluated doc.
                extract_context_and_effect(&effect_out.1, &mut context_docs, &mut terminal_doc);
            }
            Some(Effect::Unless {
                predicate,
                effect: body,
            }) if body.value.is_terminal() => {
                extract_context_and_effect(&effect_out.1, &mut context_docs, &mut terminal_doc);
            }
            Some(eff) if eff.is_terminal() => {
                terminal_doc = Some(effect_out.1.clone());
            }
            _ => {
                args_children.push(effect_out.1.clone());
            }
        }
    }

    // If we didn't see all effects (rule_not_matched case), add remaining
    // effects from the rule definition as dimmed (no annotations).
    if terminal_doc.is_none() {
        // Find the first un-evaluated effect.
        let start_idx = effects.len();
        for effect_def in rule.effects.iter().skip(start_idx) {
            match &effect_def.value {
                Effect::When {
                    predicate,
                    effect: body,
                } if body.value.is_terminal() => {
                    // Extract context predicate and terminal effect.
                    let ctx_doc = dim(unannotated_to_ann(predicate.value.to_doc()));
                    context_docs.push(ann_list_break(vec![plain_atom("context"), ctx_doc], None));
                    terminal_doc = Some(dim(unannotated_to_ann(body.value.to_doc())));
                }
                Effect::Unless {
                    predicate,
                    effect: body,
                } if body.value.is_terminal() => {
                    let ctx_doc = dim(unannotated_to_ann(predicate.value.to_doc()));
                    context_docs.push(ann_list_break(vec![plain_atom("context"), ctx_doc], None));
                    terminal_doc = Some(dim(unannotated_to_ann(body.value.to_doc())));
                }
                eff if eff.is_terminal() => {
                    terminal_doc = Some(dim(unannotated_to_ann(eff.to_doc())));
                }
                _ => {
                    // Non-terminal, non-evaluated effect — add dimmed to args
                    args_children.push(dim(unannotated_to_ann(effect_def.value.to_doc())));
                }
            }
        }
    }

    // Add context docs before args.
    for ctx_doc in context_docs {
        docs.push(ctx_doc);
    }

    // Only add (args ...) if there are arg predicates beyond the head atom.
    if args_children.len() > 1 {
        let args_doc = ann_list_break(args_children, None);
        docs.push(args_doc);
    }

    // Add terminal effect as sibling.
    if let Some(eff_doc) = terminal_doc {
        docs.push(eff_doc);
    }

    docs
}

/// Extract context predicate and terminal effect from a (when pred effect) doc.
fn extract_context_and_effect(
    when_doc: &ADoc,
    context_docs: &mut Vec<ADoc>,
    terminal_doc: &mut Option<ADoc>,
) {
    // The when doc structure is (when (pred-doc) (effect-doc))
    if let DocF::List(children) = &when_doc.node {
        // children: ["when", inner-list]
        // inner-list: [pred-doc, effect-doc]
        if children.len() == 2
            && let DocF::List(inner) = &children[1].node
            && inner.len() == 2
        {
            // pred is the context, effect is the terminal
            let context = ann_list_break(vec![plain_atom("context"), inner[0].clone()], None);
            context_docs.push(context);
            *terminal_doc = Some(inner[1].clone());
            return;
        }
    }
    // Fallback: couldn't extract, use as-is
    *terminal_doc = Some(when_doc.clone());
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

fn positional_arg_to_doc(p: &may_i_core::pattern::PositionalArg) -> Doc<()> {
    let inner = p.pattern.to_doc();
    match p.quantifier {
        Quantifier::One => inner,
        Quantifier::Optional => Doc::list(vec![Doc::atom("?"), inner]),
        Quantifier::OneOrMore => Doc::list(vec![Doc::atom("+"), inner]),
        Quantifier::ZeroOrMore => Doc::list(vec![Doc::atom("*"), inner]),
    }
}

fn arg_pattern_to_doc(pattern: &ArgPattern) -> Doc<()> {
    match pattern {
        ArgPattern::Positional { patterns, .. } => {
            let mut cs = vec![Doc::atom("positional")];
            cs.extend(patterns.iter().map(positional_arg_to_doc));
            Doc::list(cs)
        }
        ArgPattern::Exact { patterns, .. } => {
            let mut cs = vec![Doc::atom("exact")];
            cs.extend(patterns.iter().map(positional_arg_to_doc));
            Doc::list(cs)
        }
        ArgPattern::Anywhere(exprs) => {
            let mut cs = vec![Doc::atom("anywhere")];
            cs.extend(exprs.iter().map(|e| e.to_doc()));
            Doc::list(cs)
        }
        ArgPattern::Forbidden(exprs) => {
            // Render as (not (anywhere ...)) to match oracle output.
            let mut inner = vec![Doc::atom("anywhere")];
            inner.extend(exprs.iter().map(|e| e.to_doc()));
            Doc::list(vec![Doc::atom("not"), Doc::list(inner)])
        }
    }
}

fn fact_query_to_doc(query: &FactQuery) -> Doc<()> {
    Doc::list(vec![Doc::atom("has"), query.to_doc()])
}

/// A single trace entry produced by the fold.
#[derive(Clone)]
pub enum TraceEntry {
    /// Header for a compound command segment.
    SegmentHeader { command: String, decision: Decision },
    /// A rule evaluation with its annotated doc tree.
    Rule {
        doc: ADoc,
        line: Option<usize>,
        /// Pre-migration Doc for display when the config was migrated.
        /// The `doc` field still carries annotations; this field provides
        /// the original source structure for the left column.
        pre_migration_doc: Option<Doc<()>>,
    },
    /// No matching rule — default ask.
    DefaultAsk { reason: String },
}

/// Fold that produces `(EffectResult, Doc<Option<Ann>>)` pairs and
/// accumulates rule-level trace entries.
pub struct TracingFold {
    pub traces: Vec<TraceEntry>,
    source_text: Option<String>,
    pre_migration_forms: Option<Vec<(may_i_core::Span, Doc<()>)>>,
}

impl Default for TracingFold {
    fn default() -> Self {
        Self::new()
    }
}

impl TracingFold {
    pub fn new() -> Self {
        Self {
            traces: Vec::new(),
            source_text: None,
            pre_migration_forms: None,
        }
    }

    pub fn with_source_text(mut self, source_text: Option<String>) -> Self {
        self.source_text = source_text;
        self
    }

    pub fn with_pre_migration_forms(
        mut self,
        forms: Option<Vec<(may_i_core::Span, Doc<()>)>>,
    ) -> Self {
        self.pre_migration_forms = forms;
        self
    }

    fn line_of(&self, byte_offset: usize) -> Option<usize> {
        let text = self.source_text.as_ref()?;
        Some(text[..byte_offset.min(text.len())].matches('\n').count() + 1)
    }

    /// Find the pre-migration Doc whose span contains the given byte offset.
    fn find_pre_migration_doc(&self, span: may_i_core::Span) -> Option<Doc<()>> {
        let forms = self.pre_migration_forms.as_ref()?;
        forms
            .iter()
            .find(|(form_span, _)| form_span.start <= span.start && span.start < form_span.end)
            .map(|(_, doc)| doc.clone())
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
        let ann = Some(Ann::ArgMatch {
            search_tokens: detail.search_tokens.clone(),
            arg_set: detail.arg_set.clone(),
            matched,
        });
        // For forbidden patterns (rendered as (not (anywhere ...))),
        // also annotate the inner (anywhere ...) node so truncation logic
        // can see it. The inner matched is inverted: forbidden matched=true
        // means no tokens found, but the inner anywhere matched should be false.
        let ann_doc = if matches!(pattern, ArgPattern::Forbidden(_)) {
            if let DocF::List(mut children) = doc.node {
                if children.len() == 2 {
                    let inner_ann = Some(Ann::ArgMatch {
                        search_tokens: detail.search_tokens.clone(),
                        arg_set: detail.arg_set.clone(),
                        matched: !matched,
                    });
                    children[1] = Doc {
                        ann: inner_ann,
                        ..children[1].clone()
                    };
                }
                Doc {
                    ann,
                    node: DocF::List(children),
                    layout: doc.layout,
                    dimmed: doc.dimmed,
                }
            } else {
                Doc { ann, ..doc }
            }
        } else {
            Doc { ann, ..doc }
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
        body_effect: &Effect,
        result: EffectResult,
    ) -> Self::EffectOut {
        let body_doc = match body {
            ChildResult::Evaluated((_, doc)) => doc,
            ChildResult::Skipped => dim(effect_to_static_ann_doc(body_effect)),
        };
        let inner = ann_list(vec![pred.1, body_doc], None);
        let docs = vec![plain_atom("when"), inner];
        let ann = Some(Ann::Combinator {
            result_is_nil: result.is_nil(),
        });
        (result, ann_list_break(docs, ann))
    }

    fn effect_unless(
        &mut self,
        pred: Self::PredicateOut,
        body: ChildResult<Self::EffectOut>,
        body_effect: &Effect,
        result: EffectResult,
    ) -> Self::EffectOut {
        let body_doc = match body {
            ChildResult::Evaluated((_, doc)) => doc,
            ChildResult::Skipped => dim(effect_to_static_ann_doc(body_effect)),
        };
        let inner = ann_list(vec![pred.1, body_doc], None);
        let docs = vec![plain_atom("unless"), inner];
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

    fn effect_arg_continuation(
        &mut self,
        pattern: &ArgPattern,
        args: &[String],
        detail: ArgMatchDetail,
        continuation: Self::EffectOut,
    ) -> Self::EffectOut {
        let result = continuation.0.clone();
        let doc = unannotated_to_ann(arg_pattern_to_doc(pattern));
        let ann_doc = Doc {
            ann: Some(Ann::ArgMatch {
                search_tokens: detail.search_tokens,
                arg_set: detail.arg_set,
                matched: detail.matched,
            }),
            ..doc
        };
        // Wrap: (positional ... continuation-doc)
        let mut children = match ann_doc.node {
            DocF::List(cs) => cs,
            _ => vec![ann_doc],
        };
        children.push(continuation.1);
        let _ = args;
        let wrapper = Doc {
            ann: Some(Ann::ArgMatch {
                search_tokens: vec![],
                arg_set: vec![],
                matched: detail.matched,
            }),
            node: DocF::List(children),
            layout: LayoutHint::AlwaysBreak,
            dimmed: false,
        };
        (result, wrapper)
    }

    fn effect_may_i(
        &mut self,
        pattern: &ArgPattern,
        inner_cmd: &str,
        inner_args: &[String],
        inner_result: EffectResult,
        _inner_out: Self::EffectOut,
    ) -> Self::EffectOut {
        let cmd_str = if inner_args.is_empty() {
            inner_cmd.to_string()
        } else {
            format!("{} {}", inner_cmd, inner_args.join(" "))
        };
        let (decision, reason) = match &inner_result {
            EffectResult::Decision(d, r) => (*d, r.clone()),
            EffectResult::Nil => (Decision::Ask, None),
        };
        let doc = unannotated_to_ann(arg_pattern_to_doc(pattern));
        let docs = vec![plain_atom("may-i"), doc];
        let ann = Some(Ann::MayI {
            inner_command: cmd_str,
            decision,
            reason,
        });
        (inner_result, ann_list(docs, ann))
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
        rule: &Rule,
        _line: Option<usize>,
        command_out: Self::EffectOut,
        effects: Vec<Self::EffectOut>,
    ) -> Self::EffectOut {
        let line = self.line_of(rule.span.start);
        let pre_migration_doc = self.find_pre_migration_doc(rule.span);
        let ann = Some(Ann::RuleMatch {
            matched: true,
            line,
        });
        let terminal_result = effects
            .last()
            .map(|e| e.0.clone())
            .unwrap_or(EffectResult::Nil);

        let docs = build_rule_doc_children(rule, command_out, effects);
        let doc = ann_list_break(docs, ann);
        self.traces.push(TraceEntry::Rule {
            doc: doc.clone(),
            line,
            pre_migration_doc,
        });
        (terminal_result, doc)
    }

    fn rule_not_matched(
        &mut self,
        rule: &Rule,
        command_out: Self::EffectOut,
        effects: Vec<Self::EffectOut>,
    ) -> Self::EffectOut {
        // Command matched but args/context didn't — still show in trace.
        let line = self.line_of(rule.span.start);
        let pre_migration_doc = self.find_pre_migration_doc(rule.span);
        let ann = Some(Ann::RuleMatch {
            matched: false,
            line,
        });

        let docs = build_rule_doc_children(rule, command_out, effects);
        let doc = ann_list_break(docs, ann);
        self.traces.push(TraceEntry::Rule {
            doc: doc.clone(),
            line,
            pre_migration_doc,
        });
        (EffectResult::Nil, doc)
    }

    fn rule_skipped(&mut self, _rule: &Rule) -> Self::EffectOut {
        // Command didn't match at all — don't add to trace.
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
