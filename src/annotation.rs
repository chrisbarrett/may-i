// Annotation types and TracingFold for producing annotated Doc trees.
//
// Lives in the CLI binary so `Doc` never enters the engine crate.

use may_i_core::ast::{Effect, EffectResult, Rule};
use may_i_core::doc::{Doc, DocF, LayoutHint};
use may_i_core::pattern::{ArgPattern, CommandPattern, MatchMode, Quantifier};
use may_i_core::primitives::ToDoc;
use may_i_core::trivia::{Trivia, TriviaSource};
use may_i_core::{ContextFacts, Decision, FactQuery};

use may_i_engine::eval::PredicateResult;
use may_i_engine::fold::{
    ArgMatchDetail, ChildResult, EvalFold, FactDetail, PositionalElementDetail, PositionalMatchKind,
};

/// Annotation carried on each Doc node in a trace.
///
/// Public because `TraceEntry::Rule::doc` exposes `Doc<Option<Ann>>` and
/// `TraceEntry` is used by integration tests via `evaluate_segments`.
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
    /// Bind expression matched with captured value.
    BindMatch { key: String, value: Option<String> },
    /// Regex match result.
    RegexMatch {
        pattern: String,
        actual: String,
        matched: bool,
    },
    /// Positional pattern comparison: actual arg vs pattern literal.
    PositionalMatch {
        actual_arg: String,
        pattern_text: String,
        matched: bool,
    },
    /// Quantifier/combinator result.
    Combinator { result_is_nil: bool },
    /// Rule-level annotation.
    RuleMatch { matched: bool, line: Option<usize> },
    /// Named predicate (define) reference with its resolved body.
    VarRef { name: String, matched: bool },
}

impl TriviaSource for Ann {
    fn forced_break(&self) -> bool {
        false
    }
    fn leading_trivia(&self) -> &[Trivia] {
        &[]
    }
    fn trailing_trivia(&self) -> &[Trivia] {
        &[]
    }
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
        Effect::Terminal { decision, reason } => Doc {
            ann: Some(Ann::EffectDecision {
                decision: *decision,
                reason: reason.clone(),
            }),
            ..doc
        },
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
fn build_rule_doc_children(
    rule: &Rule,
    command_out: (EffectResult, ADoc),
    effect_out: (EffectResult, ADoc),
) -> Vec<ADoc> {
    use may_i_core::ast::Effect;
    let command_doc = ann_list(vec![plain_atom("command"), command_out.1], None);
    let mut docs = vec![plain_atom("rule"), command_doc];

    // Decompose the single body effect for display.
    let mut context_docs: Vec<ADoc> = Vec::new();
    let mut terminal_doc: Option<ADoc> = None;
    let mut args_children = vec![plain_atom("args")];

    match &rule.effect.value {
        Effect::When {
            predicate: _,
            effect: body,
        } if body.value.is_terminal() => {
            extract_context_and_effect(&effect_out.1, &mut context_docs, &mut terminal_doc);
        }
        Effect::Unless {
            predicate: _,
            effect: body,
        } if body.value.is_terminal() => {
            extract_context_and_effect(&effect_out.1, &mut context_docs, &mut terminal_doc);
        }
        eff if eff.is_terminal() => {
            terminal_doc = Some(effect_out.1.clone());
        }
        _ => {
            args_children.push(effect_out.1.clone());
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
    // The when doc structure is (when pred-doc effect-doc)
    if let DocF::List(children) = &when_doc.node
        && children.len() == 3
    {
        let context = ann_list_break(vec![plain_atom("context"), children[1].clone()], None);
        context_docs.push(context);
        *terminal_doc = Some(children[2].clone());
        return;
    }
    // Fallback: couldn't extract, use as-is
    *terminal_doc = Some(when_doc.clone());
}

fn command_pattern_to_doc(pattern: &CommandPattern) -> Doc<()> {
    match pattern {
        CommandPattern::Literal(s) => Doc::atom(format!("\"{}\"", s)),
        CommandPattern::Or(patterns) => {
            let mut cs = vec![Doc::atom("or")];
            cs.extend(patterns.iter().map(command_pattern_to_doc));
            if patterns.len() > 4 {
                Doc::broken_list(cs)
            } else {
                Doc::list(cs)
            }
        }
        _ => Doc::atom("<unknown-command-pattern>"),
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
        ArgPattern::Ordered {
            mode: MatchMode::Positional,
            patterns,
            ..
        } => {
            let mut cs = vec![Doc::atom("positional")];
            cs.extend(patterns.iter().map(positional_arg_to_doc));
            Doc::list(cs)
        }
        ArgPattern::Ordered {
            mode: MatchMode::Exact,
            patterns,
            ..
        } => {
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
            let mut inner = vec![Doc::atom("anywhere")];
            inner.extend(exprs.iter().map(|e| e.to_doc()));
            Doc::list(vec![Doc::atom("not"), Doc::list(inner)])
        }
        ArgPattern::Flag { names } => {
            let names_doc = flag_names_to_doc(names);
            Doc::list(vec![Doc::atom("flag"), names_doc])
        }
        ArgPattern::Parameter { names, form } => {
            let names_doc = flag_names_to_doc(names);
            let form_doc = match form {
                may_i_core::pattern::ParameterForm::Match(expr) => expr.to_doc(),
                may_i_core::pattern::ParameterForm::MayI => {
                    Doc::list(vec![Doc::atom("may-i"), Doc::atom("*")])
                }
            };
            Doc::list(vec![Doc::atom("parameter"), names_doc, form_doc])
        }
        _ => Doc::atom("<unknown-arg-pattern>"),
    }
}

fn flag_names_to_doc(names: &[String]) -> Doc<()> {
    if names.len() == 1 {
        Doc::atom(format!("\"{}\"", names[0]))
    } else {
        Doc::vector(
            names
                .iter()
                .map(|n| Doc::atom(format!("\"{n}\"")))
                .collect(),
        )
    }
}

fn fact_query_to_doc(query: &FactQuery) -> Doc<()> {
    Doc::list(vec![Doc::atom("has"), query.to_doc()])
}

/// Annotate a positional/exact pattern doc with per-element match details
/// (bindings, regex matches). Walks the doc children (skipping the head atom)
/// and matches them against the element details by index.
fn annotate_positional_elements(doc: ADoc, elements: &[PositionalElementDetail]) -> ADoc {
    if elements.is_empty() {
        return doc;
    }
    match doc.node {
        DocF::List(children) if !children.is_empty() => {
            let head = children.first().and_then(|c| c.as_atom());
            if !matches!(head, Some("positional" | "exact")) {
                return Doc {
                    node: DocF::List(children),
                    ..doc
                };
            }
            let mut new_children = vec![children[0].clone()];
            let mut elem_idx = 0;
            for child in children.into_iter().skip(1) {
                if elem_idx < elements.len() {
                    new_children.push(annotate_pattern_element(child, &elements[elem_idx]));
                    elem_idx += 1;
                } else {
                    new_children.push(child);
                }
            }
            Doc {
                node: DocF::List(new_children),
                ..doc
            }
        }
        _ => doc,
    }
}

/// Annotate a single pattern element (which may be a vector for binds,
/// an atom for literals/wildcards, or a list for regex/quantifiers).
fn annotate_pattern_element(doc: ADoc, detail: &PositionalElementDetail) -> ADoc {
    // Handle bind: doc is a Vector [":key", expr]
    if let Some(bind) = &detail.binding
        && let DocF::Vector(children) = &doc.node
    {
        let mut new_children = children.clone();
        // Annotate the inner expression if there's detail
        if new_children.len() >= 2
            && let Some(inner) = &bind.inner_match
        {
            new_children[1] = annotate_expr_match(new_children[1].clone(), inner);
        }
        return Doc {
            ann: Some(Ann::BindMatch {
                key: bind.key.to_string(),
                value: bind.value.clone(),
            }),
            node: DocF::Vector(new_children),
            ..doc
        };
    }

    // Handle regex/literal on non-bind expressions
    if let PositionalMatchKind::Expr(expr_match) = &detail.match_kind {
        return annotate_expr_match(doc, expr_match);
    }

    // Handle quantifier wrappers: (? expr), (* expr), (+ expr)
    if let DocF::List(children) = &doc.node {
        let head = children.first().and_then(|c| c.as_atom());
        if matches!(head, Some("?" | "+" | "*")) && children.len() >= 2 {
            let mut new_children = children.clone();
            new_children[1] = annotate_pattern_element(new_children[1].clone(), detail);
            return Doc {
                node: DocF::List(new_children),
                ..doc
            };
        }
    }

    doc
}

/// Move an annotation to a cond branch body within the positional children.
///
/// When a positional pattern has a trailing `Expr::Cond` with no explicit
/// continuation, `resolve_trailing_cond_effect` extracts the matching branch's
/// effect and evaluates it as a continuation. This creates a duplicate
/// `(effect :keyword)` node. This function places the evaluated annotation on
/// the original cond branch body so the annotation renders on the correct line.
fn move_ann_to_cond_branch(children: &mut [ADoc], branch_idx: usize, ann: Ann) {
    // Find the cond child among the positional children (a list starting with "cond").
    for child in children.iter_mut() {
        if let DocF::List(cond_children) = &mut child.node {
            let is_cond = cond_children.first().and_then(|c| c.as_atom()) == Some("cond");
            if !is_cond {
                continue;
            }
            // Cond children: ["cond", clause0, clause1, ...]
            let clause_idx = branch_idx + 1;
            if clause_idx >= cond_children.len() {
                continue;
            }
            // Each clause is a list: (test body)
            if let DocF::List(clause_parts) = &mut cond_children[clause_idx].node
                && let Some(body) = clause_parts.last_mut()
            {
                body.ann = Some(ann);
                return;
            }
        }
    }
}

/// Annotate an expression doc node with match detail (regex, literal).
fn annotate_expr_match(doc: ADoc, detail: &may_i_engine::fold::ExprMatchDetail) -> ADoc {
    use may_i_engine::fold::ExprMatchDetail;
    match detail {
        ExprMatchDetail::Regex {
            pattern,
            actual,
            matched,
        } => Doc {
            ann: Some(Ann::RegexMatch {
                pattern: pattern.clone(),
                actual: actual.clone(),
                matched: *matched,
            }),
            ..doc
        },
        _ => doc,
    }
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
        /// Context facts that were active when this rule was evaluated.
        /// Non-empty only for recursive evaluations where facts were bound.
        facts: Vec<(String, String)>,
        /// The command being evaluated, when this rule is inside a recursive
        /// `may-i` evaluation.
        inner_command: Option<String>,
    },
    /// An embedded command (substitution) was evaluated.
    EmbeddedCommand { source: String, decision: Decision },
    /// No matching rule — default ask.
    DefaultAsk { reason: String },
    /// Parse diagnostics were emitted.
    ParseDiagnostics {
        diagnostics: Vec<may_i_shell_parser::ParseDiagnostic>,
    },
    /// Resolved parser (style + parameter spellings) for the command
    /// being evaluated.
    Parser {
        command: String,
        style: String,
        parameter_tokens: Vec<String>,
        /// Wrapper-tail boundary spec when the parser declares a tail.
        /// `None` for parsers that consume the whole argv.
        tail: Option<String>,
    },
}

/// Fold that produces `(EffectResult, Doc<Option<Ann>>)` pairs and
/// accumulates rule-level trace entries.
pub(crate) struct TracingFold {
    pub traces: Vec<TraceEntry>,
    source_text: Option<String>,
    pre_migration_forms: Option<Vec<(may_i_core::Span, Doc<()>)>>,
    /// Stack of trace positions saved before recursive may-i evaluations.
    recursive_trace_starts: Vec<usize>,
    /// Inner traces extracted from recursive evaluations, waiting to be
    /// appended after the outer rule's trace entry. Each entry is
    /// (inner_command, traces).
    pending_inner_traces: Vec<(String, Vec<TraceEntry>)>,
}

impl Default for TracingFold {
    fn default() -> Self {
        Self::new()
    }
}

impl TracingFold {
    pub(crate) fn new() -> Self {
        Self {
            traces: Vec::new(),
            source_text: None,
            pre_migration_forms: None,
            recursive_trace_starts: Vec::new(),
            pending_inner_traces: Vec::new(),
        }
    }

    pub(crate) fn from_load_result(lr: &may_i_config::LoadResult) -> Self {
        Self {
            traces: Vec::new(),
            source_text: lr.source_text.clone(),
            pre_migration_forms: lr.pre_migration_forms.clone(),
            recursive_trace_starts: Vec::new(),
            pending_inner_traces: Vec::new(),
        }
    }

    /// Append inner traces from a recursive may-i evaluation, tagging the
    /// first entry with the inner command string.
    fn append_inner_traces(&mut self, (cmd, mut traces): (String, Vec<TraceEntry>)) {
        if let Some(TraceEntry::Rule { inner_command, .. }) = traces.first_mut() {
            *inner_command = Some(cmd);
        }
        self.traces.extend(traces);
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

    fn effect_terminal(&mut self, _effect: &Effect, result: EffectResult) -> Self::EffectOut {
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
        let doc = annotate_positional_elements(doc, &detail.positional_elements);
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
        body_effect: &Effect,
        result: EffectResult,
    ) -> Self::EffectOut {
        let body_doc = match body {
            ChildResult::Evaluated((_, doc)) => doc,
            ChildResult::Skipped => dim(effect_to_static_ann_doc(body_effect)),
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
        branches: Vec<(
            ChildResult<Self::PredicateOut>,
            ChildResult<Self::EffectOut>,
        )>,
        fallback: Option<ChildResult<Self::EffectOut>>,
        result: EffectResult,
    ) -> Self::EffectOut {
        let mut docs = vec![plain_atom("cond")];

        // Find where trailing (Skipped, Skipped) branches start.
        let trailing_skipped_start = {
            let mut start = branches.len();
            for (i, (pred, body)) in branches.iter().enumerate().rev() {
                if matches!((pred, body), (ChildResult::Skipped, ChildResult::Skipped)) {
                    start = i;
                } else {
                    break;
                }
            }
            start
        };
        let has_trailing_skipped = trailing_skipped_start < branches.len();

        for (i, (pred, body)) in branches.into_iter().enumerate() {
            if i >= trailing_skipped_start {
                break;
            }
            let pred_doc = match pred {
                ChildResult::Evaluated((_, doc)) => doc,
                ChildResult::Skipped => dim(plain_atom("…")),
            };
            let body_doc = match body {
                ChildResult::Evaluated((_, doc)) => doc,
                ChildResult::Skipped => dim(plain_atom("…")),
            };
            docs.push(ann_list(vec![pred_doc, body_doc], None));
        }

        if has_trailing_skipped {
            // Collapse all trailing skipped branches (and skipped fallback) into one ellipsis.
            docs.push(dim(plain_atom("…")));
        } else if let Some(fb) = fallback {
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
        _args: &[String],
        detail: ArgMatchDetail,
        continuation: Self::EffectOut,
    ) -> Self::EffectOut {
        let result = continuation.0.clone();
        let doc = unannotated_to_ann(arg_pattern_to_doc(pattern));
        let doc = annotate_positional_elements(doc, &detail.positional_elements);
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

        // If the continuation came from a trailing cond (no explicit continuation),
        // move the EffectDecision annotation to the matching cond branch body so it
        // renders on the correct line rather than on the duplicate continuation.
        let trailing_cond_branch = match pattern {
            ArgPattern::Ordered {
                mode: MatchMode::Positional,
                continuation: None,
                ..
            }
            | ArgPattern::Ordered {
                mode: MatchMode::Exact,
                continuation: None,
                ..
            } => detail
                .positional_elements
                .last()
                .and_then(|e| match e.match_kind {
                    PositionalMatchKind::CondBranch(idx) => Some(idx),
                    _ => None,
                }),
            _ => None,
        };

        if let Some(branch_idx) = trailing_cond_branch {
            if let Some(ref effect_ann @ Ann::EffectDecision { .. }) = continuation.1.ann {
                move_ann_to_cond_branch(&mut children, branch_idx, effect_ann.clone());
            }
            // Push continuation without the EffectDecision annotation
            children.push(Doc {
                ann: None,
                ..continuation.1
            });
        } else {
            children.push(continuation.1);
        }

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

    fn begin_recursive_eval(&mut self) {
        self.recursive_trace_starts.push(self.traces.len());
    }

    fn record_parser(&mut self, command: &str, parser: &may_i_core::ast::ResolvedParser) {
        let tail = parser.tail.as_ref().map(|t| match t {
            may_i_core::ast::Tail::AfterFlags => "(after :flags)".to_string(),
            may_i_core::ast::Tail::AfterToken(s) => format!("(after {s:?})"),
        });
        self.traces.push(TraceEntry::Parser {
            command: command.to_string(),
            style: parser.style.name().to_string(),
            parameter_tokens: parser.parameter_tokens(),
            tail,
        });
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

        // Extract inner traces that were added during recursive evaluation.
        if let Some(start) = self.recursive_trace_starts.pop() {
            let inner_traces: Vec<TraceEntry> = self.traces.drain(start..).collect();
            self.pending_inner_traces
                .push((cmd_str.clone(), inner_traces));
        }

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
        let matched = resolved.0 == PredicateResult::Match;
        let ann = Some(Ann::VarRef {
            name: name.to_string(),
            matched,
        });
        let docs = vec![plain_atom(name), resolved.1];
        (resolved.0, ann_list(docs, ann))
    }

    fn rule_matched(
        &mut self,
        rule: &Rule,
        _line: Option<usize>,
        facts: &ContextFacts,
        command_out: Self::EffectOut,
        effect_out: Self::EffectOut,
    ) -> Self::EffectOut {
        let line = self.line_of(rule.span.start);
        let pre_migration_doc = self.find_pre_migration_doc(rule.span);
        let ann = Some(Ann::RuleMatch {
            matched: true,
            line,
        });
        let terminal_result = effect_out.0.clone();

        let docs = build_rule_doc_children(rule, command_out, effect_out);
        let doc = ann_list_break(docs, ann);
        self.traces.push(TraceEntry::Rule {
            doc: doc.clone(),
            line,
            pre_migration_doc,
            facts: flatten_facts(facts),
            inner_command: None,
        });
        // Append inner traces from recursive may-i evaluations after the
        // outer rule, so the trace reads in evaluation order.
        if let Some(inner) = self.pending_inner_traces.pop() {
            self.append_inner_traces(inner);
        }
        (terminal_result, doc)
    }

    fn rule_not_matched(
        &mut self,
        rule: &Rule,
        facts: &ContextFacts,
        command_out: Self::EffectOut,
        effect_out: Self::EffectOut,
    ) -> Self::EffectOut {
        // Command matched but body effect returned Nil — still show in trace.
        let line = self.line_of(rule.span.start);
        let pre_migration_doc = self.find_pre_migration_doc(rule.span);
        let ann = Some(Ann::RuleMatch {
            matched: false,
            line,
        });

        let docs = build_rule_doc_children(rule, command_out, effect_out);
        let doc = ann_list_break(docs, ann);
        self.traces.push(TraceEntry::Rule {
            doc: doc.clone(),
            line,
            pre_migration_doc,
            facts: flatten_facts(facts),
            inner_command: None,
        });
        if let Some(inner) = self.pending_inner_traces.pop() {
            self.append_inner_traces(inner);
        }
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

    fn embedded_command(&mut self, source: &str, decision: Decision) {
        self.traces.push(TraceEntry::EmbeddedCommand {
            source: source.to_string(),
            decision,
        });
    }
}

/// Flatten all facts into (key, value) pairs.
fn flatten_facts(facts: &ContextFacts) -> Vec<(String, String)> {
    facts
        .iter()
        .flat_map(|(k, vs)| vs.iter().map(move |v| (k.to_string(), v.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::ast::{Config, Predicate, Spanned};
    use may_i_core::pattern::PositionalArg;
    use may_i_core::{FactQuery, Keyword, Span};
    use may_i_engine::eval::{EvalContext, Evaluator, evaluate_with_fold};
    use may_i_engine::fold::PureFold;
    use may_i_engine::test_generators::*;
    use proptest::prelude::*;

    fn dummy_span() -> Span {
        Span::new(0, 0)
    }

    fn spanned<T>(value: T) -> Spanned<T> {
        Spanned::new(value, dummy_span())
    }

    fn make_config(rules: Vec<Rule>) -> Config {
        Config {
            rules,
            ..Config::default()
        }
    }

    fn make_rule(command: CommandPattern, effect: Effect) -> Rule {
        Rule::new(
            spanned(Effect::CommandPattern(command)),
            spanned(effect),
            vec![],
            dummy_span(),
        )
    }

    fn presence_query(key: &str) -> FactQuery {
        FactQuery::Presence {
            key: Keyword::new(key).unwrap(),
        }
    }

    fn eval_tracing(config: &Config, cmd: &str, args: &[String]) -> Vec<TraceEntry> {
        let facts = ContextFacts::default();
        let mut fold = TracingFold::new();
        evaluate_with_fold(cmd, args, config, &facts, &mut fold).unwrap();
        fold.traces
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        #[test]
        fn tracing_fold_agrees_with_pure_fold(
            config in any_config(3),
            data in any_eval_context_data(),
        ) {
            let (cmd, args, facts) = data;
            let ctx = EvalContext::new(&cmd, &args, &facts, EvalContext::build_bindings(&config.defines));

            let evaluator = Evaluator::new(&config.rules);

            let pure_result = evaluator.evaluate(&mut PureFold, &ctx)
                .expect("evaluation should not fail on resolved config");
            let tracing_result = evaluator.evaluate(&mut TracingFold::new(), &ctx)
                .expect("evaluation should not fail on resolved config");

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

    #[test]
    fn tracing_fold_default_ask() {
        let config = make_config(vec![make_rule(
            CommandPattern::Literal("other".into()),
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
        )]);
        let entries = eval_tracing(&config, "git", &[]);
        assert!(
            entries
                .iter()
                .any(|e| matches!(e, TraceEntry::DefaultAsk { .. })),
            "should produce DefaultAsk when no rule matches"
        );
    }

    #[test]
    fn tracing_fold_command_match_or() {
        let config = make_config(vec![make_rule(
            CommandPattern::Or(vec![
                CommandPattern::Literal("git".into()),
                CommandPattern::Literal("svn".into()),
            ]),
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
        )]);
        let entries = eval_tracing(&config, "git", &[]);
        assert!(entries.iter().any(|e| matches!(e, TraceEntry::Rule { .. })));
    }

    #[test]
    fn tracing_fold_from_load_result() {
        let lr = may_i_config::LoadResult {
            config: Config::default(),
            source_text: Some("(rule \"git\" :allow)".into()),
            pre_migration_forms: Some(vec![(Span::new(0, 10), Doc::<()>::atom("test"))]),
            config_path: std::path::PathBuf::from("/tmp/test.lisp"),
        };
        let fold = TracingFold::from_load_result(&lr);
        assert!(fold.source_text.is_some());
        assert!(fold.pre_migration_forms.is_some());
    }

    #[test]
    fn tracing_fold_cond_effect() {
        let config = make_config(vec![make_rule(
            CommandPattern::Literal("git".into()),
            Effect::Cond {
                branches: vec![(
                    spanned(Predicate::Fact(presence_query(":env"))),
                    spanned(Effect::Terminal {
                        decision: Decision::Allow,
                        reason: None,
                    }),
                )],
                fallback: Some(Box::new(spanned(Effect::Terminal {
                    decision: Decision::Deny,
                    reason: Some(String::from("no env")),
                }))),
            },
        )]);
        let entries = eval_tracing(&config, "git", &[]);
        assert!(entries.iter().any(|e| matches!(e, TraceEntry::Rule { .. })));
    }

    #[test]
    fn tracing_fold_when_terminal_context() {
        let config = make_config(vec![make_rule(
            CommandPattern::Literal("git".into()),
            Effect::When {
                predicate: spanned(Predicate::Fact(presence_query(":safe"))),
                effect: Box::new(spanned(Effect::Terminal {
                    decision: Decision::Allow,
                    reason: None,
                })),
            },
        )]);
        let entries = eval_tracing(&config, "git", &[]);
        assert!(entries.iter().any(|e| matches!(e, TraceEntry::Rule { .. })));
    }

    #[test]
    fn tracing_fold_arg_continuation() {
        let config = make_config(vec![make_rule(
            CommandPattern::Literal("git".into()),
            Effect::And {
                effects: vec![
                    spanned(Effect::ArgPattern(ArgPattern::Ordered {
                        mode: MatchMode::Positional,
                        patterns: vec![PositionalArg {
                            quantifier: Quantifier::One,
                            pattern: may_i_core::pattern::Expr::Literal("push".into()),
                            recursive: false,
                        }],
                        continuation: None,
                    })),
                    spanned(Effect::Terminal {
                        decision: Decision::Allow,
                        reason: None,
                    }),
                ],
            },
        )]);
        let entries = eval_tracing(&config, "git", &["push".to_string()]);
        assert!(entries.iter().any(|e| matches!(e, TraceEntry::Rule { .. })));
    }

    #[test]
    fn tracing_fold_effect_nil_on_false_predicate() {
        let config = make_config(vec![make_rule(
            CommandPattern::Literal("git".into()),
            Effect::When {
                predicate: spanned(Predicate::Fact(presence_query(":nonexistent"))),
                effect: Box::new(spanned(Effect::Terminal {
                    decision: Decision::Allow,
                    reason: None,
                })),
            },
        )]);
        let facts = ContextFacts::default();
        let mut fold = TracingFold::new();
        evaluate_with_fold("git", &[], &config, &facts, &mut fold).unwrap();
        assert!(!fold.traces.is_empty());
    }

    #[test]
    fn tracing_fold_with_facts() {
        let config = make_config(vec![make_rule(
            CommandPattern::Literal("git".into()),
            Effect::When {
                predicate: spanned(Predicate::Fact(presence_query(":safe"))),
                effect: Box::new(spanned(Effect::Terminal {
                    decision: Decision::Allow,
                    reason: None,
                })),
            },
        )]);
        let mut facts = ContextFacts::default();
        facts.insert_present(Keyword::new(":safe").unwrap());
        let mut fold = TracingFold::new();
        evaluate_with_fold("git", &[], &config, &facts, &mut fold).unwrap();
        assert!(
            fold.traces
                .iter()
                .any(|e| matches!(e, TraceEntry::Rule { .. }))
        );
    }

    #[test]
    fn flatten_facts_produces_pairs() {
        let mut facts = ContextFacts::default();
        facts.insert_scalar(Keyword::new(":env").unwrap(), String::from("prod"));
        facts.insert_scalar(Keyword::new(":host").unwrap(), String::from("example.com"));
        let pairs = flatten_facts(&facts);
        assert_eq!(pairs.len(), 2);
        assert!(pairs.iter().any(|(k, _)| k == ":env"));
        assert!(pairs.iter().any(|(k, _)| k == ":host"));
    }

    #[test]
    fn command_pattern_to_doc_or() {
        let pat = CommandPattern::Or(vec![
            CommandPattern::Literal("a".into()),
            CommandPattern::Literal("b".into()),
        ]);
        let doc = command_pattern_to_doc(&pat);
        match &doc.node {
            DocF::List(cs) => assert_eq!(cs[0].as_atom(), Some("or")),
            _ => panic!("expected list for or pattern"),
        }
    }

    #[test]
    fn command_pattern_to_doc_or_broken_when_large() {
        let pat = CommandPattern::Or(
            (0..6)
                .map(|i| CommandPattern::Literal(format!("cmd{}", i)))
                .collect(),
        );
        let doc = command_pattern_to_doc(&pat);
        assert_eq!(doc.layout, LayoutHint::AlwaysBreak);
    }

    #[test]
    fn predicate_named_produces_var_ref_annotation() {
        use may_i_engine::fold::EvalFold;

        let mut fold = TracingFold::new();
        let child_doc = plain_atom("child-body");
        let child = (PredicateResult::Match, child_doc);
        let result = fold.predicate_named("build-mode", child, PredicateResult::Match);

        // The output doc should be annotated with VarRef
        assert!(
            matches!(
                &result.1.ann,
                Some(Ann::VarRef { name, matched: true }) if name == "build-mode"
            ),
            "expected VarRef annotation, got {:?}",
            result.1.ann
        );
        // Should contain the name atom and child body as children
        match &result.1.node {
            DocF::List(children) => {
                assert!(children.len() >= 2, "expected at least 2 children");
            }
            other => panic!("expected List node, got {:?}", other),
        }
    }

    #[test]
    fn predicate_named_no_match_produces_var_ref_unmatched() {
        use may_i_engine::fold::EvalFold;

        let mut fold = TracingFold::new();
        let child_doc = plain_atom("child-body");
        let child = (PredicateResult::NoMatch, child_doc);
        let result = fold.predicate_named("build-mode", child, PredicateResult::NoMatch);

        assert!(
            matches!(
                &result.1.ann,
                Some(Ann::VarRef { name, matched: false }) if name == "build-mode"
            ),
            "expected unmatched VarRef annotation, got {:?}",
            result.1.ann
        );
    }

    // --- Cond trailing-branch collapsing tests ---

    /// Recursively find a doc node whose head atom matches `name`.
    fn find_doc_by_head<'a>(doc: &'a ADoc, name: &str) -> Option<&'a ADoc> {
        if doc.head_atom() == Some(name) {
            return Some(doc);
        }
        if let Some(children) = doc.children() {
            for child in children {
                if let Some(found) = find_doc_by_head(child, name) {
                    return Some(found);
                }
            }
        }
        None
    }

    fn extract_cond_doc(entries: &[TraceEntry]) -> &ADoc {
        for entry in entries {
            if let TraceEntry::Rule { doc, .. } = entry
                && let Some(cond_doc) = find_doc_by_head(doc, "cond")
            {
                return cond_doc;
            }
        }
        panic!("no cond doc found in trace entries");
    }

    fn make_cond_branches(count: usize) -> Vec<(Spanned<Predicate>, Spanned<Effect>)> {
        (0..count)
            .map(|i| {
                (
                    spanned(Predicate::Fact(presence_query(
                        // Use different keys so branches are distinguishable
                        Box::leak(format!(":key{}", i).into_boxed_str()) as &str,
                    ))),
                    spanned(Effect::Terminal {
                        decision: Decision::Allow,
                        reason: None,
                    }),
                )
            })
            .collect()
    }

    #[test]
    fn cond_collapse_match_in_middle() {
        // Branch 0: :key0 absent → predicate evaluates false
        // Branch 1: :key1 present → matches, short-circuits
        // Branches 2-3: skipped → should collapse to single …
        let mut facts = ContextFacts::default();
        facts.insert_present(Keyword::new(":key1").unwrap());

        let config = make_config(vec![make_rule(
            CommandPattern::Literal("git".into()),
            Effect::Cond {
                branches: make_cond_branches(4),
                fallback: Some(Box::new(spanned(Effect::Terminal {
                    decision: Decision::Deny,
                    reason: None,
                }))),
            },
        )]);
        let mut fold = TracingFold::new();
        evaluate_with_fold("git", &[], &config, &facts, &mut fold).unwrap();
        let cond_doc = extract_cond_doc(&fold.traces);
        let children = cond_doc.children().expect("cond should be a list");

        // children: ["cond", branch0, branch1, "…"]
        assert_eq!(
            children.len(),
            4,
            "expected cond + 2 branches + 1 ellipsis, got {} children",
            children.len()
        );
        assert_eq!(children[0].as_atom(), Some("cond"));
        // Last child should be a dimmed ellipsis atom
        let last = &children[3];
        assert_eq!(last.as_atom(), Some("…"));
        assert!(last.dimmed, "trailing ellipsis should be dimmed");
    }

    #[test]
    fn cond_collapse_match_at_first_branch() {
        // Branch 0: :key0 present → matches immediately
        // Branches 1-3: skipped → should collapse to single …
        let mut facts = ContextFacts::default();
        facts.insert_present(Keyword::new(":key0").unwrap());

        let config = make_config(vec![make_rule(
            CommandPattern::Literal("git".into()),
            Effect::Cond {
                branches: make_cond_branches(4),
                fallback: None,
            },
        )]);
        let mut fold = TracingFold::new();
        evaluate_with_fold("git", &[], &config, &facts, &mut fold).unwrap();
        let cond_doc = extract_cond_doc(&fold.traces);
        let children = cond_doc.children().expect("cond should be a list");

        // children: ["cond", branch0, "…"]
        assert_eq!(
            children.len(),
            3,
            "expected cond + 1 branch + 1 ellipsis, got {} children",
            children.len()
        );
        assert_eq!(children[2].as_atom(), Some("…"));
        assert!(children[2].dimmed);
    }

    #[test]
    fn cond_no_collapse_when_all_evaluated() {
        // No facts match → all predicates evaluated to false, fallback used
        let config = make_config(vec![make_rule(
            CommandPattern::Literal("git".into()),
            Effect::Cond {
                branches: make_cond_branches(3),
                fallback: Some(Box::new(spanned(Effect::Terminal {
                    decision: Decision::Deny,
                    reason: None,
                }))),
            },
        )]);
        let entries = eval_tracing(&config, "git", &[]);
        let cond_doc = extract_cond_doc(&entries);
        let children = cond_doc.children().expect("cond should be a list");

        // children: ["cond", branch0, branch1, branch2, fallback]
        assert_eq!(
            children.len(),
            5,
            "expected cond + 3 branches + fallback, got {} children",
            children.len()
        );
        // No trailing dimmed ellipsis — last child is the fallback (not "…")
        let last = &children[4];
        assert_ne!(
            last.as_atom(),
            Some("…"),
            "should not have trailing ellipsis when all evaluated"
        );
    }

    #[test]
    fn cond_collapse_single_trailing_branch() {
        // Branch 0: :key0 present → matches
        // Branch 1: skipped → single trailing branch collapses to …
        let mut facts = ContextFacts::default();
        facts.insert_present(Keyword::new(":key0").unwrap());

        let config = make_config(vec![make_rule(
            CommandPattern::Literal("git".into()),
            Effect::Cond {
                branches: make_cond_branches(2),
                fallback: Some(Box::new(spanned(Effect::Terminal {
                    decision: Decision::Deny,
                    reason: None,
                }))),
            },
        )]);
        let mut fold = TracingFold::new();
        evaluate_with_fold("git", &[], &config, &facts, &mut fold).unwrap();
        let cond_doc = extract_cond_doc(&fold.traces);
        let children = cond_doc.children().expect("cond should be a list");

        // children: ["cond", branch0, "…"]
        // (branch1 + fallback collapsed into single "…")
        assert_eq!(
            children.len(),
            3,
            "expected cond + 1 branch + 1 ellipsis, got {} children",
            children.len()
        );
        assert_eq!(children[2].as_atom(), Some("…"));
        assert!(children[2].dimmed);
    }
}
