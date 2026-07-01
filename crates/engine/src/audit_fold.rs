// Audit capture through the `EvalFold` seam.
//
// `AuditFold` observes an evaluation and records the canonical-form hashes of
// the rules that carried the strictest-wins decision at the *outermost*
// scope. It performs no IO and changes no decision: the engine drives control
// flow via the projection methods, and `AuditFold` returns exactly the
// results `PureFold` would (it delegates the whole effect/predicate algebra to
// an inner `PureFold`), layering only the hash capture on top.
//
// `ComposedFold<A, B>` runs two folds in lock-step over one traversal,
// pairing their output types. Eval composes `TracingFold` with `AuditFold`;
// Hook runs `AuditFold` alone (no trace-tree cost).

use may_i_core::ast::{Effect, EffectResult, ResolvedParser, Rule};
use may_i_core::pattern::{ArgPattern, CommandPattern, Expr};
use may_i_core::{ContextFacts, Decision, FactQuery};

use crate::eval::PredicateResult;
use crate::fold::{
    ArgMatchDetail, ChildResult, EvalFold, FactDetail, PositionalElementDetail, PureFold,
};
use crate::trust::{canonical_rule, hash_rule};

/// Captures the canonical-form hashes of the deciding rules during an
/// evaluation, for the Audit log.
///
/// The capture mirrors the scope discipline of the CLI's `TracingFold`: a
/// stack of per-scope frames, one entry pushed per `rule_matched` call in
/// match order, so `rules_combined`'s `tied_match_indices` resolve against the
/// current scope. Only the *outermost* scope's deciding rules are retained —
/// a recursive `(authorise …)` sub-evaluation must not leak its winners into
/// the top-level record.
///
/// One command line drives several top-level evaluations: one per `EvalUnit`
/// (a `&&`/`||`/`;` segment or an embedded `$(…)` substitution — none of which
/// push a recursion frame). Each contributes a `(decision, hashes)` group, and
/// the command's overall decision is the strictest across units. So the
/// deciding rules are exactly the groups whose decision equals that aggregate;
/// [`AuditFold::deciding_hashes`] takes the aggregate and selects them. A
/// default-ask or parse-floor outcome (no rule carried the winning decision)
/// yields an empty list.
pub struct AuditFold {
    inner: PureFold,
    match_stack: Vec<Vec<(String, Decision)>>,
    groups: Vec<(Decision, Vec<String>)>,
}

impl Default for AuditFold {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditFold {
    /// Build a fresh `AuditFold` with one (outermost) scope frame.
    pub fn new() -> Self {
        Self {
            inner: PureFold,
            match_stack: vec![Vec::new()],
            groups: Vec::new(),
        }
    }

    /// The canonical-form hashes of the rules that carried `aggregate` — the
    /// command's overall (strictest-across-units) decision. Hashes are
    /// deduplicated, preserving first-seen order. Empty when no rule carried
    /// that decision (default-ask / parse-floor, or the decision came from a
    /// unit that matched no rule).
    pub fn deciding_hashes(&self, aggregate: Decision) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for (decision, hashes) in &self.groups {
            if *decision == aggregate {
                for h in hashes {
                    if !out.contains(h) {
                        out.push(h.clone());
                    }
                }
            }
        }
        out
    }

    /// Consume the fold, yielding the deciding-rule hashes for `aggregate`.
    pub fn into_deciding_hashes(self, aggregate: Decision) -> Vec<String> {
        self.deciding_hashes(aggregate)
    }
}

impl EvalFold for AuditFold {
    type EffectOut = EffectResult;
    type PredicateOut = PredicateResult;

    fn effect_result(out: &EffectResult) -> &EffectResult {
        PureFold::effect_result(out)
    }
    fn predicate_result(out: &PredicateResult) -> PredicateResult {
        PureFold::predicate_result(out)
    }

    fn effect_terminal(&mut self, effect: &Effect, result: EffectResult) -> EffectResult {
        self.inner.effect_terminal(effect, result)
    }
    fn effect_nil(&mut self, effect: &Effect) -> EffectResult {
        self.inner.effect_nil(effect)
    }
    fn effect_command_match(
        &mut self,
        pattern: &CommandPattern,
        cmd: &str,
        matched: bool,
    ) -> EffectResult {
        self.inner.effect_command_match(pattern, cmd, matched)
    }
    fn effect_arg_match(
        &mut self,
        pattern: &ArgPattern,
        args: &[String],
        matched: bool,
        detail: ArgMatchDetail,
    ) -> EffectResult {
        self.inner.effect_arg_match(pattern, args, matched, detail)
    }
    fn effect_and(
        &mut self,
        children: Vec<ChildResult<EffectResult>>,
        result: EffectResult,
    ) -> EffectResult {
        self.inner.effect_and(children, result)
    }
    fn effect_or(
        &mut self,
        children: Vec<ChildResult<EffectResult>>,
        result: EffectResult,
    ) -> EffectResult {
        self.inner.effect_or(children, result)
    }
    fn effect_not(&mut self, child: EffectResult, result: EffectResult) -> EffectResult {
        self.inner.effect_not(child, result)
    }
    fn effect_when(
        &mut self,
        pred: PredicateResult,
        body: ChildResult<EffectResult>,
        body_effect: &Effect,
        result: EffectResult,
    ) -> EffectResult {
        self.inner.effect_when(pred, body, body_effect, result)
    }
    fn effect_unless(
        &mut self,
        pred: PredicateResult,
        body: ChildResult<EffectResult>,
        body_effect: &Effect,
        result: EffectResult,
    ) -> EffectResult {
        self.inner.effect_unless(pred, body, body_effect, result)
    }
    fn effect_if(
        &mut self,
        pred: PredicateResult,
        then_: ChildResult<EffectResult>,
        else_: ChildResult<EffectResult>,
        result: EffectResult,
    ) -> EffectResult {
        self.inner.effect_if(pred, then_, else_, result)
    }
    fn effect_cond(
        &mut self,
        branches: Vec<(ChildResult<PredicateResult>, ChildResult<EffectResult>)>,
        fallback: Option<ChildResult<EffectResult>>,
        result: EffectResult,
    ) -> EffectResult {
        self.inner.effect_cond(branches, fallback, result)
    }
    fn effect_arg_continuation(
        &mut self,
        pattern: &ArgPattern,
        args: &[String],
        detail: ArgMatchDetail,
        continuation: EffectResult,
    ) -> EffectResult {
        self.inner
            .effect_arg_continuation(pattern, args, detail, continuation)
    }

    fn begin_recursive_eval(&mut self) {
        self.match_stack.push(Vec::new());
    }

    fn predicate_fact(
        &mut self,
        query: &FactQuery,
        result: PredicateResult,
        detail: FactDetail,
    ) -> PredicateResult {
        self.inner.predicate_fact(query, result, detail)
    }
    fn predicate_arg(
        &mut self,
        pattern: &ArgPattern,
        args: &[String],
        result: PredicateResult,
        positional_elements: Vec<PositionalElementDetail>,
    ) -> PredicateResult {
        self.inner
            .predicate_arg(pattern, args, result, positional_elements)
    }
    fn predicate_and(
        &mut self,
        children: Vec<ChildResult<PredicateResult>>,
        result: PredicateResult,
    ) -> PredicateResult {
        self.inner.predicate_and(children, result)
    }
    fn predicate_or(
        &mut self,
        children: Vec<ChildResult<PredicateResult>>,
        result: PredicateResult,
    ) -> PredicateResult {
        self.inner.predicate_or(children, result)
    }
    fn predicate_not(
        &mut self,
        child: PredicateResult,
        result: PredicateResult,
    ) -> PredicateResult {
        self.inner.predicate_not(child, result)
    }
    fn predicate_named(
        &mut self,
        name: &str,
        resolved: PredicateResult,
        result: PredicateResult,
    ) -> PredicateResult {
        self.inner.predicate_named(name, resolved, result)
    }
    fn predicate_bound(
        &mut self,
        binding: &may_i_core::ast::BindingName,
        result: PredicateResult,
    ) -> PredicateResult {
        self.inner.predicate_bound(binding, result)
    }
    fn predicate_matches(
        &mut self,
        binding: &may_i_core::ast::BindingName,
        pattern: &Expr<Effect>,
        result: PredicateResult,
    ) -> PredicateResult {
        self.inner.predicate_matches(binding, pattern, result)
    }
    fn predicate_every(
        &mut self,
        binding: &may_i_core::ast::BindingName,
        pattern: &Expr<Effect>,
        result: PredicateResult,
    ) -> PredicateResult {
        self.inner.predicate_every(binding, pattern, result)
    }
    fn predicate_some(
        &mut self,
        binding: &may_i_core::ast::BindingName,
        pattern: &Expr<Effect>,
        result: PredicateResult,
    ) -> PredicateResult {
        self.inner.predicate_some(binding, pattern, result)
    }
    fn predicate_scope(
        &mut self,
        matcher: may_i_core::ast::EnvScopeMatcher,
        result: PredicateResult,
    ) -> PredicateResult {
        self.inner.predicate_scope(matcher, result)
    }

    fn rule_matched(
        &mut self,
        rule: &Rule,
        line: Option<usize>,
        facts: &ContextFacts,
        command_out: EffectResult,
        effect_out: EffectResult,
    ) -> EffectResult {
        // Match order within the current scope = push order. Capture the
        // rule's canonical-form hash alongside the decision it carried, so
        // `rules_combined` can pick the tied subset and tag the scope's group.
        if let EffectResult::Decision(decision, _) = &effect_out {
            let hash = hash_rule(&canonical_rule(rule));
            if let Some(top) = self.match_stack.last_mut() {
                top.push((hash, *decision));
            }
        }
        self.inner
            .rule_matched(rule, line, facts, command_out, effect_out)
    }
    fn rule_not_matched(
        &mut self,
        rule: &Rule,
        facts: &ContextFacts,
        command_out: EffectResult,
        effect_out: EffectResult,
    ) -> EffectResult {
        self.inner
            .rule_not_matched(rule, facts, command_out, effect_out)
    }
    fn rule_skipped(&mut self, rule: &Rule) -> EffectResult {
        self.inner.rule_skipped(rule)
    }
    fn default_ask(&mut self, reason: &str) -> EffectResult {
        self.inner.default_ask(reason)
    }

    fn rules_combined(
        &mut self,
        tied_match_indices: &[usize],
        _reason_source_match_index: Option<usize>,
    ) {
        // Only an outermost scope (one top-level `EvalUnit`) contributes a
        // group. Recursive `(authorise …)` sub-evaluations push their own
        // frames; their `rules_combined` fires first, during the outer rule's
        // body, and must not be recorded as a top-level group. The tied subset
        // all share the strictest decision, so the group's decision is any
        // tied entry's.
        if self.match_stack.len() == 1 {
            let top = self.match_stack.last().cloned().unwrap_or_default();
            let tied: Vec<(String, Decision)> = tied_match_indices
                .iter()
                .filter_map(|&i| top.get(i).cloned())
                .collect();
            if let Some(decision) = tied.first().map(|(_, d)| *d) {
                let hashes = tied.into_iter().map(|(h, _)| h).collect();
                self.groups.push((decision, hashes));
            }
        }
        if let Some(top) = self.match_stack.last_mut() {
            top.clear();
        }
        if self.match_stack.len() > 1 {
            self.match_stack.pop();
        }
    }

    fn record_parser(&mut self, _command: &str, _parser: &ResolvedParser) {}
    fn embedded_command(&mut self, _source: &str, _decision: Decision) {}
}

/// Runs two folds in lock-step over a single traversal, pairing their output
/// types. Every trait method is delegated to both halves; the engine projects
/// decisions through the first half (`A`), so the halves must agree on
/// control-flow results (they always do — they observe the same evaluation).
pub struct ComposedFold<A, B> {
    a: A,
    b: B,
}

impl<A, B> ComposedFold<A, B> {
    /// Compose two folds. `a` is the projection authority for control flow.
    pub fn new(a: A, b: B) -> Self {
        Self { a, b }
    }

    /// Decompose into the two halves after evaluation.
    pub fn into_parts(self) -> (A, B) {
        (self.a, self.b)
    }
}

fn split_child<A, B>(child: ChildResult<(A, B)>) -> (ChildResult<A>, ChildResult<B>) {
    match child {
        ChildResult::Evaluated((a, b)) => (ChildResult::Evaluated(a), ChildResult::Evaluated(b)),
        ChildResult::Skipped => (ChildResult::Skipped, ChildResult::Skipped),
    }
}

fn split_children<A, B>(
    children: Vec<ChildResult<(A, B)>>,
) -> (Vec<ChildResult<A>>, Vec<ChildResult<B>>) {
    let mut va = Vec::with_capacity(children.len());
    let mut vb = Vec::with_capacity(children.len());
    for child in children {
        let (a, b) = split_child(child);
        va.push(a);
        vb.push(b);
    }
    (va, vb)
}

impl<A: EvalFold, B: EvalFold> EvalFold for ComposedFold<A, B> {
    type EffectOut = (A::EffectOut, B::EffectOut);
    type PredicateOut = (A::PredicateOut, B::PredicateOut);

    fn effect_result(out: &Self::EffectOut) -> &EffectResult {
        A::effect_result(&out.0)
    }
    fn predicate_result(out: &Self::PredicateOut) -> PredicateResult {
        A::predicate_result(&out.0)
    }

    fn effect_terminal(&mut self, effect: &Effect, result: EffectResult) -> Self::EffectOut {
        (
            self.a.effect_terminal(effect, result.clone()),
            self.b.effect_terminal(effect, result),
        )
    }
    fn effect_nil(&mut self, effect: &Effect) -> Self::EffectOut {
        (self.a.effect_nil(effect), self.b.effect_nil(effect))
    }
    fn effect_command_match(
        &mut self,
        pattern: &CommandPattern,
        cmd: &str,
        matched: bool,
    ) -> Self::EffectOut {
        (
            self.a.effect_command_match(pattern, cmd, matched),
            self.b.effect_command_match(pattern, cmd, matched),
        )
    }
    fn effect_arg_match(
        &mut self,
        pattern: &ArgPattern,
        args: &[String],
        matched: bool,
        detail: ArgMatchDetail,
    ) -> Self::EffectOut {
        (
            self.a
                .effect_arg_match(pattern, args, matched, detail.clone()),
            self.b.effect_arg_match(pattern, args, matched, detail),
        )
    }
    fn effect_and(
        &mut self,
        children: Vec<ChildResult<Self::EffectOut>>,
        result: EffectResult,
    ) -> Self::EffectOut {
        let (ca, cb) = split_children(children);
        (
            self.a.effect_and(ca, result.clone()),
            self.b.effect_and(cb, result),
        )
    }
    fn effect_or(
        &mut self,
        children: Vec<ChildResult<Self::EffectOut>>,
        result: EffectResult,
    ) -> Self::EffectOut {
        let (ca, cb) = split_children(children);
        (
            self.a.effect_or(ca, result.clone()),
            self.b.effect_or(cb, result),
        )
    }
    fn effect_not(&mut self, child: Self::EffectOut, result: EffectResult) -> Self::EffectOut {
        (
            self.a.effect_not(child.0, result.clone()),
            self.b.effect_not(child.1, result),
        )
    }
    fn effect_when(
        &mut self,
        pred: Self::PredicateOut,
        body: ChildResult<Self::EffectOut>,
        body_effect: &Effect,
        result: EffectResult,
    ) -> Self::EffectOut {
        let (ba, bb) = split_child(body);
        (
            self.a.effect_when(pred.0, ba, body_effect, result.clone()),
            self.b.effect_when(pred.1, bb, body_effect, result),
        )
    }
    fn effect_unless(
        &mut self,
        pred: Self::PredicateOut,
        body: ChildResult<Self::EffectOut>,
        body_effect: &Effect,
        result: EffectResult,
    ) -> Self::EffectOut {
        let (ba, bb) = split_child(body);
        (
            self.a
                .effect_unless(pred.0, ba, body_effect, result.clone()),
            self.b.effect_unless(pred.1, bb, body_effect, result),
        )
    }
    fn effect_if(
        &mut self,
        pred: Self::PredicateOut,
        then_: ChildResult<Self::EffectOut>,
        else_: ChildResult<Self::EffectOut>,
        result: EffectResult,
    ) -> Self::EffectOut {
        let (ta, tb) = split_child(then_);
        let (ea, eb) = split_child(else_);
        (
            self.a.effect_if(pred.0, ta, ea, result.clone()),
            self.b.effect_if(pred.1, tb, eb, result),
        )
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
        let mut branches_a = Vec::with_capacity(branches.len());
        let mut branches_b = Vec::with_capacity(branches.len());
        for (pred, body) in branches {
            let (pa, pb) = split_child(pred);
            let (ba, bb) = split_child(body);
            branches_a.push((pa, ba));
            branches_b.push((pb, bb));
        }
        let (fa, fb) = match fallback {
            Some(f) => {
                let (fa, fb) = split_child(f);
                (Some(fa), Some(fb))
            }
            None => (None, None),
        };
        (
            self.a.effect_cond(branches_a, fa, result.clone()),
            self.b.effect_cond(branches_b, fb, result),
        )
    }
    fn effect_arg_continuation(
        &mut self,
        pattern: &ArgPattern,
        args: &[String],
        detail: ArgMatchDetail,
        continuation: Self::EffectOut,
    ) -> Self::EffectOut {
        (
            self.a
                .effect_arg_continuation(pattern, args, detail.clone(), continuation.0),
            self.b
                .effect_arg_continuation(pattern, args, detail, continuation.1),
        )
    }

    fn begin_recursive_eval(&mut self) {
        self.a.begin_recursive_eval();
        self.b.begin_recursive_eval();
    }
    fn record_parser(&mut self, command: &str, parser: &ResolvedParser) {
        self.a.record_parser(command, parser);
        self.b.record_parser(command, parser);
    }

    fn predicate_fact(
        &mut self,
        query: &FactQuery,
        result: PredicateResult,
        detail: FactDetail,
    ) -> Self::PredicateOut {
        (
            self.a.predicate_fact(query, result, detail.clone()),
            self.b.predicate_fact(query, result, detail),
        )
    }
    fn predicate_arg(
        &mut self,
        pattern: &ArgPattern,
        args: &[String],
        result: PredicateResult,
        positional_elements: Vec<PositionalElementDetail>,
    ) -> Self::PredicateOut {
        (
            self.a
                .predicate_arg(pattern, args, result, positional_elements.clone()),
            self.b
                .predicate_arg(pattern, args, result, positional_elements),
        )
    }
    fn predicate_and(
        &mut self,
        children: Vec<ChildResult<Self::PredicateOut>>,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        let (ca, cb) = split_children(children);
        (
            self.a.predicate_and(ca, result),
            self.b.predicate_and(cb, result),
        )
    }
    fn predicate_or(
        &mut self,
        children: Vec<ChildResult<Self::PredicateOut>>,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        let (ca, cb) = split_children(children);
        (
            self.a.predicate_or(ca, result),
            self.b.predicate_or(cb, result),
        )
    }
    fn predicate_not(
        &mut self,
        child: Self::PredicateOut,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        (
            self.a.predicate_not(child.0, result),
            self.b.predicate_not(child.1, result),
        )
    }
    fn predicate_named(
        &mut self,
        name: &str,
        resolved: Self::PredicateOut,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        (
            self.a.predicate_named(name, resolved.0, result),
            self.b.predicate_named(name, resolved.1, result),
        )
    }
    fn predicate_bound(
        &mut self,
        binding: &may_i_core::ast::BindingName,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        (
            self.a.predicate_bound(binding, result),
            self.b.predicate_bound(binding, result),
        )
    }
    fn predicate_matches(
        &mut self,
        binding: &may_i_core::ast::BindingName,
        pattern: &Expr<Effect>,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        (
            self.a.predicate_matches(binding, pattern, result),
            self.b.predicate_matches(binding, pattern, result),
        )
    }
    fn predicate_every(
        &mut self,
        binding: &may_i_core::ast::BindingName,
        pattern: &Expr<Effect>,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        (
            self.a.predicate_every(binding, pattern, result),
            self.b.predicate_every(binding, pattern, result),
        )
    }
    fn predicate_some(
        &mut self,
        binding: &may_i_core::ast::BindingName,
        pattern: &Expr<Effect>,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        (
            self.a.predicate_some(binding, pattern, result),
            self.b.predicate_some(binding, pattern, result),
        )
    }
    fn predicate_scope(
        &mut self,
        matcher: may_i_core::ast::EnvScopeMatcher,
        result: PredicateResult,
    ) -> Self::PredicateOut {
        (
            self.a.predicate_scope(matcher, result),
            self.b.predicate_scope(matcher, result),
        )
    }

    fn rule_matched(
        &mut self,
        rule: &Rule,
        line: Option<usize>,
        facts: &ContextFacts,
        command_out: Self::EffectOut,
        effect_out: Self::EffectOut,
    ) -> Self::EffectOut {
        (
            self.a
                .rule_matched(rule, line, facts, command_out.0, effect_out.0),
            self.b
                .rule_matched(rule, line, facts, command_out.1, effect_out.1),
        )
    }
    fn rule_not_matched(
        &mut self,
        rule: &Rule,
        facts: &ContextFacts,
        command_out: Self::EffectOut,
        effect_out: Self::EffectOut,
    ) -> Self::EffectOut {
        (
            self.a
                .rule_not_matched(rule, facts, command_out.0, effect_out.0),
            self.b
                .rule_not_matched(rule, facts, command_out.1, effect_out.1),
        )
    }
    fn rule_skipped(&mut self, rule: &Rule) -> Self::EffectOut {
        (self.a.rule_skipped(rule), self.b.rule_skipped(rule))
    }
    fn default_ask(&mut self, reason: &str) -> Self::EffectOut {
        (self.a.default_ask(reason), self.b.default_ask(reason))
    }
    fn rules_combined(
        &mut self,
        tied_match_indices: &[usize],
        reason_source_match_index: Option<usize>,
    ) {
        self.a
            .rules_combined(tied_match_indices, reason_source_match_index);
        self.b
            .rules_combined(tied_match_indices, reason_source_match_index);
    }
    fn embedded_command(&mut self, source: &str, decision: Decision) {
        self.a.embedded_command(source, decision);
        self.b.embedded_command(source, decision);
    }
    fn local_function_call(&mut self, name: &str) {
        self.a.local_function_call(name);
        self.b.local_function_call(name);
    }
    fn unresolved_floor(&mut self, words: &[String]) {
        self.a.unresolved_floor(words);
        self.b.unresolved_floor(words);
    }
    fn arity_guess_advisory(&mut self, flag: &str, consumed: &str) {
        self.a.arity_guess_advisory(flag, consumed);
        self.b.arity_guess_advisory(flag, consumed);
    }
    fn env_entry_contribution(&mut self, name: &str) {
        self.a.env_entry_contribution(name);
        self.b.env_entry_contribution(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluate_command_with_fold;
    use crate::trust::{canonical_rule, hash_rule};
    use may_i_config::parse_config;
    use may_i_core::ContextFacts;

    fn rule_hash(rule: &Rule) -> String {
        hash_rule(&canonical_rule(rule))
    }

    #[test]
    fn audit_fold_records_only_the_deciding_rule() {
        let config = parse_config(
            r#"
            (rule "rm" (allow))
            (rule "rm" (deny "danger"))
        "#,
        )
        .unwrap();
        let facts = ContextFacts::default();
        let mut fold = AuditFold::new();
        let result = evaluate_command_with_fold("rm file", &config, &facts, &mut fold).unwrap();

        assert_eq!(result.decision, Decision::Deny);
        // Only the strictest-winning rule (the deny) is recorded.
        assert_eq!(
            fold.deciding_hashes(result.decision),
            vec![rule_hash(&config.rules[1])]
        );
    }

    #[test]
    fn deciding_hashes_track_the_aggregate_decision_across_units() {
        // Two top-level units: the outer `rm` denies, the embedded `echo`
        // allows. The aggregate is `deny`, so only `rm`'s hash is deciding —
        // the `echo` allow must not leak into the deny record (regression for
        // the per-unit last-wins overwrite bug).
        let config = parse_config(
            r#"
            (rule "rm" (deny "danger"))
            (rule "echo" (allow))
        "#,
        )
        .unwrap();
        let facts = ContextFacts::default();
        let mut fold = AuditFold::new();
        let result =
            evaluate_command_with_fold("rm $(echo safe)", &config, &facts, &mut fold).unwrap();

        assert_eq!(result.decision, Decision::Deny);
        let rm_hash = rule_hash(&config.rules[0]);
        let echo_hash = rule_hash(&config.rules[1]);
        let deciding = fold.deciding_hashes(result.decision);
        assert_eq!(deciding, vec![rm_hash]);
        assert!(
            !deciding.contains(&echo_hash),
            "the allowing echo rule must not appear in a deny record"
        );
    }

    #[test]
    fn audit_fold_records_all_tied_winners() {
        let config = parse_config(
            r#"
            (rule "rm" (deny "a"))
            (rule "rm" (deny "b"))
        "#,
        )
        .unwrap();
        let facts = ContextFacts::default();
        let mut fold = AuditFold::new();
        evaluate_command_with_fold("rm x", &config, &facts, &mut fold).unwrap();

        let mut got = fold.deciding_hashes(Decision::Deny);
        got.sort();
        let mut expected = vec![rule_hash(&config.rules[0]), rule_hash(&config.rules[1])];
        expected.sort();
        assert_eq!(got, expected);
    }

    #[test]
    fn audit_fold_empty_on_default_ask() {
        let config = parse_config(r#"(rule "git" (allow))"#).unwrap();
        let facts = ContextFacts::default();
        let mut fold = AuditFold::new();
        let result = evaluate_command_with_fold("rm x", &config, &facts, &mut fold).unwrap();

        assert_eq!(result.decision, Decision::Ask);
        assert!(fold.deciding_hashes(result.decision).is_empty());
    }

    /// Exercise every `ComposedFold` delegation by evaluating commands
    /// against a config with rich rule bodies (cond / and / or / not / when /
    /// if / authorise / fact / named predicate / command substitution). For
    /// each command the composed decision must equal `PureFold` alone, and the
    /// audit half must capture exactly what `AuditFold` alone would.
    #[test]
    fn composed_fold_equivalence_over_rich_bodies() {
        let config = parse_config(
            r#"
            (define safe (fact? :ci))
            (rule "git"
              (cond
                ((and (positional "push") (flag ["f" "force"])) (deny "force push"))
                ((or (positional "status") (positional "log")) (allow))
                (else (ask "review"))))
            (rule "rm" (when (not (flag "i")) (ask "confirm")))
            (rule "echo" (if safe (allow) (ask "no ci")))
            (rule "sudo" (authorise #cmd))
            ;; effect-position and / or / unless + arg match in effect position
            (rule "tar" (and (flag ["x" "extract"]) (deny "no extract")))
            (rule "cp" (or (flag "r") (ask "confirm")))
            (rule "kill" (unless (flag "9") (allow)))
            ;; rule-body binding predicates over the prelude ssh parser's #host
            (rule "ssh" (when (bound? #host) (ask "host bound")))
            (rule "ssh" (when (matches? #host (regex "prod")) (deny "prod host")))
            ;; collection-binding predicates: every? / some? over a (set #opts)
            (parser "pip" (style gnu) (flags permute) (parameter ["o" "opt"] (set #opts)))
            (rule "pip" (when (every? #opts (regex "^[a-z]")) (allow "all lower")))
            (rule "pip" (when (some? #opts (regex "danger")) (deny "danger opt")))
            "#,
        )
        .unwrap();
        let facts = ContextFacts::default();

        let commands = [
            "git push -f",
            "git status",
            "git rebase",
            "rm foo",
            "rm -i foo",
            "echo hi",
            "sudo rm bar",
            "echo $(rm baz)",
            "tar -x",
            "tar tf a.tar",
            "cp -r a b",
            "cp a b",
            "kill -9 1",
            "kill 1",
            "ssh host ls",
            "ssh prod ls",
            "pip -o foo -o bar",
            "pip -o danger",
            "unknown-prog arg",
        ];

        for cmd in commands {
            let mut pure = crate::fold::PureFold;
            let r_pure = evaluate_command_with_fold(cmd, &config, &facts, &mut pure).unwrap();

            let mut audit_alone = AuditFold::new();
            let r_audit =
                evaluate_command_with_fold(cmd, &config, &facts, &mut audit_alone).unwrap();

            let mut composed = ComposedFold::new(crate::fold::PureFold, AuditFold::new());
            let r_comp = evaluate_command_with_fold(cmd, &config, &facts, &mut composed).unwrap();

            assert_eq!(r_comp.decision, r_pure.decision, "decision for {cmd:?}");
            assert_eq!(r_audit.decision, r_pure.decision, "audit decision {cmd:?}");

            let (_pure_half, audit_half) = composed.into_parts();
            assert_eq!(
                audit_half.deciding_hashes(r_comp.decision),
                audit_alone.deciding_hashes(r_audit.decision),
                "deciding hashes for {cmd:?}"
            );
        }
    }

    #[test]
    fn composed_fold_matches_each_half_run_alone() {
        let config = parse_config(
            r#"
            (rule "rm" (allow))
            (rule "rm" (deny "danger"))
        "#,
        )
        .unwrap();
        let facts = ContextFacts::default();

        let mut audit_alone = AuditFold::new();
        let r_audit =
            evaluate_command_with_fold("rm x", &config, &facts, &mut audit_alone).unwrap();

        let mut composed = ComposedFold::new(PureFold, AuditFold::new());
        let r_comp = evaluate_command_with_fold("rm x", &config, &facts, &mut composed).unwrap();

        // The projection (through half A = PureFold) yields the same decision.
        assert_eq!(r_comp.decision, r_audit.decision);
        assert_eq!(r_comp.decision, Decision::Deny);

        // The audit half captures exactly what AuditFold alone would.
        let (_pure, audit_half) = composed.into_parts();
        assert_eq!(
            audit_half.deciding_hashes(r_comp.decision),
            audit_alone.deciding_hashes(r_audit.decision)
        );
    }
}
