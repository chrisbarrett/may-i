## Context

The v0.0.3 trace system used `annotate.rs` (2141 lines) to walk the rule tree
in parallel with evaluation, producing `Doc<Option<EvalAnn>>` — a
pretty-printable s-expression where each node carries an evaluation annotation.
`output.rs` (1233 lines) rendered these annotated docs into two-column terminal
output. Both files were deleted during the v2 syntax migration. The evaluator
was rewritten for the new AST but trace generation was not restored.

The v2 AST is structurally different: `Effect` is now a recursive tree with
combinators (`And`/`Or`/`Not`), conditionals (`When`/`Unless`/`If`/`Cond`), and
recursive evaluation (`MayI`). The old flat `Rule { command, context, args,
body }` is now `Rule { command_effect, effects }` where matching and effects are
unified.

The `Doc<A>` recursion-scheme infrastructure in `may-i-core::doc` is intact and
general-purpose: `DocF<R>` is the base functor, `Doc<A>` is the fixpoint with
annotations, and it supports `map`, `fold` (catamorphism), and layout hints.

## Goals / Non-Goals

**Goals:**

- Restore trace output for `may-i eval` matching v0.0.3 quality (two-column
  terminal, JSON)
- Restore `may-i check` with pass/fail reporting and traces on failure
- Keep `Doc` out of the engine crate — separation of evaluation and rendering
- Single-traversal architecture — no separate "evaluate then annotate" pass
- Predicate-internal tracing (show which branch of `(and (fact? :a) (fact? :b))`
  matched)

**Non-Goals:**

- Changing the v2 AST or evaluation semantics
- Adding new trace features beyond what v0.0.3 provided
- Trace output for the config parser or migration system

## Decisions

### Decision 1: Zygomorphism via `EvalFold` trait

The evaluator is parameterised over a fold trait so two algebras compose in one
traversal: evaluation (produces decisions) and annotation (produces `Doc<Ann>`).

```
trait EvalFold {
    type EffectOut;
    type PredicateOut;

    // Projection — engine extracts decisions for control flow
    fn effect_result(out: &Self::EffectOut) -> &EffectResult;
    fn predicate_result(out: &Self::PredicateOut) -> PredicateResult;

    // Effect algebra
    fn effect_terminal(&mut self, effect: &Effect, result: EffectResult) -> Self::EffectOut;
    fn effect_nil(&mut self, effect: &Effect) -> Self::EffectOut;
    fn effect_command_match(&mut self, pattern: &CommandPattern, cmd: &str, matched: bool) -> Self::EffectOut;
    fn effect_arg_match(&mut self, pattern: &ArgPattern, args: &[String], matched: bool, detail: ArgMatchDetail) -> Self::EffectOut;
    fn effect_and(&mut self, children: Vec<ChildResult<Self::EffectOut>>, result: EffectResult) -> Self::EffectOut;
    fn effect_or(&mut self, children: Vec<ChildResult<Self::EffectOut>>, result: EffectResult) -> Self::EffectOut;
    fn effect_not(&mut self, child: Self::EffectOut, result: EffectResult) -> Self::EffectOut;
    fn effect_when(&mut self, pred: Self::PredicateOut, body: ChildResult<Self::EffectOut>, result: EffectResult) -> Self::EffectOut;
    fn effect_unless(&mut self, pred: Self::PredicateOut, body: ChildResult<Self::EffectOut>, result: EffectResult) -> Self::EffectOut;
    fn effect_if(&mut self, pred: Self::PredicateOut, then_: ChildResult<Self::EffectOut>, else_: ChildResult<Self::EffectOut>, result: EffectResult) -> Self::EffectOut;
    fn effect_cond(&mut self, branches: Vec<(Self::PredicateOut, ChildResult<Self::EffectOut>)>, fallback: Option<ChildResult<Self::EffectOut>>, result: EffectResult) -> Self::EffectOut;
    fn effect_may_i(&mut self, inner_cmd: &str, inner_args: &[String], inner_result: EffectResult, inner_out: Self::EffectOut) -> Self::EffectOut;
    fn effect_may_i_no_match(&mut self, pattern: &ArgPattern) -> Self::EffectOut;

    // Predicate algebra
    fn predicate_fact(&mut self, query: &FactQuery, result: PredicateResult, detail: FactDetail) -> Self::PredicateOut;
    fn predicate_arg(&mut self, pattern: &ArgPattern, args: &[String], result: PredicateResult) -> Self::PredicateOut;
    fn predicate_and(&mut self, children: Vec<ChildResult<Self::PredicateOut>>, result: PredicateResult) -> Self::PredicateOut;
    fn predicate_or(&mut self, children: Vec<ChildResult<Self::PredicateOut>>, result: PredicateResult) -> Self::PredicateOut;
    fn predicate_not(&mut self, child: Self::PredicateOut, result: PredicateResult) -> Self::PredicateOut;
    fn predicate_named(&mut self, name: &str, resolved: Self::PredicateOut, result: PredicateResult) -> Self::PredicateOut;

    // Rule-level
    fn rule_matched(&mut self, rule: &Rule, line: Option<usize>, out: Self::EffectOut) -> Self::EffectOut;
    fn rule_skipped(&mut self, rule: &Rule) -> Self::EffectOut;
    fn default_ask(&mut self, reason: &str) -> Self::EffectOut;
}
```

The `ChildResult` enum distinguishes evaluated vs short-circuited children:

```
enum ChildResult<T> {
    Evaluated(T),
    Skipped,
}
```

**Alternative considered**: Observer/visitor pattern with enter/exit events.
Rejected because it forces the consumer to reconstruct tree structure from a
flat event stream (SAX vs DOM problem).

**Alternative considered**: Separate trace pass after evaluation. Rejected
because it requires a second traversal and duplicates control-flow logic.

### Decision 2: `PureFold` for zero-cost non-tracing evaluation

```
struct PureFold;

impl EvalFold for PureFold {
    type EffectOut = EffectResult;
    type PredicateOut = PredicateResult;
    // All methods trivially return the result argument
}
```

Used by engine tests, the check runner (when traces aren't needed), and any
future consumer that only needs decisions.

### Decision 3: `TracingFold` lives in the CLI binary

```
struct TracingFold { /* source info for line numbers */ }

impl EvalFold for TracingFold {
    type EffectOut = (EffectResult, Doc<Option<Ann>>);
    type PredicateOut = (PredicateResult, Doc<Option<Ann>>);
    // Each method builds an annotated Doc node alongside the result
}
```

`Ann` is an enum with variants for each annotation kind (command match, arg
match, fact query result, effect decision, etc.). Adapted from v0.0.3's
`EvalAnn` for the v2 AST.

`Doc` and `Ann` never appear in the engine crate's public API.

### Decision 4: Recover renderer from git history

The v0.0.3 `output.rs` is recovered and adapted rather than rewritten. Key
components:

- Two-column layout engine (`Row`, `Cell`, `Element`, `render_elements`)
- Annotated Doc walker (`collect_annotations`, `format_annotation`)
- Cosmetic helpers (truncation, elision, dimming, colorization)
- JSON trace serialisation (`trace_to_json`, `collect_json_annotations`)

Adaptation needed: `EvalAnn` -> `Ann`, old AST references -> v2 AST, old
`TraceEntry::Rule { doc, line }` -> new structure where the fold produces
`Doc<Option<Ann>>` directly.

### Decision 5: `EvalResult` becomes trace-free

`EvalResult` drops its `trace: Vec<TraceEntry>` field. It becomes a simple
`{ decision, reason }` pair. `CheckResult` similarly drops its trace field.

The CLI pairs `EvalResult` with `Doc<Option<Ann>>` at the call site when
traces are needed.

### Decision 6: Arg match detail for rich annotations

The fold receives structured detail about argument matching so annotations can
show evidence like `"-r" ∈ {"-r", "-f", "/"} → yes`. This means the evaluator
must compute and pass match evidence (which args were tested, what the arg set
was) to the fold method, not just a boolean `matched`.

Similarly, `FactDetail` carries evidence about fact queries (observed values,
failure reasons) for the annotation.

## Risks / Trade-offs

- **Trait size**: `EvalFold` has ~25 methods. This is large but each method is
  simple and corresponds 1:1 to an AST node. Alternative of fewer, more generic
  methods would push complexity into the implementations.
  → Accept: the trait surface matches the AST surface.

- **Monomorphisation cost**: Generic evaluator means each fold type generates
  its own code. There are exactly two implementations (`PureFold`,
  `TracingFold`) so binary size impact is bounded.
  → Accept: two copies is fine.

- **Detail types**: `ArgMatchDetail` and `FactDetail` are new types the
  evaluator must populate. This adds some work to each match site in the
  evaluator.
  → Mitigate: keep detail types simple; `PureFold` ignores them.

- **Renderer adaptation**: The old `output.rs` references old AST types
  throughout. Adaptation is mechanical but tedious.
  → Mitigate: recover from git, adapt incrementally, test against v0.0.3 output.
