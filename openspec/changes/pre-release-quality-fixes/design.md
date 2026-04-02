## Context

A pre-release code review identified critical correctness bugs, spec deviations,
and type-safety gaps. The Claude Code hook — a primary entry point — bypasses
predicate resolution and uses naive command parsing. The evaluator panics on
unresolved predicates. `Expr::Or` with bindings leaks facts from non-first
alternatives. Several serialization and evaluation details diverge from specs.

The codebase has 7 crates (core, config, engine, sexpr, shell-parser, layout,
pp) plus a top-level binary. The changes span core (types), engine (evaluation),
config (loading), and the binary (hook + serialization).

## Goals / Non-Goals

**Goals:**
- Eliminate all known correctness bugs in the evaluation path
- Align implementation with existing specs (Keyword-typed facts, Or
  short-circuit, Cond short-circuit, fact? serialization)
- Spec the Claude Code hook entry point so it has the same quality guarantees as
  the main `eval` path
- Ensure the evaluator never panics on reachable input — return errors instead

**Non-Goals:**
- Addressing the 15 duplication instances (separate change)
- Adding property tests for the newly identified algebraic invariants (separate
  change)
- Specifying other unspecified features (parse subcommand, reference subcommand,
  config auto-creation, etc.)
- Refactoring large files or improving API ergonomics beyond what's needed for
  correctness

## Decisions

### D1: Keyword-typed keys in ContextFacts — change internal representation

Change `ContextFacts` from `BTreeMap<String, BTreeSet<String>>` to
`BTreeMap<Keyword, BTreeSet<String>>`. Change `FactQuery` key fields from
`String` to `Keyword`.

**Rationale**: The runtime-context spec already says `Map<Keyword, Set<String>>`.
The `Keyword` newtype exists to enforce the `:` prefix invariant. Using bare
strings defeats that guarantee.

**Alternative considered**: Keep `String` internally, validate at insertion. This
wouldn't catch bugs at compile time, which is the whole point of the newtype.

**Migration**: All call sites constructing `ContextFacts` or `FactQuery` with
bare strings must use `Keyword::new()` or `Keyword::new_unchecked()`. The
public API methods on `ContextFacts` (`has`, `get`, `contains`, etc.) will
accept `&Keyword` instead of `&str`.

### D2: Evaluator returns Result for unresolved predicates

Change the `evaluate` family of functions to return `Result<T, EvalError>` where
`EvalError` covers at minimum `UnresolvedPredicate { name: String }`. The
`panic!` at `eval.rs:358` becomes `Err(EvalError::UnresolvedPredicate { .. })`.

**Rationale**: Library code must not panic on input that callers can construct.
A `Config` without resolution is valid to construct; the evaluator should reject
it gracefully.

**Alternative considered**: Add a `Config::is_resolved()` check and
`debug_assert!`. This is weaker — it only catches the issue in debug builds.

### D3: Or expression matching short-circuits on first match

In `match_expr_with_binding`, when processing `Expr::Or`, return immediately
after the first matching alternative. Do not continue iterating and merging
facts from later alternatives.

**Rationale**: The expr-combinator-matching spec already says "Only bound facts
from matching sub-expressions SHALL be included" and the scenario shows only the
first matching branch's facts. Iterating all alternatives and merging violates
first-match semantics.

### D4: Claude Code hook uses shell parser and resolution

Replace `split_whitespace` with `shell_parser::parse` and add a
`validate_and_resolve` call before evaluation in `cmd_claude_code_hook.rs`.

**Rationale**: The hook is a primary integration point. It must have the same
preprocessing guarantees as `cmd_eval`. Using `split_whitespace` silently
breaks quoted arguments.

### D5: Cond stops evaluating predicates after a match

In the `Cond` evaluation loop, once a branch predicate matches and its effect
is evaluated, mark all remaining branches as `Skipped` without evaluating their
predicates.

**Rationale**: The configuration-language spec says "evaluate the effect of the
first branch whose predicate matches". Evaluating later predicates is wasted
work and produces misleading trace annotations.

### D6: Predicate::to_doc emits `fact?`

Change `ast.rs:314` from `Doc::atom("has")` to `Doc::atom("fact?")`.

**Rationale**: The canonical keyword is `fact?` in REFERENCE.txt, all specs,
and the config parser. `has` is a stale legacy name that breaks serialization
roundtrips.

## Risks / Trade-offs

- **Keyword-typed facts is a breaking change** → Contained within the workspace;
  no external consumers yet. All call sites are in this repo. Risk: moderate
  churn in tests that construct facts with bare strings.
- **Result-typed evaluator changes all call sites** → Every call to `evaluate()`
  must handle the error. Mitigation: in practice this is just adding `?` since
  all callers already return `Result` or `miette::Result`.
- **Or short-circuit may change observable behaviour** → If any existing config
  relies on facts from non-first Or alternatives, the fix changes semantics.
  Mitigation: this is already the specified behaviour; the old behaviour was a
  bug.
