## Context

Quantifiers (`?`, `+`, `*`) are modelled as a `Quantifier` enum on
`PositionalArg`, which wraps exactly one `Expr` (`crates/core/src/pattern.rs:234-267`).
The parser enforces arity 2 on each quantifier head
(`crates/config/src/pattern.rs:474-503`, "? must have exactly one pattern").
The matcher is a flat backtracking recursion over `&[PositionalArg]`
(`crates/engine/src/eval/positional.rs:73-239`): each quantifier folds its
single `Expr` over consecutive args.

This blocks quantifying a *sequence*. The terragrunt pass-through form
`terragrunt run -- <verb>` needs `(? "run" (? "--"))` — `--` only after
`run` — which the arity check rejects.

Two existing facts shape the design:

- The `regex` crate (v1) used for `Expr::Regex` is the NFA/DFA engine with
  guaranteed linear-time matching; there is no ReDoS surface in the existing
  regex feature. The only super-linear matcher in may-i is the positional
  backtracker, which is already polynomial for overlapping `*`/`+` patterns.
- The expansion-bearing-word soundness check computes provenance from
  `(pattern, expansion[i])` via `unprovable_match`
  (`crates/engine/src/eval/positional.rs:61-70`), threaded into a separate
  `unresolved` field on `PositionalMatch`. The `matched` bool and the
  `unresolved` provenance are computed by two independent calls today.

Binding semantics are unaffected: rule-body `Expr::Bind` captures accumulate
into `ContextFacts`, a `BTreeMap<Keyword, BTreeSet<String>>` whose `merge`
unions sets (`crates/core/src/context.rs:42-65`). Multi-match already collapses
to a set, and `binding-shapes` governs parser-declared `#var` bindings, not
rule-body binds — so neither the closed shape vocabulary nor the Collection
model needs to change.

## Goals / Non-Goals

**Goals:**

- Quantifier heads accept one or more sub-patterns; >1 is an implicit
  sequence. `+`/`*` repeat the whole sub-sequence (Kleene).
- Guaranteed termination: nullable-iteration guard + step budget.
- Soundness of the expansion-bearing-word rule preserved across all new
  group match paths, enforced structurally rather than by convention.
- Round-trip + idempotent `fmt` for the new form; stable trust hashing.

**Non-Goals:**

- No surface syntax for the step budget (config-structure field only).
- No explicit `(seq …)` head. No quantifier *modifiers* (separator,
  bounded-repeat `{m,n}`, lazy, group-level bind) — deferred; if ever added
  they get their own head, never trailing options on `? * +`.
- No change to `binding-shapes`, the Collection model, or `every?`/`some?`.
- No correlation/tuple binding for repeated groups (set-union semantics of
  `ContextFacts` is retained and documented).

## Decisions

### D1: Recursive positional term replaces flat `PositionalArg`

Introduce a recursive term so a quantifier can wrap either one `Expr` or a
sub-sequence:

```
enum PosTerm {
  Single { quantifier, pattern: Expr },
  Group  { quantifier, seq: Vec<PosTerm> },
}
```

`Single` with `Quantifier::One` is the bare-pattern case. A quantifier head
with one sub-pattern parses to `Single`; with more than one, to `Group`.

**Alternatives considered:**

- *Flat list with a span marker* (keep `Vec<PositionalArg>`, tag group
  start/end): rejected — groups nest, so the data is inherently a tree;
  a flat encoding pushes nesting logic into every consumer.
- *Explicit `(seq …)` head, `Group` only via `seq`*: rejected for surface
  syntax (D5) but the AST `Group` node is exactly an implicit `seq`.

### D2: Implicit-seq surface syntax; modifiers get their own head later

`(? A B …)` reads all args after the head as sequence elements. Chosen over
`(? (seq A B …))`.

Rationale: the only thing that varies on a quantifier head today is arity;
may-i's element-head set (`or and regex not cond ? + *`, plus literals, `*`,
`[:k e]`) is closed and disjoint from any plausible modifier head, but a
*human* reads `(+ A (max 5))` ambiguously and reserving modifier heads burns
symbols. Keeping the quantifier arglist as pure sequence elements forever, and
giving future modifiers their own wrapping head (`(sep-by "," A)`,
`(rep 2 5 A B)`, `(bind #items (+ A B))`), avoids the collision entirely.

**Alternatives considered:**

- *Explicit `(seq …)`*: keeps the quantifier arglist free for trailing
  options. Rejected — we do not want trailing options (they collide under
  implicit-seq and are the only thing explicit-seq buys), and `(? "run" (? "--"))`
  is the ergonomic target.

### D3: Backtracking group matcher with nullable guard + step budget

`+`/`*` over a `Group` is Kleene repetition over a sub-sequence: greedily
match as many full sub-sequence occurrences as possible, then backtrack
(try fewer) so following patterns can match — generalising the existing
greedy-then-backtrack loop (`positional.rs:157-237`).

Termination:

- **Nullable guard**: if a repetition iteration consumes zero args, stop the
  repetition. Without this, `(* (? A))` loops forever. This is the only
  *new* unbounded risk groups introduce; existing flat patterns cannot loop.
- **Step budget**: thread a decrementing step counter through
  `match_positional_recursive`; on exhaustion return no-match. Bounds the
  pre-existing polynomial blow-up too. Budget lives in config structure with
  a high default (only pathological Patterns hit it) and no surface syntax,
  making it testable without committing to a user-facing knob.

**Alternatives considered:**

- *No budget, nullable guard only*: rejected — the user asked for the budget
  to be config-structure-level and testable rather than hard-coded, and it
  also caps the existing polynomial case.
- *Forbid nullable groups under `*`/`+` at parse time*: rejected — more
  surprising to authors than silently terminating a zero-consuming iteration,
  and the guard is cheap.

### D4: Fused match-evidence type carries provenance (soundness)

Replace the two-call (`match_expr_with_binding` + `unprovable_match`) pattern
with a single smart constructor:

```
struct MatchEvidence { facts: ContextFacts, unresolved: Vec<String> } // private fields
fn match_token(pattern, token, expansion) -> Option<MatchEvidence>
impl MatchEvidence { fn and(self, other: Self) -> Self /* merges BOTH fields */ }
```

`match_token` is the only way to obtain evidence of an element match, and it
always computes `unresolved` from `pattern.matches_any_value()` and the
expansion. The matcher combines evidence with `and`, which merges both fields.
A successful path therefore cannot exist without its provenance — the unsound
state (matched-without-provenance) is unconstructible, converting "forgot to
thread `unresolved` on one of N new group paths" from a silent omission into
"produced no evidence, so the path cannot succeed".

This is not a dependent-type proof (Rust cannot express "unresolved equals
exactly the constrained expansion-bearing matches on this path"); the residual
— that `and` is associative/total — is covered by one proptest. The refactor
also de-risks the existing flat matcher.

**Alternatives considered:**

- *Keep two calls, add targeted tests per group path*: rejected — relies on
  every future contributor remembering the second call; the failure mode is
  invisible and security-relevant.

### D5: Canonical form / trust hash and `fmt`

`Group` serialises as `(Q elem …)` with the same head glyphs. `to_doc` /
pretty-printer render the nested form; `fmt` must be idempotent on it. Trust
hashing serialises the new node canonically. Existing trusted configs use no
groups, so their canonical form and hashes are unchanged and continue to
verify (consistent with the `binding-shapes` canonical-form precedent).

## Risks / Trade-offs

- **Exponential backtracking on nested repetition** (`(* (* A))`) → step
  budget caps it; nullable guard removes the infinite case. Budget default
  set high enough that legitimate rules never hit it.
- **Soundness regression on a new group path** → D4 makes the unsound state
  unconstructible; one proptest covers the combinator law; a targeted test
  asserts a constrained match against `$VAR` inside a repeated group floors
  to `:ask`.
- **Proptest suite slows** if the generator emits deep nullable nests that
  burn the budget every case → cap generator nesting depth and prefer
  non-nullable inner terms under repetition.
- **Lost bind correlation in repeated groups** (`(* [:k k] [:v v])` unions
  into sets, losing pairing) → accepted and documented; no current predicate
  tests correlation, and adding a correlated operator is out of scope.
- **Reader ambiguity of implicit-seq** (`(+ A B)` = repeat-pair vs two
  patterns) → documented in `CONTEXT.md`; mitigated by the "modifiers get
  their own head" rule (D2) so the arglist meaning never shifts.

## Migration Plan

Additive grammar change: forms previously rejected ("? must have exactly one
pattern") now parse. No existing config changes meaning. No migration entry
required (no Class-B rewrite of existing forms). Trust store unaffected
(no existing config uses groups). Rollback is removing the feature; since no
config will have depended on it before release, there is no data to migrate
back.

## Open Questions

- Exact default value for the step budget (order of magnitude; pick during
  implementation against the proptest corpus so legitimate deep rules pass).
- Whether `build_positional_element_details` (annotation/trace re-walk,
  `positional.rs:308`) needs full group awareness for trace rendering, or a
  simpler "group consumed N args" summary suffices for the trace UI.
