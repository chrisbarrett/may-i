## Why

`may-i fmt` currently alphabetises `(check …)` cases by their first
string literal. Users author check forms with section-header comments
that group related cases ("Resource management", "State manipulation",
etc.), and trivia rides along with cases when they move — so each `fmt`
run scrambles the comments away from the cases they were meant to label.
Check cases are independent test assertions (engine-order-independent)
but they are also human-curated content, which means reordering destroys
authored structure for no semantic benefit. The canonicaliser made a
category error treating them like a set.

## What Changes

- The canonicaliser SHALL preserve source order of `(check …)` cases.
- Trivia (comments and blank lines) continues to attach to its neighbour
  forms; with no reorder pass it simply stays put.
- Recursion into check-case children continues unchanged — nested forms
  (`with-facts`, decision verbs, embedded patterns) still receive their
  normal canonical treatment.
- The pretty-printer's indentation and whitespace normalisation for
  check forms is unaffected.
- **BREAKING (formatting only)**: configs whose check cases were
  previously alphabetised by `fmt` will not be auto-rearranged. The fix
  stops future scrambling; one-time manual re-clustering under section
  comments is the user's responsibility. No migration tool ships.

## Capabilities

### New Capabilities

_None._

### Modified Capabilities

- `pretty-printing`: the Canonical body-form ordering requirement
  changes — `(check …)` cases move from the sorted list to the
  preserved-order list, and the principle is restated so it generalises
  (sort only when a form is both engine-order-independent and not
  human-curated).

## Impact

- **Code**: `crates/config/src/canonicalise.rs` — drop the
  `Some("check") => sort_check_body` arm; recursion path stays. The
  `sort_check_body` function becomes dead code and can be removed along
  with its helper `check_case_sort_key`.
- **Tests**:
  - Unit test `check_cases_alphabetised_by_command` inverts to assert
    source order.
  - Proptest `canonicalise_is_idempotent_on_check` continues to hold
    (trivially under a no-op sort); retain as a guard against future
    regressions.
- **Docs**:
  - `REFERENCE.md` lines 757 and 862 currently state "(check …) body:
    cases alphabetised by command string" — update to "source order
    preserved".
  - `CONTEXT.md` § Canonical-form ordering already encodes the refined
    principle (this change makes the code match).
- **Trust**: no effect. `canonical_rule` in
  `crates/engine/src/trust.rs` already excludes checks from the trust
  hash; the existing `canonical_rule_excludes_checks` test pins this.
- **Behavioural diff for users**: configs with check-case orderings
  that differ only in permutation will now produce different `fmt`
  output. They are functionally equivalent under `may-i check`.
