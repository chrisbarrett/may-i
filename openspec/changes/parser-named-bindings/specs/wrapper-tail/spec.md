## REMOVED Requirements

### Requirement: `(tail (after VALUE))` declares a tail slice in a parser

**Reason**: Replaced by explicit binding via `(rest #var)` plus flag-scanning mode via `(flags MODE)`. The boundary-vs-mode conflation was one of the warts addressed by this change.

**Migration**: `(tail (after :flags))` rewrites to `(flags posix) (rest #cmd)`. `(tail (after "TOK"))` rewrites to `(flags (until "TOK")) (rest #cmd)`. `(tail (after [STR…]))` rewrites to `(flags (until STR…)) (rest #cmd)`. The migration is mechanical (Class A) and runs automatically under `may-i migrate`.

### Requirement: `(tail (authorise))` recurses on the tail slice

**Reason**: Replaced by `(authorise #var)` where `#var` is the binding declared by `(rest …)` (or by a `(parameter …)` or `(positional …)` declaration). The single-verb-with-explicit-argument form removes the context-sensitive routing that the old `(tail …)` form required.

**Migration**: `(tail (authorise))` in a rule body rewrites to `(authorise #cmd)` (where `#cmd` is the name of the parser's `(rest …)` binding). Migration applies under `may-i migrate`; conventional name is `#cmd`.

### Requirement: When parser declares `(tail …)`, argv matchers scope to outer slice

**Reason**: The outer/tail distinction is replaced by a single binding environment plus a positional residual. Rule-body matchers (`(flag …)`, `(parameter …)`, `(positional …)`, `(exact …)`, `(anywhere …)`, `(forbidden …)`) operate on the post-flag-scanning positional residual under the active `(flags MODE)`. The tail value bound by `(rest …)` is opaque to these matchers — it is only accessible via `(authorise #var)`, `(bound? #var)`, `(matches? #var …)`, or promotion through `(with-facts …)`.

**Migration**: Behaviour is preserved by the new model — matchers continue to see the equivalent of the old "outer" slice. No rule-body rewrites required beyond the `(tail (authorise))` → `(authorise #var)` rewrite covered above.

### Requirement: `(tail (authorise))` without parser-declared tail uses residual positionals

**Reason**: The residual-fallback behaviour was the fourth of five context-sensitive meanings for `(tail (authorise))` and the most fragile (it routed silently based on absence of a declaration). It is replaced by explicit positional bindings: where a rule previously did `(when (positional [:k *]) (tail (authorise)))`, the migration moves the positional capture to the parser body as `(positional #var *)` and the rule body becomes `(with-facts [[:k #var]] (authorise #cmd))`.

**Migration**: Class B (semantic shift). The migration tool detects the `(when (positional …) (tail (authorise)))` idiom, emits a warning per affected rule, and suggests the parser-body rewrite. The user verifies via `may-i check` against their existing `(check …)` blocks. The user's primary config has this pattern in `ssh`, `direnv exec`, and `timeout` rules; all are flagged.

### Requirement: Trace surfaces outer/tail split

**Reason**: Replaced by trace rendering of the binding environment. The new trace shows the parser's resolved `(flags MODE)`, the positional residual, and the value of each bound `#var` per evaluation step.

**Migration**: Trace renderer rewritten as part of this change. Snapshot baselines under `src/snapshots/` and oracle-trace tests under `crates/engine/src/integration_tests.rs` are regenerated.

### Requirement: Improper-list `(positional X . CONT)` retires

**Reason**: Already retired by the dsl-coherence change. This requirement is dropped from the wrapper-tail capability because the entire `(tail …)` form is removed; the migration story moves to the parser-bindings capability.

**Migration**: No further action — the dsl-coherence migration already eliminated this form.
