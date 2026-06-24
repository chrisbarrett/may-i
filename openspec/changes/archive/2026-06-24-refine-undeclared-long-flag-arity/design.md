## Context

The gnu Tokenisation guesses the arity of an undeclared long flag in
`crates/engine/src/eval/entry.rs`. `parser_positional_indices` computes the
positional residual; when `gnu_long_consumes_next` holds (gnu-shaped Style) it
consumes the next token for **every** undeclared long flag:

```rust
let consumes_next = is_declared_param || (starts_long && gnu_long_consumes_next);
if consumes_next && separators.iter().any(|s| s == " ") && iter.peek().is_some() {
    iter.next();
}
```

The stated reason — "without this, `(parameter X *)` rules can't see the value"
— is stale: `Config::parser_for_with_rules` already back-fills implicit
parameters from Rule bodies (`crates/core/src/ast.rs`), so `is_declared_param`
covers every flag any Rule cares about. The blanket consume therefore only moves
the residual for flags **nobody declared** — and it does so blindly, eating
flags, the `--` flag-stop, and subcommands.

Established empirically against the debug binary:

- `cargo run --quiet --bin may-i -- eval` → `--quiet` eats `--bin` → `run`/`--`
  non-adjacent → spurious `ask`.
- `cargo --release build` → `--release` eats `build` → `(positional "build")`
  misses → silent `ask`. Note: the value-shape guard does **not** resolve this
  case — `build` is a plausible (non-flag) value, so `--release` still consumes
  it. The guard fixes only flag-then-flag adjacency (the `--quiet --bin` case);
  the `--release build` guess is now made *observable* via the (B) Advisory and
  side-stepped by declaring the flag, not silently corrected.
- `(flag …)` and `(anywhere …)` match on raw argv — they saw a consumed
  `/etc/shadow`. Only `(positional …)` reads the consumption-sensitive residual.

## Goals / Non-Goals

**Goals:**

- Make the undeclared-long-flag arity guess value-shaped: don't consume a
  flag-shaped token or the `--` flag-stop (C′).
- Make the residual guess that remains (undeclared flag + non-flag value)
  observable via a Trace Advisory (B).
- Document `(flag)`/`(parameter)` as parser-body kinds and steer deny-guards
  onto consumption-immune Patterns (A).

**Non-Goals:**

- Flipping the default to pure-boolean (never consume undeclared). Rejected: it
  doesn't fix the cargo adjacency case (`--bin may-i` would leave `may-i` as a
  positional) and breaks legitimate undeclared value flags more often.
- Modelling cargo's (or any tool's) full flag set in the prelude.
- Changing declared-parameter behaviour, short-flag clustering, or non-gnu
  Styles.
- A config-syntax migration — no surface syntax changes.

## Decisions

**1. Value-shape predicate over arity inference.** Gate consumption on the shape
of the *next* token, not on any guess about the flag itself. A token is
flag-shaped (⇒ not consumed) iff it begins with the Style's short/long prefix
and the char after the prefix is a letter. Digits (`-5`), bare `-`, and
prefix-less tokens are plausible values (⇒ consumed).

- *Why:* "an option value doesn't itself look like an option" is the convention
  clap/argparse/getopt-in-practice already follow; users expect it. It fixes
  flag-then-flag (the cargo nag) at the mechanism level.
- *Alternatives:* (a) pure-boolean default — see Non-Goals; (b) declare every
  cargo flag — high authoring burden, recurs per tool; (c) `separators "="`
  style (the shipped `.may-i.lisp` workaround) — blunt, loses space-separated
  values globally.

**2. Guard applies only to the guess, not to declared parameters.** Keep
`is_declared_param` consuming unconditionally — the author asserted arity, so
`grep --regexp --foo` legitimately takes `--foo` as the pattern.

**3. Advisory emitted at the guess site, surfaced through the Trace.** The
consume decision in `parser_positional_indices` is where the guess is known.
Thread an advisory record (flag spelling + consumed token) out to the
`TracingFold` so it lands in both the human and JSON trace surfaces, alongside
existing advisory rendering. Emit only when a guess was actually made (undeclared
+ non-flag value) — not when the flag was declared or left value-less.

- *Why here:* the alternative (re-deriving the guess in the renderer) duplicates
  the tokeniser logic. Producing the advisory where the decision is made keeps
  one source of truth.

**4. A is documentation-only.** Reference text is hand-maintained in
`src/cmd_help.rs`; update it to list `(flag NAME)` / `(parameter NAME …)` as
parser-body declarations and add the deny-guard-placement guidance. No spec
governs the reference string, so it rides in tasks.

## Risks / Trade-offs

- **Trailing undeclared boolean before a guarded positional** → with the guard,
  `--A --B X` (A,B undeclared booleans, X a guarded positional) tokenises as `A`
  boolean, `B` consumes `X` — hiding `X` from a `(positional …)` deny-guard.
  → *Mitigation:* (A) guidance — security deny-guards belong on `(flag)` /
  `(anywhere)`, which are consumption-immune; document the residual class via the
  (B) advisory; proptest the shape.

- **Decision shift on existing configs** → re-tokenisation changes some outcomes
  (mostly `ask → allow`; rarely the reverse per above). → *Mitigation:* not
  trust-relevant (no hash/participation/approval change); call out in release
  notes; the change is pre-1.0.

- **Negative-number false-positives** → a genuine short flag that is all digits
  is vanishingly rare; treating `-5` as a value is the safe, conventional call.
  → *Mitigation:* documented; declarable via `(flag)` if a tool truly has a
  numeric flag.

- **Advisory noise** → common invocations carry undeclared value flags
  (`--output x`), so the advisory could fire often. → *Mitigation:* it is a
  Trace-only Advisory (not a prompt, no Decision change); threshold/visibility
  can follow existing advisory rendering conventions.

## Migration Plan

No config migration (no syntax change). Steps: implement the value-shape guard
and `--` protection; add the advisory; update reference text; add proptests and
`(check …)` regressions; note the tokenisation-behaviour change in release notes.
Rollback is a straight revert — no persisted state, no trust-store impact. The
`.may-i.lisp` `cargo` parser workaround may later be simplified back to
`(positional "run" "--")`, but that is optional and out of scope here.

## Open Questions (resolved)

- Should the arity-guess Advisory have a verbosity threshold (e.g. only at
  `--trace`/`ask`+), or always render? **Resolved:** always render, following
  the existing trace-advisory surface (it rides the same `traces` path as
  `unresolved expansion:` and renders whenever the trace does). No new knob.
- Is "char after prefix is a letter" the exact flag-shape test we want, or
  should it be "not a digit"? **Resolved:** "char after prefix is an ASCII
  letter". Digits (`-5`), bare `-`, and prefix-less tokens are plausible
  values; only a letter-led prefixed token is flag-shaped. This keeps
  negative-number values consumable and matches clap/argparse convention.
- Does declaring a flag suppress the guess? **Resolved (added during
  implementation):** a flag declared as a boolean `(flag …)` on the parser is
  treated as value-less and never consumes its successor — so declaring the
  flag is the supported mitigation for the trailing-boolean-before-subcommand
  case (`cargo --release build`). `(flag …)` was previously consulted only by
  rule-body matchers, not the tokeniser; this change makes it govern arity too.
