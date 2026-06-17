## Why

A command substitution executes a command, so `may-i` must evaluate it wherever
it appears. Today the decomposer only scans substitutions in **simple-command
words** and **redirect targets**. A `$(…)` / `` `…` `` / `<(…)` in a bare
assignment value, a `for` loop's iteration words, or a `case` subject/pattern
runs at runtime but produces **no evaluation unit** — so nothing gates it. The
command silently resolves to `:allow`:

```
z=$(rm -rf /); echo done            → allow   ← rm never gated
for x in $(rm -rf /); do echo; done → allow   ← rm never gated
case $(rm -rf /) in *) echo;; esac  → allow   ← rm never gated
```

This is a bypass of the whole security model — a dangerous embedded command
escapes review entirely — and the position list will keep drifting as the
grammar grows. The same bug class (a code-bearing position the static walk
skips) was just closed for function-call liveness; this closes it for embedded
command extraction.

## What Changes

- Extract embedded substitutions (`$( … )`, backticks, process substitution)
  from **every** word position the AST exposes, not just simple-command words
  and redirect targets:
  - values of bare `Command::Assignment` nodes (`z=$(…)`),
  - `for` loop iteration words (`for x in $(…)`),
  - `case` subject and pattern words (`case $(…) in $(…)) …`).
- Add a coverage **invariant** (property test): every command/backtick/process
  substitution present in the input yields an `EmbeddedCommand` evaluation unit,
  so a future word position cannot silently reintroduce the gap.

## Capabilities

### New Capabilities

<!-- none -->

### Modified Capabilities

- `shell-command-security-model`: add a requirement that an embedded command
  substitution is evaluated regardless of the word position it occupies —
  assignment values, loop words, and case words included — so it can never
  resolve to `:allow` unreviewed.

## Impact

- `crates/engine/src/eval/decompose.rs` — extend the embedded-extraction walk
  (sibling to `push_embedded_units_from_redirect_targets`) to cover assignment
  values, `For` words, and `Case` words; keep span/coordinate handling identical
  to the existing paths so nested-segment colouring stays correct.
- Tests: `crates/engine` decompose units + a cross-cutting property test
  asserting substitution-coverage across arbitrary inputs.
- No DSL, config, trust-hash, or migration surface change. Pre-existing bug,
  independent of `recognise-local-function-calls`. Out of scope: opaque-string
  commands (`eval`/`trap`/`source`/`bash -c`) — these gate by their own name and
  ask by default; intentional recursion into a wrapper payload remains the
  `(authorise …)` mechanism's job.
