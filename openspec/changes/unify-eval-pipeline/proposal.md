## Why

The hook path (Claude Code integration) and `eval --json` currently use
`parse_command_args` which extracts only the first simple command from the
input. Compound commands like `echo hello && rm -rf /` evaluate only `echo`,
completely bypassing policy on `rm`. The pretty-print `eval` path uses
`evaluate_segments` which correctly segments at top-level operators, but this
logic is not shared with the other paths. This is a security defect: the
security-critical hook path is strictly less safe than the human-facing path.

See: [shell-command-security-model](../../specs/shell-command-security-model/spec.md)
requirements R1, R2, R3.

## What Changes

1. **Replace `evaluate_segments` and `parse_command_args` with a single
   AST-based evaluation function** that all three entry points use (hook, eval
   --json, eval pretty).

2. **The new function walks the parsed AST** to extract every simple command,
   evaluates each against the policy, and returns the aggregate (most
   restrictive) decision.

3. **Embedded commands in substitutions (`$(...)`, `` `...` ``, `<(...)`,
   `>(...)`) are recursively parsed and evaluated.** Their decisions contribute
   to the aggregate.

4. **Dynamic command names** (containing `$VAR`, `$(cmd)`, globs, etc.) produce
   `:ask` with a descriptive reason.

5. **The `segment()` function becomes presentation-only** — used solely for
   colorizing output in the pretty-print path. It no longer drives evaluation.

## Capabilities

### Spec Alignment

- [shell-command-security-model](../../specs/shell-command-security-model/spec.md)
  — R1 (unified pipeline), R2 (AST decomposition), R3 (embedded command eval),
  R5 (dynamic command names), R6 (empty input)

### Affected Components

- `src/cmd_eval.rs` — replace `parse_command_args` + `evaluate_segments` with
  unified function
- `src/cmd_claude_code_hook.rs` — use the unified function instead of
  `parse_command_args`
- `crates/engine/` — new `decompose` module for AST walking + embedded command
  extraction
- `crates/shell-parser/` — expose `extract_all_words` or similar for walking
  word parts (currently test-only)

### Unchanged

- `crates/shell-parser/src/segment.rs` — retained for display colorization
- Config loading, rule parsing, effect evaluation — unchanged
- The `EvalFold` trait and tracing infrastructure — unchanged

## Scope

This change focuses on making the evaluation pipeline correct and unified. Parse
error reporting (R4 from the spec) is a separate change that builds on this
foundation.

## Risks

- **Trace output changes**: The pretty-print trace currently shows per-segment
  headers. The new trace will show per-command headers from AST decomposition,
  which may look different. This is acceptable — the new output is more accurate.

- **Embedded command recursion depth**: Deeply nested substitutions like
  `$($($($(cmd))))` could be expensive. Reuse the existing recursion depth limit
  from the `may-i` effect evaluation.

- **Behavioural change for existing users**: Commands that previously evaluated
  as `:allow` (because only the first command was checked) will now correctly
  evaluate as `:ask` or `:deny`. This is strictly more secure — the old
  behaviour was a bug.
