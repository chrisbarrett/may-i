## Why

When a command's name is a variable, `may-i` gives up and reports `dynamic
command name: $BIN` → ask — even when the variable was just assigned a constant
in the same command. The idiom `BIN=./target/debug/may-i; $BIN eval …` (and the
loop form `for c in …; do "$BIN" eval … "$c"; done`) is everywhere in agent
tooling, and every such call asks despite the program name being **provable**.
The value is sitting right there in a literal assignment; `may-i` should
dereference it and evaluate the real command name.

## What Changes

- Resolve a variable command name against the constants the same command
  provably assigns. `BIN=./x; $BIN run` SHALL evaluate as the command `./x`, not
  as a dynamic command.
- Resolution is **conservative — provably-constant only**. A variable is
  resolved only when it has a single static-literal assignment that
  unconditionally executes before the use, with no reassignment or `unset`
  anywhere in the command. Anything uncertain (assigned from `$(…)`, assigned
  inside a conditional/loop/function, reassigned, a loop variable) stays a
  dynamic command and asks, exactly as today.
- Wrong resolution is never acceptable: resolving to the wrong name would apply
  the wrong rule, so the default direction is to stay dynamic. The change only
  ever *narrows* the set of dynamic-command asks; it never changes a non-dynamic
  decision.

## Capabilities

### New Capabilities

<!-- none -->

### Modified Capabilities

- `shell-command-security-model`: add a requirement that a variable command name
  with a provably-constant value (single static-literal assignment, executes
  before use, no reassignment/unset) is resolved to that value and evaluated as
  that command; all other variable command names remain dynamic.

## Impact

- `crates/shell-parser` — a pure AST analysis that returns the provably-constant
  variable environment for a command (single straight-line static assignment per
  variable), reusing the existing `resolve_param_op` machinery.
- `crates/engine/src/eval/decompose.rs` — before classifying a first word as a
  `DynamicCommand`, attempt resolution against that constant env; on success emit
  a `SimpleCommand` with the resolved name.
- Tests: `crates/shell-parser` analysis cases + `crates/engine` eval scenarios.
- No DSL, config, or trust-hash surface change; no migration. Out of scope:
  resolving variable *arguments*, transitive assignments (`DIR=/o; BIN=$DIR/x`),
  and any value not provable by straight-line analysis.
