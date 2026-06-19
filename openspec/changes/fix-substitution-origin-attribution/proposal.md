## Why

When a command inside a substitution produces a reason (`No rule for command
`resolve``), the engine annotates it with the substitution's origin — e.g.
`($(...) substitution in `set`)`. The origin name is wrong: `outer_command_name`
(`crates/engine/src/eval/command.rs:282`) picks the **first simple command in
the whole input**, not the command that lexically contains the substitution. For
`set -euo pipefail; … main() { dest=$(resolve); … }`, the substitution lives in
an assignment inside `main`'s body, but the label says `in `set`` — attributing
the substitution to an unrelated command that did not run it. The label reads as
though `set` performed the substitution, which is misleading in exactly the
diagnostics an agent relies on to understand a prompt.

## What Changes

- Attribute each substitution to the **syntactic position that lexically
  contains it**, computed where `decompose` already partitions substitution
  ownership, instead of guessing a global first-command.
- The annotation describes the owning position by kind:
  - simple-command word → `in \`grep\``
  - assignment value → `in assignment to \`dest\``
  - `for` list word → `in \`for\` list`
  - `case` subject / pattern → `in \`case\` subject`
  - redirect target → `in redirect target`
- The annotation SHALL NOT attribute a substitution to a command that does not
  own it.

## Capabilities

### New Capabilities

<!-- none -->

### Modified Capabilities

- `shell-command-security-model`: require the substitution-origin annotation to
  describe the syntactic position that lexically contains the substitution, and
  forbid attributing it to a non-owning command.

## Impact

- `crates/engine/src/eval/decompose.rs` — each pass that emits an
  `EmbeddedCommand` (`decompose_simple_command`,
  `push_embedded_units_from_structural_words`,
  `push_embedded_units_from_redirect_targets`) tags the unit with its syntactic
  origin (a per-origin descriptor on `EvalUnit::EmbeddedCommand`), since each
  pass already knows the owning context.
- `crates/engine/src/eval/command.rs` — `annotate_embedded_reason` consumes the
  carried origin instead of the global `outer_command_name`; remove the
  first-simple-command heuristic.
- Tests: `crates/engine` — origin-label assertions for each position kind, and a
  regression for the `in `set`` cross-attribution.
- No DSL, config, or trust-hash surface change; no migration. Independent of the
  cross-substitution recognition change (different code paths); ordering between
  the two is free.
