## Why

A script that defines shell functions and then calls them — common in agent
tooling — is flagged spuriously. `may-i` already traverses function bodies and
authorises the commands inside them, but it does not know that the function
*name* was defined by the same script. So every call site
(`materialise "$BASE"`, `run_seeds …`, a sibling call inside another body) is
treated as an unknown external program and reported `No rule for command
`materialise``, forcing an ask. The dangerous operations are already caught at
the body; the call to a script-local function executes nothing but dispatch and
should not read as an unknown command.

## What Changes

- Recognise **script-local functions**: collect the names defined by
  `FunctionDef` nodes anywhere in the parsed command, and treat a simple command
  whose name is one of them as an **internal call**, not an external program.
- An internal call resolves to `:allow` and is traceable as such (the body was
  authorised once, at its definition) — it does not emit `No rule for command
  …`. Function bodies continue to be authorised exactly as today.
- Semantics are **set-based** (order-insensitive): a name defined as a function
  anywhere in the command makes calls to it internal. This intentionally favours
  forward references and mutual recursion (a body calling a sibling defined later
  is correct at runtime) over the exotic case of a call preceding its definition;
  that imprecision is documented, not handled by flow analysis.

## Capabilities

### New Capabilities

<!-- none -->

### Modified Capabilities

- `shell-command-security-model`: add a requirement that a call to a
  script-local function is an internal call (resolves to `:allow`, never `No
  rule for command …`), that function bodies remain authorised, and that
  recognition is set-based across the whole command.

## Impact

- `crates/shell-parser` — expose the set of `FunctionDef` names from a parsed
  command (a collector alongside `extract_simple_commands`).
- `crates/engine/src/eval/decompose.rs` — add a `LocalFunctionCall` `EvalUnit`;
  classify a simple command whose name is a defined-function name as that unit
  instead of a `SimpleCommand`. Function bodies still decompose as today.
- `crates/engine/src/eval/command.rs` — evaluate a `LocalFunctionCall` as
  `:allow` with a traceable reason; it contributes nothing to the aggregate.
- Tests: `crates/engine` decompose + eval scenarios.
- No DSL, config, or trust-hash surface change; no migration. Out of scope:
  dynamic command names (`"$VAR" …`) and the `done < <(…)` parse warning seen in
  the same scripts — both tracked separately.
