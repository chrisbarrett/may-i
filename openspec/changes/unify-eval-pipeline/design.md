## Context

Three code paths currently convert a raw command string into a security
decision, each using different logic:

1. **Hook path** (`cmd_claude_code_hook.rs:31`): calls `parse_command_args` →
   `parse_simple_command` → evaluates only the first simple command. Compound
   commands (`&&`, `||`, `;`, `|`) are not decomposed.

2. **`eval --json`** (`cmd_eval.rs:37-51`): same `parse_command_args` path.

3. **`eval` pretty** (`cmd_eval.rs:52-67`): calls `evaluate_segments` which uses
   the lexer-level `segment()` function to split at top-level operators, then
   evaluates each segment independently and aggregates with `max(decisions)`.

Path 3 is more secure than paths 1 and 2, but still operates at the lexer level
— it cannot see inside subshells, brace groups, loops, or conditionals.

The shell parser already produces a full AST that represents the complete
structure. The evaluator should walk this AST instead of relying on
lexer-level segmentation.

Additionally, the parser extracts `CommandSubstitution`, `Backtick`, and
`ProcessSubstitution` as word parts, but the evaluator never inspects argument
word parts for embedded commands.

## Goals / Non-Goals

**Goals:**

- Single evaluation function used by all three entry points (hook, JSON, pretty)
- AST-based command decomposition that recurses into all compound structures
- Recursive evaluation of embedded commands in `$(...)`, `` `...` ``, `<(...)`,
  `>(...)` word parts
- Dynamic command names (containing `$VAR`, `$(cmd)`, etc.) produce `:ask`
- Empty/whitespace input produces `:ask`
- Trace output reflects per-command evaluation within compound commands
- The `segment()` function remains available for display colorization only

**Non-Goals:**

- Parse error reporting (separate `parse-diagnostics` change)
- Changing the config DSL, rule syntax, or effect evaluation
- Handling aliases, tilde expansion, or runtime variable resolution
- Modifying the `EvalFold` trait

## Decisions

### D1: New `evaluate_command` function in the engine crate

**Decision**: Add `engine::eval::evaluate_command(input: &str, config, facts) →
EvalResult` that parses the input, walks the AST, evaluates all simple commands
and embedded substitutions, and returns the aggregate decision.

**Alternatives considered**:

- *Extend `evaluate_segments`*: This would still be lexer-level. The segmenter
  cannot recurse into subshells, conditionals, or word parts. Rejected.
- *Add decomposition to existing `evaluate`*: The current `evaluate` takes
  `(command_name, args)` — changing its signature would be a larger refactor.
  Better to add a new higher-level entry point that calls `evaluate` per simple
  command.

**Rationale**: A new top-level function is the cleanest way to unify the three
paths without restructuring the existing per-rule evaluation.

### D2: AST walk via `Command::children()` + word-part extraction

**Decision**: Use the existing `Command::children()` method to recursively
find all `Simple(cmd)` nodes. For each simple command, also walk its word
parts to find embedded commands (`CommandSubstitution`, `Backtick`,
`ProcessSubstitution`).

The walk produces a flat list of `EvalUnit`:

```rust
enum EvalUnit {
    /// A simple command extracted from the AST.
    SimpleCommand { command: String, args: Vec<String> },
    /// An embedded command found in a word part (substitution).
    EmbeddedCommand { source: String },
    /// A command with a dynamic name that cannot be resolved.
    DynamicCommand { reason: String },
}
```

Each `EvalUnit` is evaluated independently. `EmbeddedCommand` sources are
recursively parsed and evaluated through the same pipeline. `DynamicCommand`
always produces `:ask`.

**Alternatives considered**:

- *Evaluate at the AST node level (preserving structure)*: This would let the
  trace show the compound structure (if/then/else, etc.). More informative but
  significantly more complex — requires threading fold through compound nodes.
  Deferred to a future enhancement.

**Rationale**: Flat decomposition is simpler, correct, and sufficient. The
compound structure is visible in the original command string; the trace shows
which simple commands matched which rules.

### D3: Embedded command recursion uses `parser::parse` + same pipeline

**Decision**: When an `EmbeddedCommand` source is found (e.g., the string
`"rm -rf /"` from `$(rm -rf /)`), it is parsed with `parser::parse` and
evaluated through the same `evaluate_command` pipeline. This naturally handles
nesting: `$(echo $(rm -rf /))` first parses `echo $(rm -rf /)`, which itself
contains an embedded `$(rm -rf /)`.

**Depth limit**: Reuse the existing recursion depth limit from the `may-i`
effect. Default 10 levels, which is more than sufficient.

**Alternatives considered**:

- *Skip embedded commands entirely*: Leaves a security gap — rejected.
- *Only evaluate the outermost substitution*: Misses nested substitutions —
  rejected.

### D4: Dynamic command detection via `Word.has_dynamic_parts()`

**Decision**: A command name is "dynamic" if its first word contains any
non-literal, non-quoted word part. The existing `Word` type already has a
`dynamic_parts()` method (test-only). Promote this to public API.

Word parts that make a command name dynamic:
- `Parameter` / `ParameterExpansion` / `ParameterExpansionOp`
- `CommandSubstitution` / `Backtick`
- `Arithmetic`
- `Glob`
- `Opaque`

Word parts that are static: `Literal`, `SingleQuoted`, `DoubleQuoted` (if all
inner parts are static), `AnsiCQuoted`, `BraceExpansion`.

### D5: Aggregate decision is `max()` over all units

**Decision**: The final decision is `max(unit_decisions)`, using the existing
`Decision` ordering (Allow < Ask < Deny). The reason string comes from the
most-restrictive unit.

If any parse diagnostic has Error severity (once `parse-diagnostics` is
implemented), the floor is raised to `:ask`.

### D6: All three entry points call `evaluate_command`

**Decision**:

- `cmd_claude_code_hook.rs`: replace `parse_command_args` + `evaluate` with
  `evaluate_command`.
- `cmd_eval.rs` JSON path: replace `parse_command_args` + `evaluate_with_fold`
  with `evaluate_command` (with fold).
- `cmd_eval.rs` pretty path: replace `evaluate_segments` with
  `evaluate_command` (with fold). Use `segment()` only for display colorization
  after evaluation.

### D7: Trace output for compound commands

**Decision**: When the input contains multiple simple commands, the trace shows
a segment header per command (similar to current `evaluate_segments` behaviour).
Embedded commands appear as nested trace entries.

The fold interface gets one new method:

```rust
fn embedded_command(&mut self, source: &str, decision: Decision);
```

This is minimal and non-breaking — existing fold implementations get a default
no-op.

## Risks / Trade-offs

**[Behavioural change]** Commands previously allowed (because only the first was
checked) will now correctly evaluate as `:ask` or `:deny`. → This is
intentional. The old behaviour was a bug. Users who relied on it need to add
rules for the additional commands.

**[Trace output format change]** The pretty trace will look slightly different
for compound commands. → The information is strictly more complete. No backwards
compatibility concern for machine-readable JSON since the hook response format
is unchanged.

**[Performance]** Parsing embedded commands requires recursive `parser::parse`
calls. → Each call is O(n) in the substitution string length. In practice,
commands are short. The recursion depth limit prevents pathological cases.

**[`segment()` becomes presentation-only]** Code that currently uses
`evaluate_segments` for display will need to be adjusted to use the new
evaluation function for decisions and `segment()` only for colorization. →
Contained to `cmd_eval.rs`.
