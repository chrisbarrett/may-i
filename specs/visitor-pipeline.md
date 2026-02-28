# Visitor Pipeline

Chain-of-responsibility pattern for evaluating simple commands. Each visitor
inspects a resolved command and either handles it (terminal), passes it to the
next visitor (continue), or rewrites it for re-evaluation (recurse).

---

## R22: Visitor outcomes

A visitor returns one of:

| Outcome    | Meaning                                                   |
| :--------- | :-------------------------------------------------------- |
| `Terminal` | Handled — return this result; skip remaining visitors     |
| `Continue` | Not handled — pass to next visitor in chain               |
| `Recurse`  | Rewrite command and re-walk from the top (e.g., unwrap)   |

`Terminal` carries an `EvalResult` and updated `VarEnv`. `Recurse` carries a
rewritten `Command` and updated `VarEnv`.

**Verify:** `cargo test -- engine`

## R23: Visitor chain order

Visitors execute in fixed order. Order matters — earlier visitors short-circuit
later ones:

1. **ReadBuiltin** — `read`, `readarray`, `mapfile`
2. **DynamicParts** — unresolvable dynamic content
3. **CodeExecution** — `source`, `eval`, `bash -c`
4. **FunctionCall** — user-defined functions
5. **WrapperUnwrap** — `nohup`, `env`, `sudo`, etc.
6. **RuleMatch** — match against config rules (catch-all, always terminal)

`RuleMatch` is guaranteed to produce a `Terminal` result, so the chain always
terminates.

**Verify:** `cargo test -- engine`

## R24: ReadBuiltin visitor

**Given** command is `read` **Then** allow and mark target variables as `Opaque`
(user input is safe but unknown).

**Given** `read` with a herestring providing a literal value and a single target
variable **Then** mark the variable as `Known(value)`.

**Given** command is `readarray` or `mapfile` **Then** allow and mark target
variable as `Opaque`.

Default target variable for bare `read` is `REPLY`.

**Verify:** `cargo test -- engine::read`

## R25: DynamicParts visitor

**Given** a resolved command containing unresolvable dynamic parts (unexpanded
variables, command substitutions in command position, etc.) **Then** return
`ask` with a reason identifying the dynamic content.

This catches commands that cannot be statically analyzed and ensures the user
is prompted rather than silently allowing an unknown operation.

**Verify:** `cargo test -- engine::dynamic`

## R26: CodeExecution visitor

**Given** `source` or `.` **Then** return `ask` (file contents are unknown at
analysis time).

**Given** `eval` with all-literal arguments **Then** concatenate args and
recurse (re-parse and re-evaluate the resulting string).

**Given** `eval` with opaque arguments **Then** return `ask`.

**Given** `bash -c`, `sh -c`, or `zsh -c` with a literal `-c` argument **Then**
recurse into the argument string.

**Given** `bash -c` with an opaque `-c` argument **Then** return `ask`.

Recursion depth is capped (see constraints).

**Verify:** `cargo test -- engine::code_execution`

## R27: FunctionCall visitor

**Given** a command name matching a function definition stored in `VarEnv`
**Then** set positional parameters (`$1`, `$2`, ...) from the resolved
arguments, then recurse into the function body.

Argument state propagates: literal args become `Known`, opaque args become
`Opaque`.

**Verify:** `cargo test -- engine::function`

## R28: WrapperUnwrap visitor

**Given** a command matching a configured wrapper pattern (R9) **Then** extract
the inner command and recurse.

**Given** a wrapper whose inner command is a single word containing spaces
**Then** re-parse it as a full shell command (handles `ssh host 'complex
command'`).

Wrapper recursion depth is capped at 5 levels.

**Verify:** `cargo test -- engine::wrapper`

## R29: RuleMatch visitor (catch-all)

**Given** a resolved command **Then** expand flags (R8), iterate all config
rules, and match.

- First `deny` match → return immediately
- First `allow` match → save it, continue searching for `deny`
- No match → `ask` (either "no matching rule" or "rule matched but args
  didn't")

Always returns `Terminal`.

**Verify:** `cargo test -- engine`; `may-i check` exercises inline examples

## Constraints

- Maximum evaluation depth: prevents infinite recursion through `eval`,
  `bash -c`, nested function calls, and wrapper unwrapping
- Visitor chain is closed — adding a visitor requires updating the fixed chain
- RuleMatch must always be last (catch-all guarantee)
