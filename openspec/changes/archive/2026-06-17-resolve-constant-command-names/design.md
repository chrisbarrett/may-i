## Context

`BIN=./x; $BIN eval foo` evaluates to `:ask` with reason `dynamic command name:
$BIN`. The pieces to do better already exist:

- the parser models assignments as `Assignment { name, value }` and the value's
  word parts (so `BIN=./x` is a `Literal` value);
- `crates/shell-parser/src/resolve.rs::resolve_param_op` already resolves a
  `${VAR…}` parameter expansion against an env snapshot;
- `decompose` classifies a first word via `Word::is_dynamic()` → `DynamicCommand`.

What is missing is the link: nothing builds an env from the command's own
assignments, and `decompose` never tries to resolve a dynamic first word before
giving up.

This is the same definition-sequence theme as the function-call work — but the
safety polarity is **opposite**. There, treating a call as internal was safe even
if order was ambiguous, because the body was authorised regardless. Here,
resolving `$X` to the *wrong* command would apply the *wrong rule* — a potential
bypass. So resolution must be conservative and order-correct: prove the value or
stay dynamic.

## Goals / Non-Goals

**Goals:**

- Resolve a variable command name when its value is provably a constant literal
  assigned, unconditionally, before the use.
- Never change a decision except to turn a dynamic-command ask into evaluation of
  the real, proven command name.

**Non-Goals:**

- Resolving variable *arguments* (only the command name).
- Transitive resolution (`DIR=/o; BIN=$DIR/x`) — RHS must be a pure literal in v1.
- Any value requiring runtime knowledge: `$(…)`, conditionally-set, reassigned,
  loop/function-scoped, environment-inherited.

## Decisions

### D1 — A pure "provably-constant env" analysis in shell-parser

Add an AST analysis that returns `HashMap<String, String>` of variables whose
value is provably constant for the whole command. A variable qualifies only if:

- it has **exactly one** assignment in the command whose RHS resolves to a static
  literal (no substitution, no unresolved variable, no glob), and
- it is never reassigned or `unset`.

Assignments inside a conditional, loop body, or function body do **not**
qualify (they may not execute, or execute out of order). This keeps the analysis
a simple structural walk — no path enumeration — by treating "appears in a
branch/loop/function" as "not provable".

### D2 — Resolve the first word in decompose before declaring it dynamic

In `decompose`, when the first word is dynamic and consists of a single variable
expansion (`$VAR` / `${VAR}`, including a lone double-quoted form `"$VAR"` as in
the motivating loop), resolve it against the D1 env via `resolve_param_op`. On
success, emit `SimpleCommand { command: <resolved>, … }`; otherwise fall through
to `DynamicCommand` exactly as today. A mixed word (`/opt/$VAR/x`) or an operator
expansion (`${VAR:-x}`) stays dynamic. Argument words are untouched.

### D3 — Conservative by construction; resolution only narrows asks

If the variable is not in the D1 env, behaviour is byte-for-byte unchanged. A
resolved command name then flows through normal rule matching as any literal
first word would (path-vs-basename matching is an existing, orthogonal concern).
The analysis can never *introduce* a wrong allow because an unproven value is
never resolved.

## Risks / Trade-offs

- **Mis-resolution → wrong rule** → mitigated by the single-static-assignment,
  straight-line, no-reassignment bar; ambiguity always falls back to dynamic.
- **Straight-line precedence vs true execution order** → assignments in branches
  are conservatively excluded; we do not attempt to prove a conditional always
  runs. Cost: some safe cases stay dynamic. Acceptable — the change only adds
  coverage, never removes safety.
- **`export VAR=lit`** → treat as an assignment for the analysis; confirm a
  scenario. Prefix assignments (`VAR=lit cmd`) bind only `cmd`'s environment and
  do not name the command — out of the command-name path.

## Open Questions

- Transitive single-level resolution (`DIR=/o; BIN=$DIR/x`) is a natural follow-up
  once D1 exists (resolve RHS variables against the same env). Defer to a later
  change unless trivially free.
- Should a resolved relative path (`./x`) be normalised, or matched verbatim
  against rules? Likely verbatim (matches the existing literal-first-word path);
  confirm against current command-name matching.
