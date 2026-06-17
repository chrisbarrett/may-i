## Context

`may-i` already handles function definitions well: the parser produces
`Command::FunctionDef { name, body }` for both `name() { … }` and `function
name { … }`, `FunctionDef::children()` returns the body, and
`extract_simple_commands` recurses through `children()`, so the commands inside
a body are decomposed and authorised. Confirmed by running the engine: the `rm`
in `cleanup() { rm -rf "$wt"; }` asks.

The gap is the **call site**. `decompose` flattens the AST to simple commands
with no notion of which names the script itself defined, so
`materialise "$BASE"` decomposes to a `SimpleCommand { command: "materialise" }`
and the engine reports `No rule for command `materialise`` → ask. In a script
that defines three functions and calls each (sometimes from inside another
body), every call asks, drowning the real signal.

## Goals / Non-Goals

**Goals:**

- A call to a function the same command defines, **when that function is live at
  the call site**, is internal: `:allow`, never `No rule for command …`, and
  visible as such in the trace.
- Function bodies stay authorised exactly as today.
- A bounded, **sound** liveness analysis: never classify a call internal unless
  the function is provably live there (a false-internal is a security bypass — an
  ungated external runs). No argument binding, no interprocedural call-graph.

**Non-Goals:**

- Connecting call-site arguments to body parameters (`$1`, `$@`). Bodies are
  authorised as written, with their own dynamic-ness.
- Path-sensitive analysis of conditional definitions and full interprocedural
  call-graph precision. Conservatively approximated to `:ask` — see D2.
- Dynamic command names (`"$TGBIN" stack generate`) and the `done < <(…)`
  brace-group parse warning observed in the same scripts. Separate concerns.

## Decisions

### D1 — A `LocalFunctionCall` eval unit, classified in `decompose`

Add a collector to `crates/shell-parser` that returns the set of `FunctionDef`
names in a parsed command (sibling to `extract_simple_commands`). A liveness
classifier (D2) consumes it and decides, per call site, whether the call is a
**live** local-function call; `decompose` emits `EvalUnit::LocalFunctionCall {
name, span }` for those (keyed by the simple command's span) instead of
`EvalUnit::SimpleCommand`. `command.rs` evaluates that unit as `:allow` with a
traceable reason (e.g. *"internal call to script-local function `materialise` —
body authorised at its definition"*); it contributes nothing to the aggregate
(never raises the decision, fills the reason only as a last resort).

- *Why a distinct unit over silently dropping the call:* the trace and the audit
  log should explain why a call did not ask. A dedicated unit renders an
  intelligible line; dropping it would look like a coverage hole.
- Embedded substitutions in the call's arguments are still extracted and
  evaluated (a `local_fn "$(rm -rf /)"` argument must not escape) — only the
  command-name classification changes.

### D2 — Liveness-aware recognition (revises the original set-based choice)

A call is classified internal only when the named function is **provably live**
at that call site. The analysis is a small abstract interpreter over the parsed
command, in two tiers — because bash executes top-level statements **in order**
but runs a function body only when the function is *called*:

- **Tier 1 — top-level calls (order-sensitive).** Walk the top-level spine
  (`;` `&&` `||` `|` `&`) left to right maintaining a `live` set: a top-level
  `name() { … }` adds `name`; a statically-resolved `unset -f name` removes it.
  A top-level call is internal iff its resolved name is in `live` at that point.
- **Tier 2 — body calls (establishment-based).** A call inside a function body
  is internal iff its name is defined unconditionally at top level *before the
  activation point* and never unset. The **activation point** is the source
  position of the earliest top-level call to any defined-function name; every
  body runs at or after it, so functions established before it are guaranteed
  live inside any body. This keeps **mutual recursion** and
  **helper-defined-below** working while refusing the
  forward-reference-invoked-before-definition case.

Direction of safety: a false *internal* is a bypass (an ungated external runs); a
false *external* is only a spurious `:ask`. So the analysis is **conservative** —
anything it cannot prove live falls back to the external/ask path:

- definitions inside `if`/`while`/`case`/subshell/brace-group do not establish
  internal status (conditionally reached / scoped);
- a dynamic `unset -f "$x"` clears the whole live set (could remove anything);
- a dynamic call head (`"$f"`) is never matched (already `DynamicCommand`).

This closes the bypasses the original set-based rule accepted:
`rm -rf /; rm(){ :; }` (Tier 1: `rm` not yet live → ask),
`rm(){ :; }; unset -f rm; rm -rf /` (Tier 1: unset removed `rm` → ask), and the
narrow body residual `g(){ f; }; g; f(){ … }` (Tier 2: `f` defined after the
activation point → not established → ask).

True interprocedural precision (every invocation site of every function) is not
attempted; the activation-point approximation is sound and covers the realistic
"define a cluster, then call it" shape.

Implementation: the classifier returns the set of simple-command **spans** that
are live internal calls; `decompose` consults it. A shared `resolved_command_name`
helper keeps the classifier and the `SimpleCommand`/`LocalFunctionCall`
branch in agreement on name resolution (including `$BIN` constant resolution).

## Risks / Trade-offs

- **Shadowing a live function over a real command** (`git() { … }; git push`) →
  the call is internal and skips any `git` rule. This is **runtime-correct** bash
  shadowing: the function is live, so the body is what actually runs, and the
  body is authorised. Accepted; noted in the spec/trace.
- **Conservative spurious asks** → a function defined only inside a conditional,
  or called before it is provably live, asks instead of resolving internal. Safe
  by construction (false-external), and rare in agent-generated scripts.
- **Name resolution on dynamic call heads** → only non-dynamic first words are
  classified; `"$f" args` stays a dynamic command and asks as today.

## Open Questions

- Should the `LocalFunctionCall` reason name the definition site (span/line) for
  the trace? Nice for forensics; defer unless cheap with the existing span data.
