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

- A call to a function the same command defines is internal: `:allow`, never
  `No rule for command …`, and visible as such in the trace.
- Function bodies stay authorised exactly as today.
- Zero new analysis burden: no dataflow, no argument binding, no call-graph.

**Non-Goals:**

- Connecting call-site arguments to body parameters (`$1`, `$@`). Bodies are
  authorised as written, with their own dynamic-ness.
- Control-flow analysis of definition order (conditional defs, `unset -f`,
  redefinition). Out of scope — see D2.
- Dynamic command names (`"$TGBIN" stack generate`) and the `done < <(…)`
  brace-group parse warning observed in the same scripts. Separate concerns.

## Decisions

### D1 — A `LocalFunctionCall` eval unit, classified in `decompose`

Add a collector to `crates/shell-parser` that returns the set of `FunctionDef`
names in a parsed command (sibling to `extract_simple_commands`). In
`decompose`, thread that set in; when a simple command's resolved (non-dynamic)
first word is in the set, emit `EvalUnit::LocalFunctionCall { name, span }`
instead of `EvalUnit::SimpleCommand`. `command.rs` evaluates that unit as
`:allow` with a traceable reason (e.g. *"internal call to script-local function
`materialise` — body authorised at its definition"*); it contributes nothing to
the aggregate.

- *Why a distinct unit over silently dropping the call:* the trace and the
  forthcoming audit log should explain why a call did not ask. A dedicated unit
  renders an intelligible line; dropping it would look like a coverage hole.
- Embedded substitutions in the call's arguments are still extracted and
  evaluated (a `local_fn "$(rm -rf /)"` argument must not escape) — only the
  command-name resolution changes.

### D2 — Set-based recognition, order-insensitive (P1)

A name defined as a function *anywhere* in the command makes all calls to it
internal. The alternative — source-order precedence (a call is internal only if
a definition appears textually before it) — was rejected:

- Bodies routinely **forward-reference** sibling functions; at runtime every
  top-level definition has executed before any function is called, so a body
  calling a sibling defined later is correct. Source-order would false-ask on
  exactly the mutual-recursion / helper-defined-below patterns this change
  exists to fix.
- The only case set-based gets "wrong" is a call that precedes its definition
  *and* shadows a real command — exotic, and bounded because the body is
  authorised regardless. Documented as accepted imprecision.

True flow analysis (conditional definitions, `unset -f`) is effectively
undecidable cheaply and buys nothing for agent-generated scripts; explicitly not
attempted.

## Risks / Trade-offs

- **Shadowing a real command** (`git() { … }; git push`) → the call is now
  internal and skips any `git` rule. Bounded: the wrapper body is authorised, so
  whatever it actually runs is still gated. Acceptable; note in the spec/trace.
- **Pre-definition call to a name that is also an external program** → treated as
  internal, external not gated. Exotic; accepted per D2.
- **Name resolution on dynamic call heads** → only non-dynamic first words are
  matched against the set; `"$f" args` stays a dynamic command and asks as today.

## Open Questions

- Should the `LocalFunctionCall` reason name the definition site (span/line) for
  the trace? Nice for forensics; defer unless cheap with the existing span data.
