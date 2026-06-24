## Context

`may-i` recognises script-local function calls via a liveness analysis:
`live_local_call_spans` (`crates/engine/src/eval/decompose.rs:786`) walks the
outer AST and returns the spans of simple commands that are **live** internal
calls; `decompose` emits `EvalUnit::LocalFunctionCall` for those, and
`command.rs` resolves them to `:allow`. The analysis is two-tier (design D2 of
the original `recognise-local-function-calls` change): Tier 1 is order-sensitive
along the top-level spine; Tier 2 uses the establishment set fixed at the
activation point for calls inside function bodies and conditionally-reached
regions.

The gap is the **command-substitution boundary**. A `$(…)` / backtick / process
substitution is extracted by `decompose` as `EvalUnit::EmbeddedCommand { source,
span, kind }` and re-evaluated by `command.rs:304` via `eval_units(source, …)`.
That call re-parses `source` from scratch — for `dest=$(resolve)`, `source` is
literally `"resolve"`, with none of the outer script's function definitions. So
the inner `live_local_call_spans` sees an empty defs set, `resolve` classifies
as an unknown external, and the engine reports `No rule for command `resolve``.

Confirmed: the unit loop in `command.rs:287` never early-aborts (it aggregates
strictest-wins over every unit to build the full trace and per-segment
decisions), and `parse_result` — holding the outer AST — stays resident for the
whole of `eval_units`. So there is no run-time saving available from deferring
the liveness computation.

## Goals / Non-Goals

**Goals:**

- A call to a script-local function inside a substitution is internal whenever
  the same call would be internal as a bare command at the substitution's site.
- Soundness preserved: never classify a substitution call internal unless the
  function is provably live at that site (a false-internal runs an ungated
  external).
- Nested substitutions (`$(f $(g))`) recognise functions at every depth.
- Default behaviour (empty inherited set) is byte-for-byte today's behaviour.

**Non-Goals:**

- Modelling subshell-local mutation that does not affect classification — a
  subshell's `unset -f` does not propagate to the parent, but classification is
  decided at subshell *entry* against the inherited table, so it does not change
  the recognition decision.
- Connecting substitution output to its consumer (`dest=$(resolve)` leaves the
  value of `dest` unknown; a later use of `$dest` as a command is already a
  dynamic command). Unchanged.
- The substitution-origin label defect (`outer_command_name`). Separate change.

## Decisions

### D1 — Inherited live-name set carried on `EmbeddedCommand`, computed eagerly

Add `inherited_fns: HashSet<String>` to `EvalUnit::EmbeddedCommand`. `decompose`
gains an `inherited_fns` parameter (the names live at the *enclosing* scope's
entry; empty at the top level). For each substitution it emits, the carried set
is `inherited_fns ∪ established-at-the-substitution-span`, where the established
set is computed by the same liveness machinery `live_local_call_spans` uses.
`command.rs` passes the carried set through `eval_units` into the inner
`decompose`, which seeds its own liveness analysis with it.

**Why eager, not lazy.** Lazy recomputation would only pay off if authorisation
could abort before reaching a given embedded unit — it cannot (`command.rs:287`
visits every unit), and the outer AST is resident regardless (`command.rs:250`).
So lazy buys no performance and costs re-threading the outer AST down the
recursive eval seam. Eager keeps liveness colocated with the existing
`live_local_call_spans` call and travels with the unit as plain, testable data.

### D2 — Position-aware inheritance, not the global defs set

The inherited set is the functions live **at the substitution's byte offset**,
not the whole-script `defined_function_names` set. Command substitution inherits
the parent shell's *current* function table at the point it executes, so the
correct set is exactly what a bare call at that site would see. Using the global
set would reintroduce the false-internal hole the conservative design exists to
close: `x=$(resolve); resolve() { … }` runs the substitution *before* `resolve`
is defined, so the subshell calls an external `resolve` — a global set would
wrongly mark it internal and `:allow` it.

A substitution that sits inside a function body or a conditionally-reached region
inherits the Tier-2 establishment set, exactly as a bare call there would —
reusing `live_local_call_spans`' existing Spine/Deferred mode distinction rather
than inventing a second notion of liveness.

### D3 — Recursive propagation for nested substitutions

`x=$(outer $(inner))` nests subshells: the subshell for `$(inner)` inherits the
subshell for `$(outer …)`, which inherits the parent. So a function live at the
outer statement is live in both. The carried set composes by union at each level:
`inherited-for-children = received-inherited ∪ locally-live-here`. Because
`command.rs` already recurses through `eval_units` with `depth + 1`, threading
the inherited set through that call propagates it for free — no depth tracking,
no special-casing. Functions defined *inside* a substitution's own source are
picked up by that level's own `live_local_call_spans` and unioned forward to its
nested substitutions.

**Alternative rejected — cap at one level.** Recognising only top-level `$(…)`
would require detecting nesting depth and *suppressing* propagation: more code,
and it leaves `$(f $(g))` asking on `g` for no soundness gain. The recursive
union is both simpler and strictly more correct.

### D4 — Governing invariant: classification equivalence at the site

The correctness property is: *a function call inside a substitution gets the same
internal/external classification it would get as a bare call at the
substitution's site.* This is the spec clause and the test oracle simultaneously
— a metamorphic proptest reuses the already-specified-and-tested bare-call path
as ground truth instead of hand-asserting decisions per case. The equivalence is
about **recognition** (internal vs external, hence ask-or-not), not full bash
runtime semantics; classification is decided at subshell entry against the
inherited table, so a subshell-local `unset -f` does not break it.

### D5 — Soundness argument

Recognising the call as internal does not suppress analysis of what the function
does: the body is authorised at its definition site (the outer `FunctionDef` is
walked by the outer `decompose`), so a dangerous operation inside `resolve` is
already gated. The substitution call is pure dispatch — the same argument that
justifies the existing top-level `LocalFunctionCall`. Position-aware liveness
guarantees the inherited set never contains a name not provably live at the site,
so the change can only *remove* spurious asks, never add a missed gate.

## Risks / Trade-offs

- **Field on a security-sensitive enum.** `EvalUnit::EmbeddedCommand` gains a
  field threaded into the eval recursion. Mitigated: additive, default-empty
  reproduces current behaviour, and the metamorphic oracle pins equivalence to
  the bare-call path.
- **Liveness analysis now runs per embedded level.** Each nested substitution
  re-derives its established set during its own `decompose`. Bounded by the
  existing recursion limit (`DEFAULT_RECURSION_LIMIT`); no new unbounded work.

## Migration

None. The new field is on an internal AST type, not user config; rule hashing
and trust storage are untouched.

## Open Questions

<!-- none -->
