## Why

The env-write floor keys on the wrong thing. It fires for every assignment that
lands in a simple command's assignment list — which, by an artifact of parsing,
includes a declaration builtin's array argument (`declare -A m=([k]=v)`) but not
its scalar argument (`declare FOO=bar`), and not an exported scalar
(`export LD_PRELOAD=/evil.so`). The result is simultaneously **too tight** —
a shell-local array declaration floors to `:ask` though it never crosses a
process boundary — and **too loose**: `export LD_PRELOAD=/evil.so; cmd` is
`:allow` because the export is invisible to per-segment evaluation, even though
every later command inherits it. The spec itself only ever described the
*command-prefix* case, so the array over-block is already a spec violation and
the `export`/`declare -x` under-block is an unspecified hole.

The correct discriminator is **whether the write reaches a child process**, not
the syntactic shape of the assignment. A shell variable is inert; risk attaches
at the process boundary. Deciding "reaches a child" for a bare reassignment of an
already-exported name (`PATH=/evil`) requires knowing the inherited environment —
which `may-i` runs inside and can capture, but only as a first-class,
testable input rather than ambient state it silently sniffs.

## What Changes

- **Reframe the env-write floor from "command prefix" to "write that reaches a
  child process."** A write reaches a child when it is a command prefix
  (`NAME=v cmd`), an `export NAME[=v]` / `declare -x` / `typeset -x` /
  `readonly -x`, a bare reassignment of a name already in the entry environment
  (re-export), or any assignment while `set -a` / `set -o allexport` is active.
  A purely shell-local write — a bare assignment to a name *not* in the entry
  environment, a `declare`/`local`/`readonly` without `-x`, an array literal —
  SHALL NOT floor. **BREAKING** for configs that relied on shell-local
  assignments flooring (e.g. expecting `declare -A m=…` to `:ask`).
- **Introduce the *entry environment*** — a new first-class evaluation input: an
  immutable, **names-only** snapshot of the exported environment at the start of
  the invocation. It carries no values, so it can never leak a secret into a
  trace, audit record, or error message. It is *not* a fact: facts are asserted
  policy context consumed by `(fact? …)`; the entry environment is observed
  ground truth consumed structurally by the write-floor.
- **Capture per invocation mode.** `may-i hook` SHALL capture the snapshot as
  its first action, before any internal environment mutation. `may-i eval` SHALL
  default to an empty snapshot, accept `--env NAME` (repeatable) to construct a
  hypothetical one, and accept `--inherit-env` to capture the real process
  environment for reproducing a live hook decision. `may-i check` SHALL remain
  hermetic: it never reads the process environment and uses only what a check
  case declares.
- **Simulate the entry environment in check cases** via `(with-env [NAME …] …)`,
  mirroring `(with-facts …)` and nesting the same way.
- **Emit a scope predicate** `(scope …)` usable inside an `(env …)` decision so
  policy can branch on `prefix` / `export` / `bare` / `reaches-child`.
- **Attribute entry-environment influence in traces** so a decision tipped by
  "`PATH` ∈ entry environment ⇒ reaches a child" is explainable.
- **Advise** when a config has scope-dependent env rules but no check case
  declares an entry environment — the hermetic default (empty) under-tests
  exactly the always-exported dangerous names (`PATH`, `LD_*`).

## Capabilities

### New Capabilities

<!-- none — the entry environment is runtime context per invocation, so it
     belongs to the existing `facts` layer/bucket, not a new capability. -->

### Modified Capabilities

- `facts`: add the **entry environment** — a names-only, immutable snapshot of
  the exported environment, sourced per invocation mode (hook captures live;
  eval injects via `--env` / `--inherit-env`; check is hermetic) — as a distinct
  kind of runtime context, NOT exposed through `(fact? …)`.
- `shell-command-security-model`: reframe the env-write floor requirement from
  the command-prefix case to "a write that reaches a child process," enumerating
  the reaching forms and the exempt shell-local forms; add the `(scope …)`
  predicate for env decisions; add scenarios for export/`declare -x` flooring,
  bare-reassignment-of-entry-env flooring, and shell-local exemption.
- `testing-strategy`: add the `(with-env [NAME …] …)` check-case wrapper
  (mirroring `(with-facts …)`) and the advisory for scope-dependent env rules
  with no entry-environment coverage.
- `traces`: a decision contributed by the entry environment SHALL render the
  consulted name and its presence (never a value).

## Impact

- `crates/engine/src/eval/decompose.rs` — stop emitting an `EnvPrefix` unit for
  every assignment; classify assignment scope and emit the floor only for
  reaching writes, consulting the entry environment for the bare-reassignment
  case.
- `crates/shell-parser/src/parse.rs` / `ast` — surface assignment scope
  (prefix vs declaration-builtin arg, exported vs shell-local, `set -a` state).
- New entry-environment input threaded through the engine alongside
  `ContextFacts`; captured in `src/cmd_hook.rs`, injected in `src/cmd_eval.rs`,
  held empty/declared in `crates/engine/src/check.rs`.
- `src/main.rs` — `--env` / `--inherit-env` flags on `eval`.
- Config check DSL — `(with-env …)` form parsing.
- Trace rendering — entry-environment contribution line.
- Advisory surface — untested-scope-rule notice.
