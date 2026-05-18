## Context

`crates/engine/src/eval/mod.rs` currently `pub use`s 14 items from its submodules. A grep across the workspace (`src/`, `crates/`, `tests/`) shows seven of those have no consumer outside the engine crate:

- `BindingValue` — referenced only in `crates/engine/src/eval/{command,effects,bindings,mod}.rs`.
- `Bindings` — no external callers.
- `parse_argv` — no external callers.
- `EvalUnit`, `decompose` — referenced externally only via `crates/shell-parser/src/ast/word.rs` (within the workspace but transitively engine-internal in terms of public seam) and one integration test that goes through `evaluate_command` instead.
- `parser_positional_args` — only `crates/engine/src/eval/{effects,entry,predicates,bindings,test_generators/*}.rs`.
- `tokenise` — no external callers.

`PredicateResult` is referenced from `src/annotation.rs` (CLI binary). `Evaluator`, `EvalContext`, and the `evaluate*` family are referenced from integration tests and the CLI.

## Goals / Non-Goals

**Goals:**
- Reduce the engine crate's public seam to items that have at least one external caller.
- Make future restructuring of `bindings`, `decompose`, and tokenisation a non-breaking change.
- Encode the narrowed surface as a `code-quality` requirement so re-widening is a deliberate choice with spec backing.

**Non-Goals:**
- Renaming or restructuring the internals. This is a visibility-only change.
- Changing `EvalResult` or `SegmentDecision` (those live in `crates/engine/src/lib.rs` and have legitimate external users).
- Changing the contributor-internals types (`Effect`, `Predicate`, etc.) — that's a separate concern owned by the config crate.

## Decisions

### Demote rather than delete

Each unused re-export is still needed *within* the engine crate. The minimal change is `pub use … → pub(crate) use …` in `eval/mod.rs`. Alternative considered: physically remove the re-exports and have engine-internal callers go through the submodule path. Rejected: forces churn at every internal call site for no public-API benefit.

### Anchor the rule in `code-quality`, not a new spec

`code-quality` already collects contributor-only invariants (unwrap bans, rewrite-convergence bounds). Adding one more requirement keeps cross-cutting hygiene in a single spec. Alternative considered: a new `crate-surfaces` capability. Rejected: would also need to absorb the upcoming `narrow-config-parser-surface` and `output-pipeline-as-builder` changes; deferred until there is enough material to justify a spec of its own.

### Verification by grep + `cargo check`

The narrowed surface is verifiable by `cargo check --workspace`. If a hidden consumer exists, the compiler reports it immediately. No runtime behaviour changes — no new tests required for the visibility change itself.

## Risks / Trade-offs

- **Risk**: A consumer added between proposal and apply uses one of the demoted items. → **Mitigation**: `cargo check --workspace` after the edit; the change is reversible per-item.
- **Trade-off**: Engine-internal tests reaching for `decompose` or `parse_argv` keep working because they live inside the crate. External integration tests that wanted to poke internals must go through the supported `Evaluator` API. This is the intended deepening — internal experiments should not become public contracts by accident.
