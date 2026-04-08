## Context

Three files exceed the 600-line module-structure spec limit by 3–5x:

| File | Lines | Concerns mixed |
|------|-------|----------------|
| `crates/pp/src/lib.rs` | 3242 | Output traits, rendering engine, format detection, colorization, 5 test blocks |
| `crates/engine/src/eval.rs` | 2911 | Entry points, predicate eval, positional matching, effect eval, tests |
| `crates/engine/src/test_generators.rs` | 1766 | 165 lines of generators + 1600 lines of inline tests |

All public API paths must be preserved — downstream crates and the binary import
from these modules.

## Goals / Non-Goals

**Goals:**
- Bring all three files under the module-structure spec limits (600 prod / 1200 test)
- Each new file has a single cohesive concern
- All existing `pub` imports continue to resolve at the same paths
- Workspace compiles and all tests pass after each file's restructuring

**Non-Goals:**
- Changing any logic or behaviour
- Restructuring other files that also exceed limits (e.g. `shell-parser/src/tests.rs`)
- Tightening visibility beyond what the module-structure spec requires for new submodules

## Decisions

### D1: pp crate — split lib.rs into submodule directory

`crates/pp/src/lib.rs` becomes `crates/pp/src/` with:

| File | Contents | Visibility |
|------|----------|------------|
| `lib.rs` | Re-exports, `Format`, `detect_column_width`, `INDENT_SPECS`, `FILL_ELIGIBLE_HEADS`, `indent_spec` | `pub` for external API; `pub(crate)` for crate-internal |
| `output.rs` | `PrettyOutput` trait, `OutputEvent` enum | `pub(crate)` (trait is crate-internal) |
| `render.rs` | `pretty`, `pretty_into`, `line_prefix_width`, and all recursive rendering logic (the bulk of lines 700–1466) | `pretty`/`pretty_into` are `pub`; internal fns are private |
| `buffer.rs` | `StringBuilder`, `EventBuffer`, `AnnotatedLine`, `AnnotatedLineBuilder` and their `PrettyOutput` impls | `pub(crate)` |
| `color.rs` | `colorize_atom`, `visible_len` | `pub(crate)` |
| `tests/` | All `#[cfg(test)]` blocks extracted into per-topic files | test-only |

**Rationale:** Grouping by concern (trait definition, rendering algorithm,
buffering, colorization) mirrors the natural reading order of the code. `lib.rs`
stays as the public facade.

### D2: engine eval — convert eval.rs to eval/ directory

`crates/engine/src/eval.rs` becomes `crates/engine/src/eval/`:

| File | Contents | Visibility |
|------|----------|------------|
| `mod.rs` | Re-exports of all currently-public symbols | `pub` |
| `context.rs` | `EvalContext`, `PredicateResult`, `DEFAULT_RECURSION_LIMIT` | `pub(crate)` for types used within engine |
| `entry.rs` | `evaluate`, `evaluate_with_fold`, `expand_combined_flags`, `positional_args`, `Evaluator` | `pub` for entry points; helpers `pub(super)` |
| `predicates.rs` | `evaluate_predicate`, `evaluate_predicate_fold` | `pub(super)` |
| `positional.rs` | `match_positional_patterns` and surrounding pattern-matching logic | `pub(super)` |
| `effects.rs` | `evaluate_effect`, `evaluate_effect_fold` | `pub(super)` |
| `tests/` | All `#[cfg(test)]` blocks | test-only |

**Rationale:** The eval module has four distinct algorithmic phases (predicate,
positional, effect, orchestration). Splitting along phase boundaries means each
file has a clear contract.

### D3: test_generators — extract test modules

`crates/engine/src/test_generators.rs` retains only the proptest strategy
functions (~165 lines). The `#[cfg(test)]` inner modules move to separate files
under `crates/engine/src/tests/`:

| Current module | New file |
|----------------|----------|
| `tests` (L189) | `tests/predicate_properties.rs` |
| `eval_property_tests` (L395) | `tests/eval_properties.rs` |
| `check_property_tests` (L942) | `tests/check_properties.rs` |
| `predicate_eval_properties` (L1098) | `tests/predicate_eval_properties.rs` |
| `evaluate_properties` (L1234) | `tests/evaluate_properties.rs` |
| `evaluator_properties` (L1438) | `tests/evaluator_properties.rs` |

An existing `tests/` test-module file or a new `tests.rs` with `mod` declarations
will wire them in.

**Rationale:** The generators are reusable infrastructure; the tests are consumers.
Separating them makes the generators easy to find and the tests easy to run
individually.

### D4: Processing order

Apply changes in this order:
1. `pp` crate (leaf — no in-workspace dependents use internal symbols)
2. `engine/eval.rs` (depends on core; depended on by binary)
3. `engine/test_generators.rs` (test-only, no downstream impact)

Each step is independently compilable and testable.

## Risks / Trade-offs

- **Merge conflicts** — Any in-flight branches touching these files will conflict.
  Mitigation: This is a pure restructuring with no logic changes, so conflicts
  are mechanical to resolve.
- **IDE navigation** — More files means more tabs. Mitigation: `mod.rs`
  re-exports keep the public API discoverable; `zat` outlines still work per-file.
- **Test module wiring** — Moving `#[cfg(test)]` blocks to separate files
  requires careful `mod` and `use` adjustments. Mitigation: `cargo test` after
  each move confirms nothing was lost.
