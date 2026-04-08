## Requirements

### Requirement: Maximum file size

Every production (non-test) `.rs` source file SHALL be at most 600 lines. Test
files SHALL be at most 1200 lines.

#### Scenario: No oversized production files

- **WHEN** `find crates/ src/ -name '*.rs' -not -path '*/tests/*'` is run and
  line counts computed
- **THEN** no file exceeds 600 lines

#### Scenario: No oversized test files

- **WHEN** test files under `tests/` directories or `#[cfg(test)]` module files
  are measured
- **THEN** no file exceeds 1200 lines

### Requirement: Single-concern modules

Each source file SHALL contain one cohesive concern: either type definitions, or
an algorithm, or rendering logic, or test cases — not a mixture.

#### Scenario: Type definitions are separate from algorithms

- **WHEN** a module directory (e.g. `eval/`, `cst/`) is examined
- **THEN** type/struct definitions live in dedicated files (e.g. `context.rs`,
  `types.rs`) separate from algorithmic logic (e.g. `effects.rs`, `parser.rs`)

### Requirement: Submodule directory structure

When a file exceeds the size limit or conflates multiple concerns, it SHALL be
decomposed into a submodule directory with a `mod.rs` that re-exports all
previously-public symbols.

#### Scenario: eval.rs becomes eval/ directory

- **WHEN** `crates/engine/src/eval/` exists
- **THEN** `eval/mod.rs` re-exports `EvalContext`, `Evaluator`, `evaluate`,
  `evaluate_with_fold`, `PredicateResult` at the same paths as before

#### Scenario: cst.rs becomes cst/ directory

- **WHEN** `crates/sexpr/src/cst/` exists
- **THEN** `cst/mod.rs` re-exports `CstNode`, `Shape`, `ShapeF`, `TriviaAnn`,
  `Trivia`, `RewriteRule`, `rewrite_until_convergence` at the same paths

#### Scenario: annotation.rs becomes trace/ directory

- **WHEN** `src/trace/` exists
- **THEN** `trace/mod.rs` re-exports `Ann`, `TraceEntry`, `TracingFold` and all
  prior import paths from `crate::annotation` are updated to `crate::trace`

### Requirement: Visibility tightening

Internal helper functions that are only used within a submodule directory SHALL
use `pub(super)` visibility. Functions only used within the same crate SHALL use
`pub(crate)`.

#### Scenario: Parser-internal helpers are pub(super)

- **WHEN** `crates/config/src/parser/pattern.rs` contains `parse_expr`
- **THEN** `parse_expr` is declared `pub(super)`, not `pub` or `pub(crate)`

#### Scenario: Doc builders are pub(super)

- **WHEN** `src/trace/doc_builders.rs` contains annotation-building helpers
- **THEN** all functions in that module are `pub(super)`, callable only from
  within the `trace/` directory

#### Scenario: Render internals are private

- **WHEN** `crates/pp/src/render.rs` contains `render_flat`, `render_broken`,
  etc.
- **THEN** those functions are private (`fn`, no `pub` qualifier), with only
  `pretty`, `pretty_into`, and `visible_len` being `pub`

### Requirement: API stability via re-exports

All symbols that are currently importable from other crates SHALL remain
importable at the same path after restructuring. `lib.rs` and `mod.rs` files
SHALL contain re-exports that preserve backward compatibility.

#### Scenario: Cross-crate imports unchanged

- **WHEN** `cargo check` is run on the full workspace after restructuring a
  crate
- **THEN** compilation succeeds with no import-path errors in any dependent
  crate

#### Scenario: Engine crate public API preserved

- **WHEN** the engine crate's `eval/` restructuring is complete
- **THEN** `may_i_engine::evaluate`, `may_i_engine::EvalContext`,
  `may_i_engine::fold::EvalFold` etc. resolve to the same types as before

### Requirement: Test dissolution for monolith test files

Test files exceeding 1200 lines SHALL be split into per-topic files under a
`tests/` directory within the crate's `src/`.

#### Scenario: shell-parser tests.rs dissolved

- **WHEN** `crates/shell-parser/src/tests.rs` (3973 lines) is restructured
- **THEN** it is replaced by multiple files under `tests/` grouped by topic
  (parsing, word methods, redirections, expansions, globs, resolution, helpers)

#### Scenario: engine test_generators.rs test modules extracted

- **WHEN** `crates/engine/src/test_generators.rs` is restructured
- **THEN** the `#[cfg(test)]` inner modules move to `tests/` files, and
  `test_generators.rs` retains only the proptest generators

### Requirement: Crate processing order

Crates SHALL be restructured in dependency order — leaf crates first, dependents
after — so each commit leaves the workspace in a compilable state.

#### Scenario: Leaf crates before dependents

- **WHEN** the restructuring is applied as a series of commits
- **THEN** the order is: core, sexpr, pp, shell-parser, config, engine, binary
  crate — and `cargo check` passes after each commit

### Requirement: pp crate submodule structure

When `crates/pp/src/lib.rs` exceeds the file size limit, it SHALL be decomposed
into a submodule directory. `lib.rs` SHALL re-export all previously-public
symbols.

#### Scenario: pp lib.rs split into submodules

- **WHEN** `crates/pp/src/` is examined after restructuring
- **THEN** the directory contains `lib.rs`, `output.rs`, `render.rs`,
  `buffer.rs`, and `color.rs`
- **THEN** no production file exceeds 600 lines

#### Scenario: pp public API preserved

- **WHEN** `cargo check` is run on the full workspace after pp restructuring
- **THEN** compilation succeeds with no import-path errors
- **THEN** `may_i_pp::pretty`, `may_i_pp::pretty_into`, `may_i_pp::Format`,
  `may_i_pp::PrettyOutput`, and `may_i_pp::visible_len` resolve to the same
  types as before

#### Scenario: pp test modules extracted

- **WHEN** `crates/pp/src/` is examined
- **THEN** `#[cfg(test)]` blocks from the original `lib.rs` live in dedicated
  test files, not inline in production modules

### Requirement: eval submodule directory

When `crates/engine/src/eval.rs` exceeds the file size limit, it SHALL be
decomposed into an `eval/` directory. `eval/mod.rs` SHALL re-export all
previously-public symbols.

#### Scenario: eval.rs split into submodules

- **WHEN** `crates/engine/src/eval/` is examined after restructuring
- **THEN** the directory contains `mod.rs`, `context.rs`, `entry.rs`,
  `predicates.rs`, `positional.rs`, and `effects.rs`
- **THEN** no production file exceeds 600 lines

#### Scenario: eval public API preserved

- **WHEN** `cargo check` is run on the full workspace after eval restructuring
- **THEN** compilation succeeds with no import-path errors
- **THEN** `may_i_engine::evaluate`, `may_i_engine::evaluate_with_fold`,
  `may_i_engine::EvalContext`, and `may_i_engine::EvalError` resolve to the same
  types as before

#### Scenario: eval test modules extracted

- **WHEN** `crates/engine/src/eval/` is examined
- **THEN** `#[cfg(test)]` blocks from the original `eval.rs` live in dedicated
  test files under `eval/tests/`, not inline in production modules

### Requirement: test_generators test extraction

The test modules in `crates/engine/src/test_generators.rs` SHALL be extracted
into separate files, leaving only the proptest generator functions in
`test_generators.rs`.

#### Scenario: generators file reduced to generators only

- **WHEN** `crates/engine/src/test_generators.rs` is examined after restructuring
- **THEN** it contains only proptest strategy functions and `pub use` re-exports
- **THEN** it does not exceed 600 lines

#### Scenario: extracted test modules compile and pass

- **WHEN** `cargo test -p may-i-engine` is run after extraction
- **THEN** all property tests that previously lived in `test_generators.rs` pass
