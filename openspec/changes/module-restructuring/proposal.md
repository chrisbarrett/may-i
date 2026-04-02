## Why

12 source files exceed 800 lines (up to 3973), making navigation difficult and
obscuring module boundaries. Large files conflate multiple responsibilities —
types, algorithms, rendering, and tests — behind a single flat namespace, so
there is no compiler-enforced encapsulation of internal details. Splitting them
into focused modules improves readability, tightens visibility (`pub(super)` /
`pub(crate)`), and makes the stable public API of each crate explicit.

## What Changes

- Split `shell-parser` `tests.rs` (3973 lines) into per-topic test files;
  decompose `lexer.rs` and `ast.rs` into submodule directories.
- Split `engine` `eval.rs` (2640 lines) into `eval/` subtree by concern
  (context, evaluator, effects, positional matching, args, details); extract
  test suites from `test_generators.rs` into `tests/`.
- Split `sexpr` `cst.rs` (2207 lines) into `cst/` with parser, pretty-printer,
  and rewrite engine as separate modules; rename `span.rs` → `error.rs`.
- Split `pp` `lib.rs` (1890 lines) into `format.rs`, `color.rs`, `output.rs`,
  `render.rs` + test directory.
- Split `config` `migrate.rs` (1645 lines) into `migrate/` (rules / driver /
  analysis); split `resolve.rs` into `resolve/`; move parsers under `parser/`.
- Split `core` `ast.rs` (912 lines) into `ast/` (spanned, effect, predicate,
  config).
- Split binary crate `annotation.rs` (1352 lines) into `trace/` (types,
  doc-builders, fold); split `output/transform.rs` into `reduce.rs` +
  `distribute.rs`.

No public API surfaces change. All re-exports are preserved via `mod.rs` /
`lib.rs` facades.

## Capabilities

### New Capabilities

- `module-structure`: Defines the target module layout for all crates, the
  naming conventions for submodules, and the visibility rules
  (`pub` / `pub(super)` / `pub(crate)`) that enforce encapsulation.

### Modified Capabilities

(none — this is a purely internal restructuring with no behavioural changes)

## Impact

- **All 7 crates/packages** in the workspace are affected (shell-parser, engine,
  sexpr, pp, config, core, binary crate).
- **No API changes** — downstream `use` paths are preserved via re-exports.
- **No behavioural changes** — all existing tests pass without modification
  (they move files, not logic).
- **Build graph** — no new crate dependencies; module-internal `use` paths
  change but cross-crate imports are stable.
