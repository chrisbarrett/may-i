## Context

The workspace has 7 packages. 12 source files exceed 800 lines because multiple
concerns (types, algorithms, rendering, tests) accumulated in single files over
time. No public API changes are needed — the problem is purely internal
organisation and lack of compiler-enforced visibility boundaries.

## Goals / Non-Goals

**Goals:**

- Every production source file under ~600 lines
- Each module owns one cohesive concern
- Internal helpers hidden behind `pub(super)` or `pub(crate)` where possible
- All existing `use` paths from other crates remain valid via re-exports
- All tests continue to pass with no logic changes

**Non-Goals:**

- Changing any public API surface
- Introducing new crates or workspace members
- Refactoring algorithms or control flow
- Improving test coverage (beyond moving tests to better locations)

## Decisions

### 1. Submodule directories over flat files

Large files become directories (`eval/`, `cst/`, `ast/`, `migrate/`, `resolve/`,
`trace/`, `lexer/`) with a `mod.rs` that re-exports public items. This gives
each sub-concern its own file while keeping the parent module's import path
stable.

**Alternative considered:** Keeping flat files and using `#[doc(hidden)]` or
naming conventions for internal items. Rejected because it provides no
compiler-enforced encapsulation — `pub` items remain callable from anywhere in
the crate.

### 2. Re-export facades preserve API stability

Each `mod.rs` / `lib.rs` re-exports every previously-public symbol at its
original path. Cross-crate callers see no change.

### 3. Tests co-locate with their subject where small; move to `tests/` where large

Inline `#[cfg(test)] mod tests` stays when tests are <300 lines and tightly
coupled to one module. Large test suites (shell-parser's 4k-line `tests.rs`,
engine's embedded prop-test modules) move to dedicated test files grouped by
topic.

### 4. Visibility tightening as the primary encapsulation gain

The main benefit is not smaller files per se, but the ability to mark helpers as
`pub(super)` — visible within a submodule directory but invisible outside it.
Key examples:

- `config::parser::parse_expr` → `pub(super)` (only used by sibling parsers)
- `trace::doc_builders::*` → `pub(super)` (only used by TracingFold)
- `engine::eval::details::*` → `pub(crate)` (only used within the engine crate)
- `pp::render::render_flat` etc. → private (only called by `pretty`)

### 5. Process: one crate at a time, independent commits

Each crate's restructuring is a self-contained commit. Order chosen to minimise
cross-crate churn — leaf crates first (core, sexpr, pp, shell-parser), then
dependents (config, engine), then the binary crate last.

## Risks / Trade-offs

- **Risk: Merge conflicts with in-flight work** → Mitigation: Each crate is one
  atomic commit; rebase is straightforward since no logic changes.
- **Risk: IDE "go to definition" temporarily broken during transition** →
  Mitigation: `cargo check` after each commit confirms all paths resolve.
- **Trade-off: More files to navigate** → Accepted; focused files with clear
  names are easier to find than scrolling a 2k-line file. Module tree is at most
  2 levels deep.
- **Trade-off: `pattern.rs` (964 lines) stays intact in config crate** →
  Accepted; it gains encapsulation (`parse_expr` becomes `pub(super)`) from
  moving under `parser/` without needing an internal split.
