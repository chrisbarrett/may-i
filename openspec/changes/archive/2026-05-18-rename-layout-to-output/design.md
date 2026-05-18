## Context

`crates/layout` provides the `Layout` ADT, `Terminal` width detection,
combinators (`HRule`, `Columns`, `Stack`, `Note`), `Advisory`, and
`write_layout`. Every caller is in this workspace: `src/output/*` and
`src/trust/*` (8 files importing `may_i_layout`). The
[output-rendering](../../specs/output-rendering/spec.md) spec already
treats these primitives as `may-i`'s rendering substrate, fronted by the
`crate::output` module.

The crate name predates the output-rendering spec and the
`relocate-advisory-builders` change (archived 2026-05-11) that pulled
advisory shapes into it. Today the name no longer matches the contents.

## Goals / Non-Goals

**Goals:**

- Cargo package name, directory name, and Rust extern crate name all
  reflect that this crate is `may-i`'s output renderer, not a generic
  text-layout library.
- No behavioural change. No public-type rename. No spec-requirement
  change.

**Non-Goals:**

- Carving generic primitives (`Layout`, `Terminal`, `write_layout`) into
  a separate `text-layout` crate. That was the "expensive" option in the
  candidate proposal; not pursued here.
- Renaming individual types inside the crate (e.g., `Layout` →
  `OutputLayout`). The spec pins these names; touching them is out of
  scope.
- Changing the `crate::output` public surface defined by
  [output-rendering](../../specs/output-rendering/spec.md).

## Decisions

### Rename target: `may-i-output`

Chosen because the existing user-facing wrapper module is `src/output/`
(`crate::output`), and the
[output-rendering](../../specs/output-rendering/spec.md) spec already
uses the noun "output" for this concern. The Rust extern name becomes
`may_i_output`, matching `may_i_pp`, `may_i_engine`, `may_i_config`,
`may_i_core` style.

**Alternative considered: `may-i-render`** — accurate but introduces a
new noun ("render") not used in any spec; would invite drift from the
established "output" vocabulary. Rejected.

**Alternative considered: keep `may-i-layout`, rename only inside docs**
— rejected because the misleading name lives in `Cargo.toml`, every
`use` statement, and `cargo tree` output. Documentation-only fixes don't
remove the friction.

### Rename mechanism: directory move + package rename + import rewrite

One atomic change touching:

1. `crates/layout/` → `crates/may-i-output/` (`git mv`).
2. `crates/may-i-output/Cargo.toml`: `name = "may-i-output"`.
3. Workspace `Cargo.toml`: dependency entry
   `may-i-output = { path = "crates/may-i-output" }`, replacing the
   `may-i-layout` line.
4. Rust import sites: `fastmod 'may_i_layout' 'may_i_output' src/`.

**Alternative considered: keep `crates/layout/` directory, change only
the Cargo `name`** — Cargo permits a package name decoupled from its
directory, but readers navigating `crates/` would still see `layout`
and conclude the crate is generic. Inconsistent on disk vs. in
manifests. Rejected.

**Alternative considered: use Cargo `[lib] name = "may_i_output"`
while leaving the package name as `may-i-layout`** — solves the import
ergonomics but leaves `cargo tree`, `Cargo.lock`, and the directory
misleading. Half-measure. Rejected.

### Archived-change references stay as-is

References to `may-i-layout` inside `openspec/changes/archive/*` are
historical and SHALL NOT be rewritten. Archived changes are an
immutable record of past decisions; rewriting them would falsify the
history.

## Risks / Trade-offs

- **[Risk]** A stray `may_i_layout` reference survives the rewrite →
  build breaks at compile time, no silent regression possible.
  **Mitigation:** `cargo build` after the `fastmod` pass; `rg
  may_i_layout src/ crates/` returns no hits.

- **[Risk]** Insta snapshot directory `crates/layout/src/snapshots/`
  moves with the `git mv`; snapshot file paths inside the directory are
  unchanged. **Mitigation:** `cargo test -p may-i-output` after the
  move confirms snapshots resolve.

- **[Risk]** `Cargo.lock` churn includes the rename. **Mitigation:**
  expected; commit the regenerated lockfile.

- **[Risk]** Pre-commit hook `cargo fmt` (per CLAUDE.md) flags formatting
  in any touched file. **Mitigation:** run `cargo fmt` before staging.

## Migration Plan

Single commit. No user-facing migration (no config syntax change, no
trust-hash change, no DSL change). No `may-i migrate` step.
