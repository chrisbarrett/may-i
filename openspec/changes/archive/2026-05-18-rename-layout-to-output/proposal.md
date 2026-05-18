## Why

The `may-i-layout` crate is named for what its primitives look like
(`Layout`, `Columns`, `HRule`) but its actual role is `may-i`'s trace and
advisory output renderer. The name implies a general-purpose text-layout
library; readers of the workspace are misled into thinking it's a reusable
dependency, and the [output-rendering](../../specs/output-rendering/spec.md)
spec already treats `crate::output` (which wraps it) as the rendering seam.
Rename the crate to make the role honest.

## What Changes

- Rename the workspace crate `crates/layout` → `crates/may-i-output` (Cargo
  package and directory).
- Rename the Rust extern crate `may_i_layout` → `may_i_output` at every
  import site in the workspace (workspace `Cargo.toml`, `src/output/*`,
  `src/trust/*`).
- Update archived-change references and any non-spec documentation that
  names the crate. Stable spec files describe types by name (`Layout`,
  `Terminal`, `ColRow`) and do not name the crate — no spec body changes
  required.
- **BREAKING** for any out-of-tree consumer of `may-i-layout` (none exist;
  pre-1.0, single workspace).

## Capabilities

### New Capabilities

_None._

### Modified Capabilities

- `code-quality`: adds a contributor-internals requirement that the
  workspace's output-rendering crate is named `may-i-output` (not
  `may-i-layout`). This pins the new name so a future readability sweep
  doesn't quietly revert it, and gives the rename a testable
  acceptance scenario.

The [output-rendering](../../specs/output-rendering/spec.md) requirements
constrain types by name (`Layout`, `Terminal`, `write_layout`) and the
`crate::output` surface, both of which are unaffected by this change.

## Impact

- **Code:** workspace `Cargo.toml`, `crates/layout/Cargo.toml`, every
  `use may_i_layout::…` in `src/output/*.rs` and `src/trust/*.rs`.
- **Snapshots:** `crates/layout/src/snapshots/` moves with the crate; insta
  snapshot names are unaffected (keyed on test path within the crate).
- **External consumers:** none.
- **Build/CI:** `cargo build`, `cargo test`, `cargo tarpaulin`, `prek` hooks
  all re-resolve against the new package name without configuration change.
