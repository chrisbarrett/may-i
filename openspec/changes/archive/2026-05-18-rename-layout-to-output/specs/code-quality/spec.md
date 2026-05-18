## ADDED Requirements

### Requirement: Output-rendering crate is named may-i-output

The workspace crate hosting the `Layout` ADT, `Terminal` detection, `write_layout`, and the advisory/note/columns combinators SHALL be named `may-i-output` (Cargo package, directory, and Rust extern name `may_i_output`); the earlier name `may-i-layout` SHALL NOT appear.

#### Scenario: Cargo manifest exposes the renamed package

- **WHEN** `cargo metadata --no-deps --format-version 1` is queried for
  workspace members
- **THEN** a package named `may-i-output` is present at
  `crates/may-i-output`
- **AND** no package named `may-i-layout` is present

#### Scenario: No source file imports the old extern name

- **WHEN** the workspace is scanned for `may_i_layout` (Rust import
  identifier) under `src/` and `crates/`
- **THEN** zero matches are found
- **AND** every former import resolves to `may_i_output`
