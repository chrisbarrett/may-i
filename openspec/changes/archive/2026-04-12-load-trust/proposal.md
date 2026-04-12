## Why

The `(load ...)` directive (config-load-directive change) lets users split
config across files. Loaded files may come from project directories, shared
repos, or third-party dotfiles — sources the user hasn't directly authored. Without
a trust mechanism, any loaded file can silently alter authorization decisions.

## What Changes

- Rules and defines from loaded files are tagged with provenance
  (`PrimaryConfig` vs `Loaded`).
- For each program that has any `Loaded` rule or references a `Loaded` define,
  the system computes a trust hash over the resolved rule closure for that
  program.
- Trust hashes are stored persistently. On load, if a program's hash differs
  from the stored value, the system blocks evaluation for that program and
  prompts the user to review and approve.
- `safe-env-vars` from loaded files gets its own trust hash, independent of
  program closures.
- Rules in the primary config are implicitly trusted and do not require hashing
  or approval.
- `CommandPattern::Regex` is removed from command dispatch. Command patterns are
  restricted to `Literal` and `Or(Vec<Literal>)`, making the set of program
  names decidable and enumerable. **BREAKING**
- A `may-i trust` subcommand allows users to review and approve changed
  programs.

## Capabilities

### New Capabilities

- `rule-provenance`: Tagging rules and defines with `PrimaryConfig` or `Loaded`
  provenance during load expansion.
- `trust-hashing`: Computing per-program trust hashes from the resolved rule
  closure, excluding comments, checks, and formatting. Includes `safe-env-vars`
  as a separate trust scope.
- `trust-store`: Persistent storage and comparison of trust hashes, blocking
  evaluation for untrusted programs.
- `trust-command`: CLI subcommand (`may-i trust`) for reviewing and approving
  changed program closures.

### Modified Capabilities

(none)

## Impact

- `crates/config/src/io.rs`: Load expansion tags each rule/define with
  provenance.
- `crates/core/src/ast.rs`: `Define` and `Rule` gain a `Provenance` field.
  `CommandPattern::Regex` is removed.
- `crates/core/src/pattern.rs`: Remove `Regex` variant from `CommandPattern`.
- `crates/config/src/rule.rs`: Remove regex command pattern parsing.
- `crates/engine/`: New trust-hash computation module.
- `src/main.rs`: New `trust` subcommand.
- Trust store location: `~/.local/share/may-i/trust/` or equivalent via
  `dirs` crate.
- Prerequisite: `binding-environment` change (provenance on defines requires
  the Var/env model so provenance propagates through references rather than
  being lost on inline).
