## 1. Remove CommandPattern::Regex

- [x] 1.1 Remove `Regex` variant from `CommandPattern` enum in `crates/core/src/pattern.rs`
- [x] 1.2 Remove regex command parsing from `crates/config/src/rule.rs`
- [x] 1.3 Remove or update tests that use regex command patterns
- [x] 1.4 Add test: regex in command position produces a parse error

## 2. Add Provenance to Rule and Define

- [x] 2.1 Add `Provenance` enum (`PrimaryConfig`, `Loaded`) to `crates/core/src/ast.rs`
- [x] 2.2 Add `provenance: Provenance` field to `Rule` and `Define`
- [x] 2.3 Default provenance to `PrimaryConfig` in the config parser
- [x] 2.4 Update load expansion in `io.rs` to tag forms from loaded files as `Loaded`
- [x] 2.5 Add tests: root config forms get `PrimaryConfig`, loaded forms get `Loaded`, recursively loaded forms get `Loaded`

## 3. Trust hash computation

- [x] 3.1 Create trust hash module (extract program names from `CommandPattern`, group rules by program)
- [x] 3.2 Implement canonical serialization of resolved rule closures (via `ToDoc`, span-free)
- [x] 3.3 Implement SHA-256 hashing of canonical form
- [x] 3.4 Implement provenance-aware filtering: identify programs needing trust (any Loaded rule or Loaded define reference)
- [x] 3.5 Implement `safe-env-vars` trust hash (separate scope, triggered by any Loaded entry)
- [x] 3.6 Add tests: hash stability, hash changes on rule modification, hash unchanged on comment/check edits, hash unchanged for PrimaryConfig-only programs

## 4. Trust store

- [x] 4.1 Implement trust store read/write (JSON file at platform data dir)
- [x] 4.2 Implement hash comparison: match, mismatch, missing (new program)
- [x] 4.3 Implement trust blocking: return `ask` with trust-specific reason on mismatch
- [x] 4.4 Implement trust bypass for PrimaryConfig-only programs
- [x] 4.5 Add tests: persist and reload, mismatch detection, first-load blocking, bypass for untouched programs

## 5. Integrate trust checking into eval pipeline

- [x] 5.1 Wire trust hash computation into config loading (after load expansion, before eval)
- [x] 5.2 Wire trust store check into `cmd_eval` — block on mismatch
- [x] 5.3 Wire trust block into hook mode with exit code 2
- [x] 5.4 Add integration tests: eval blocked on first load, eval succeeds after approval, eval blocked on change

## 6. Trust CLI subcommand

- [x] 6.1 Add `trust` subcommand to clap CLI definition
- [x] 6.2 Implement `may-i trust` (no args) — list programs with trust status
- [x] 6.3 Implement `may-i trust "<program>"` — approve specific program
- [x] 6.4 Implement `may-i trust --all` — approve all pending
- [x] 6.5 Implement `--json` output for trust status
- [x] 6.6 Add integration tests for trust subcommand
