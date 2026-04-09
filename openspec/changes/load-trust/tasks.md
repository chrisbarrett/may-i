## 1. Remove CommandPattern::Regex

- [ ] 1.1 Remove `Regex` variant from `CommandPattern` enum in `crates/core/src/pattern.rs`
- [ ] 1.2 Remove regex command parsing from `crates/config/src/rule.rs`
- [ ] 1.3 Remove or update tests that use regex command patterns
- [ ] 1.4 Add test: regex in command position produces a parse error

## 2. Add Provenance to Rule and Define

- [ ] 2.1 Add `Provenance` enum (`PrimaryConfig`, `Loaded`) to `crates/core/src/ast.rs`
- [ ] 2.2 Add `provenance: Provenance` field to `Rule` and `Define`
- [ ] 2.3 Default provenance to `PrimaryConfig` in the config parser
- [ ] 2.4 Update load expansion in `io.rs` to tag forms from loaded files as `Loaded`
- [ ] 2.5 Add tests: root config forms get `PrimaryConfig`, loaded forms get `Loaded`, recursively loaded forms get `Loaded`

## 3. Trust hash computation

- [ ] 3.1 Create trust hash module (extract program names from `CommandPattern`, group rules by program)
- [ ] 3.2 Implement canonical serialization of resolved rule closures (via `ToDoc`, span-free)
- [ ] 3.3 Implement SHA-256 hashing of canonical form
- [ ] 3.4 Implement provenance-aware filtering: identify programs needing trust (any Loaded rule or Loaded define reference)
- [ ] 3.5 Implement `safe-env-vars` trust hash (separate scope, triggered by any Loaded entry)
- [ ] 3.6 Add tests: hash stability, hash changes on rule modification, hash unchanged on comment/check edits, hash unchanged for PrimaryConfig-only programs

## 4. Trust store

- [ ] 4.1 Implement trust store read/write (JSON file at platform data dir)
- [ ] 4.2 Implement hash comparison: match, mismatch, missing (new program)
- [ ] 4.3 Implement trust blocking: return `ask` with trust-specific reason on mismatch
- [ ] 4.4 Implement trust bypass for PrimaryConfig-only programs
- [ ] 4.5 Add tests: persist and reload, mismatch detection, first-load blocking, bypass for untouched programs

## 5. Integrate trust checking into eval pipeline

- [ ] 5.1 Wire trust hash computation into config loading (after load expansion, before eval)
- [ ] 5.2 Wire trust store check into `cmd_eval` — block on mismatch
- [ ] 5.3 Wire trust block into hook mode with exit code 2
- [ ] 5.4 Add integration tests: eval blocked on first load, eval succeeds after approval, eval blocked on change

## 6. Trust CLI subcommand

- [ ] 6.1 Add `trust` subcommand to clap CLI definition
- [ ] 6.2 Implement `may-i trust` (no args) — list programs with trust status
- [ ] 6.3 Implement `may-i trust "<program>"` — approve specific program
- [ ] 6.4 Implement `may-i trust --all` — approve all pending
- [ ] 6.5 Implement `--json` output for trust status
- [ ] 6.6 Add integration tests for trust subcommand
