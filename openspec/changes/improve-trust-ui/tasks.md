## 1. Provenance with file paths

- [ ] 1.1 Change `Provenance::Loaded` to `Provenance::Loaded { path: PathBuf }` in `crates/core/src/ast.rs`
- [ ] 1.2 Update `expand_loads` in `crates/config/src/io.rs` to thread file paths into `Provenance::Loaded`
- [ ] 1.3 Fix all pattern matches on `Provenance::Loaded` across the codebase (engine, config, tests)
- [ ] 1.4 Add/update provenance tests in `crates/config/src/io.rs` to verify file paths are recorded

## 2. TrustHashes metadata

- [ ] 2.1 Add `ProgramMeta` struct to `crates/engine/src/trust.rs` with `hash`, `canonical_rules`, `source_files` fields
- [ ] 2.2 Change `TrustHashes.programs` from `BTreeMap<String, String>` to `BTreeMap<String, ProgramMeta>`
- [ ] 2.3 Update `compute_trust_hashes` to retain canonical rule strings and collect source file paths from rule provenance
- [ ] 2.4 Fix all call sites that access `TrustHashes.programs` (cmd_trust, cmd_eval, cmd_claude_code_hook, trust_store)
- [ ] 2.5 Add tests for metadata content (canonical forms present, source files correct)

## 3. Trust store v2 format

- [ ] 3.1 Define v2 store structs in `src/trust_store.rs` with `version` field, nested program entries containing `hash` + `rules`
- [ ] 3.2 Implement backward-compatible deserialization: detect v1 (flat) vs v2 (versioned) on load
- [ ] 3.3 Implement integrity verification on load: re-hash stored canonical forms against stored hash, return `Vec<SuspectEntry>` for mismatches
- [ ] 3.4 Update `approve` to store canonical forms alongside hash
- [ ] 3.5 Add accessor for previous canonical forms (for diff computation)
- [ ] 3.6 Update `save` to write v2 format
- [ ] 3.7 Add tests: v1→v2 loading, round-trip, previous forms retrieval, integrity verification pass/fail, v1 entries have no forms (no verification needed)

## 4. Interactive review infrastructure

- [ ] 4.1 Add `SuspectEntry` struct (program name, stored hash, unverified forms) to trust_store module
- [ ] 4.2 Implement TTY detection helper (stdin is TTY and no `--json` flag)
- [ ] 4.3 Implement shared entry detail renderer: displays program name, status badge, source files, canonical rule forms, and (for CHANGED) diff against previous forms
- [ ] 4.4 Implement shared `interactive_review` function: takes list of entries with action choices, prompts per-entry, returns user decisions
- [ ] 4.5 Implement integrity repair session using `interactive_review`: re-approve (re-hash stored forms) or drop (remove entry)
- [ ] 4.6 Save repaired store after all suspect entries resolved, then proceed with original operation
- [ ] 4.7 Non-interactive fallback for integrity: treat suspect forms as unavailable, emit stderr warning directing user to run `may-i trust` interactively
- [ ] 4.8 Implement interactive approval for `may-i trust --all`: walk each NEW/CHANGED entry through `interactive_review`, approve or skip
- [ ] 4.9 Implement interactive approval for `may-i trust <program>`: display single entry detail, prompt confirm
- [ ] 4.10 Implement interactive flow for `may-i trust` (no args): show listing, offer to walk through pending entries
- [ ] 4.11 Non-interactive fallback for approval: approve without prompting when stdin is not TTY or `--json` (preserves batch/CI behavior)
- [ ] 4.12 Add tests: repair re-approve updates hash, repair drop removes entry, approval approve/skip, non-interactive batch approval, already-trusted program reports status without prompt

## 5. Trust listing UI redesign

- [ ] 5.1 Implement grouped-by-file layout for all-trusted case using `Layout::Columns` with `ColContent::Breakable`
- [ ] 5.2 Implement untrusted detail view: program name, status badge, source file, canonical rule forms
- [ ] 5.3 Implement diff display for CHANGED programs: line-level diff with `-`/`+` prefixes
- [ ] 5.4 Update JSON mode to include `files`, `rules`, and `previousRules` fields
- [ ] 5.5 Add integration tests for listing output in both human and JSON modes

## 6. Block message context

- [ ] 6.1 Update `check_trust_for_command` in `cmd_eval.rs` to include source file paths in block message
- [ ] 6.2 Update `check_trust` in `cmd_claude_code_hook.rs` to include source file paths in reason string
- [ ] 6.3 Update eval JSON block response to include `files` array
- [ ] 6.4 Update integration tests for block messages with file paths

## 7. Final validation

- [ ] 7.1 Run full test suite and fix any breakage from Provenance/TrustHashes type changes
- [ ] 7.2 Manual smoke test: create config with loaded rules, verify trust listing, approve, modify, verify diff display
- [ ] 7.3 Smoke test: tamper with trust store canonical forms, verify interactive repair triggers
