## 1. Provenance with file paths

- [x] 1.1 Change `Provenance::Loaded` to `Provenance::Loaded { path: PathBuf }` in `crates/core/src/ast.rs`
- [x] 1.2 Update `expand_loads` in `crates/config/src/io.rs` to thread file paths into `Provenance::Loaded`
- [x] 1.3 Fix all pattern matches on `Provenance::Loaded` across the codebase (engine, config, tests)
- [x] 1.4 Add/update provenance tests in `crates/config/src/io.rs` to verify file paths are recorded

## 2. TrustHashes metadata

- [x] 2.1 Add `ProgramMeta` struct to `crates/engine/src/trust.rs` with `hash`, `canonical_rules`, `source_files` fields
- [x] 2.2 Change `TrustHashes.programs` from `BTreeMap<String, String>` to `BTreeMap<String, ProgramMeta>`
- [x] 2.3 Update `compute_trust_hashes` to retain canonical rule strings and collect source file paths from rule provenance
- [x] 2.4 Fix all call sites that access `TrustHashes.programs` (cmd_trust, cmd_eval, cmd_claude_code_hook, trust_store)
- [x] 2.5 Add tests for metadata content (canonical forms present, source files correct)

## 3. Trust store v2 format

- [x] 3.1 Rewrite `TrustStore` struct with `version` field and nested program entries containing `hash` + `rules`
- [x] 3.2 Implement integrity verification on load: re-hash stored canonical forms against stored hash, return `Vec<SuspectEntry>` for mismatches
- [x] 3.3 Update `approve` to store canonical forms alongside hash
- [x] 3.4 Add accessor for previous canonical forms (for diff computation)
- [x] 3.5 Add tests: round-trip, previous forms retrieval, integrity verification pass/fail

## 4. Interactive review infrastructure

- [x] 4.1 Add `SuspectEntry` struct (program name, stored hash, unverified forms) to trust_store module
- [x] 4.2 Implement TTY detection helper (stdin is TTY and no `--json` flag)
- [x] 4.3 Implement shared entry detail renderer: displays program name, status badge, source files, canonical rule forms, and (for CHANGED) diff against previous forms
- [x] 4.4 Implement shared `interactive_review` function: takes list of entries with action choices, prompts per-entry, returns user decisions
- [x] 4.5 Implement integrity repair session using `interactive_review`: re-approve (re-hash stored forms) or drop (remove entry)
- [x] 4.6 Save repaired store after all suspect entries resolved, then proceed with original operation
- [x] 4.7 Non-interactive fallback for integrity: treat suspect forms as unavailable, emit stderr warning directing user to run `may-i trust` interactively
- [x] 4.8 Implement interactive approval for `may-i trust --all`: walk each NEW/CHANGED entry through `interactive_review`, approve or skip
- [x] 4.9 Implement interactive approval for `may-i trust <program>`: display single entry detail, prompt confirm
- [x] 4.10 Implement interactive flow for `may-i trust` (no args): show listing, offer to walk through pending entries
- [x] 4.11 Non-interactive fallback for approval: approve without prompting when stdin is not TTY or `--json` (preserves batch/CI behavior)
- [x] 4.12 Add tests: repair re-approve updates hash, repair drop removes entry, approval approve/skip, non-interactive batch approval, already-trusted program reports status without prompt

## 5. Trust listing UI redesign

- [x] 5.1 Implement grouped-by-file layout for all-trusted case using `Layout::Columns` with `ColContent::Breakable`
- [x] 5.2 Implement untrusted detail view: program name, status badge, source file, canonical rule forms
- [x] 5.3 Implement diff display for CHANGED programs: line-level diff with `-`/`+` prefixes
- [x] 5.4 Update JSON mode to include `files`, `rules`, and `previousRules` fields
- [x] 5.5 Add integration tests for listing output in both human and JSON modes

## 6. Block message context

- [x] 6.1 Update `check_trust_for_command` in `cmd_eval.rs` to include source file paths in block message
- [x] 6.2 Update `check_trust` in `cmd_claude_code_hook.rs` to include source file paths in reason string
- [x] 6.3 Update eval JSON block response to include `files` array
- [x] 6.4 Update integration tests for block messages with file paths

## 7. Trust advisory box rendering

- [x] 7.1 Add `trust_warning_note()` to `src/output/mod.rs`: takes list of untrusted program names + source files, returns `Option<Layout>`. Single program → names it in heading + suggests `may-i trust "<program>"`. Multiple → heading "Untrusted rules", body lists names (take 5, comma-sep, "(and N more)"), suggests `may-i trust`.
- [x] 7.2 Add `trust_integrity_note()` to `src/output/mod.rs`: takes store path + suspect entries (or corrupt flag), returns `Layout`. Specific entries → NoteLevel::Error, names store path, lists entry names (take 5). Corrupt file → distinct "Trust store corrupted" heading, notes re-approval required.
- [x] 7.3 Add unit tests for both note builders: single program, multiple programs, >5 programs truncation, integrity with few entries, integrity with >5 entries, corrupt file variant.

## 8. Eval shows warning instead of blocking

- [x] 8.1 Change `cmd_eval` non-JSON path: replace early-return trust block with advisory box rendering + proceed with evaluation (untrusted rules default to `:ask`)
- [x] 8.2 JSON mode and hook mode remain unchanged (still block with `:ask` response)
- [x] 8.3 Add/update tests: eval with untrusted rules produces both warning box and trace output, eval JSON mode still returns ask block

## 9. Check subcommand gains trust awareness

- [x] 9.1 Add trust hash computation + store loading to `cmd_check` non-JSON path
- [x] 9.2 Render trust advisory box (warning for untrusted, error for integrity) before check results
- [x] 9.3 Add tests: check with untrusted rules shows warning then runs checks, check JSON mode unaffected

## 10. Advisory boxes in remaining subcommands

- [x] 10.1 Add trust advisory rendering to `cmd_trust` non-interactive paths (integrity error box for suspect entries)
- [x] 10.2 Add trust advisory rendering to `cmd_migrate` and `cmd_parse` (warning box for untrusted rules)
- [x] 10.3 Verify hook mode and reference/help are excluded

## 11. Final validation (phase 1)

- [x] 11.1 Run full test suite and fix any breakage from Provenance/TrustHashes type changes
- [x] 11.2 Manual smoke test: create config with loaded rules, verify trust listing, approve, modify, verify diff display
- [x] 11.3 Smoke test: tamper with trust store canonical forms, verify interactive repair triggers
- [x] 11.4 Smoke test: eval with untrusted rules shows advisory box + trace output
- [x] 11.5 Smoke test: check with untrusted rules shows advisory box + check results
- [x] 11.6 Smoke test: >5 untrusted programs renders truncated list correctly
- [x] 11.7 Smoke test: tampered trust store entries render error box with store path and entry names
- [x] 11.8 Smoke test: corrupted trust store file renders distinct "corrupted" error box

## 12. Trust store v3: per-rule entries

- [x] 12.1 Define `RuleEntry` struct with `program: String`, `form: String`, `status: RuleStatus` where `RuleStatus` is `Approved | Ignored`
- [x] 12.2 Rewrite `TrustStore` to use `BTreeMap<String, RuleEntry>` keyed by canonical form hash (replacing per-program `BTreeMap`)
- [x] 12.3 Implement v2→v3 migration on load: expand each program's `rules` array into individual `RuleEntry` values with `status: Approved`
- [x] 12.4 Update `TrustStore::check` to return per-rule status (approved/ignored/pending) given a rule hash
- [x] 12.5 Add `TrustStore::approve_rule(hash, program, form)` and `TrustStore::ignore_rule(hash, program, form)`
- [x] 12.6 Add `TrustStore::cleanup_orphans(current_hashes)` to remove entries not in the current config
- [x] 12.7 Add `TrustStore::previous_form(hash)` accessor for diff computation (returns stored form if hash differs but same program+position)
- [x] 12.8 Update integrity verification for v3 format
- [x] 12.9 Add tests: v2→v3 migration, approve/ignore/pending status checks, orphan cleanup, round-trip persistence

## 13. Per-rule trust hashing

- [x] 13.1 Change `compute_trust_hashes` to produce per-rule metadata: each rule gets its own hash, canonical form, source file, and program name
- [x] 13.2 Define `RuleMeta` struct: `hash: String`, `canonical_form: String`, `program: String`, `source_file: Option<PathBuf>`, `position: usize` (index within program's rules)
- [x] 13.3 Update `TrustHashes` to contain `Vec<RuleMeta>` (ordered) instead of `BTreeMap<String, ProgramMeta>`
- [x] 13.4 Retain `ProgramMeta`-like grouping as a derived view for listing UI (group `RuleMeta` by program)
- [x] 13.5 Update all call sites consuming `TrustHashes` (cmd_trust, cmd_eval, cmd_check, trust_advisory, interactive)
- [x] 13.6 Add tests: per-rule hashes are stable, each rule gets distinct hash, source files propagated

## 14. Eval pipeline trust filtering

- [x] 14.1 Add a `filter_trusted_rules(config, trust_store) -> Config` function that removes loaded rules not approved in the store
- [x] 14.2 Call `filter_trusted_rules` in `cmd_eval` before evaluation (both JSON and human modes)
- [x] 14.3 Call `filter_trusted_rules` in `cmd_claude_code_hook` before evaluation
- [x] 14.4 Primary config rules (non-loaded) pass through unfiltered
- [x] 14.5 Add tests: ignored rule excluded, pending rule excluded, approved rule included, primary rule always included

## 15. Interactive per-rule review

- [x] 15.1 Replace `interactive_approve` with `interactive_review` that iterates rules (not programs) and offers `y/n/s/q` keybindings
- [x] 15.2 Implement single-key input (no Enter required) using `dialoguer` or raw terminal input
- [x] 15.3 Display each rule: canonical form, status badge (NEW/CHANGED), source file path
- [x] 15.4 For CHANGED rules: detect change by comparing current rule at position N against stored rule at position N for the same program; show line-level diff
- [x] 15.5 `y` → call `store.approve_rule(...)`, `n` → call `store.ignore_rule(...)`, `s` → no-op, `q` → break loop
- [x] 15.6 Print summary after review: `Approved: N  Ignored: N  Skipped: N`
- [x] 15.7 Non-interactive fallback: `--all` without TTY approves all pending rules
- [x] 15.8 Add tests: approve/ignore/skip/quit flows, summary counts, non-interactive batch

## 16. Trust listing update for per-rule model

- [x] 16.1 Update `list_status_human` to show per-rule status within each program group
- [x] 16.2 Update `list_status_json` to emit per-rule entries with `program`, `hash`, `form`, `status`, `file`
- [x] 16.3 Update trust advisory box to count pending rules (not programs) and name affected programs
- [x] 16.4 Add tests: mixed statuses within a program render correctly, JSON format matches spec

## 17. Final validation (phase 2)

- [x] 17.1 Run full test suite
- [x] 17.2 Smoke test: fresh config with loaded rules — all rules pending, eval uses only primary rules
- [x] 17.3 Smoke test: approve some rules, ignore others — eval uses only approved
- [x] 17.4 Smoke test: modify a rule — appears as CHANGED with diff in `may-i trust`
- [x] 17.5 Smoke test: `may-i trust --all` in non-interactive mode approves all pending
- [x] 17.6 Smoke test: orphan cleanup removes stale entries after rules deleted from config
- [x] 17.7 Smoke test: v2 trust store migrates to v3 on load, preserving approvals
