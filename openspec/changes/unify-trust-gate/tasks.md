## 1. Snapshot existing behaviour

- [ ] 1.1 Identify representative inputs covering: text-mode advisory, text-mode no-advisory, JSON-mode block, JSON-mode no-block, hook-mode block, hook-mode no-block, compound command first-segment block.
- [ ] 1.2 Capture stdout/stderr/exit-code for each input against the current binary; commit fixtures under `tests/fixtures/trust_gate/` (or extend `tests/snapshots/` if convention applies).

## 2. Build the gate

- [ ] 2.1 Create `src/trust_gate.rs` with `GateMode` enum (`Text`, `Json`, `Hook`) and `GateOutcome` enum (`Proceed { config, advisory: Option<Layout> }`, `Block { decision, reason, files: Vec<String> }`).
- [ ] 2.2 Move `default_trust_store_path` + `TrustStore::load` orchestration inside the gate; degrade silently on IO failure (matches today's `if let Ok(...)`).
- [ ] 2.3 Move program-name extraction (`split_whitespace().next() | rsplit('/').next()`) into the gate as a private helper.
- [ ] 2.4 Implement `Text` mode: filter rules, build advisory `Layout` (port logic from `trust_warning_note` + `trust_advisory::render`), return `Proceed`.
- [ ] 2.5 Implement `Json` mode: detect untrusted programs in command segments, build block reason + files (port from `cmd_eval::check_trust_json_block`), return `Block`.
- [ ] 2.6 Implement `Hook` mode: detect untrusted program for first segment, build block reason with file path (port from `cmd_claude_code_hook::check_trust`), return `Block`.
- [ ] 2.7 Add `pub use` to `src/lib.rs`.

## 3. Cover with tests

- [ ] 3.1 Unit tests in `trust_gate.rs` for each scenario in `specs/trust-gate/spec.md` (six explicit scenarios).
- [ ] 3.2 Property test: `Proceed` variant always returns a config with no Loaded rules whose hash is un-approved.
- [ ] 3.3 Property test: program-name extraction agrees with the verbatim algorithm copied from prior call sites (parametric over commands).

## 4. Refactor `trust_advisory` and `trust_store` for gate consumption

- [ ] 4.1 Convert `trust_advisory::render` into a pure `build_layout(...) -> Option<Layout>` (no stdout/stderr writes); side effects move to the caller (the gate, or `cmd_eval`/`cmd_check` writing the layout).
- [ ] 4.2 Demote `trust_advisory::filter_trusted_rules` and `trust_advisory::compute` to `pub(crate)` (or keep `pub` only where the hook crate boundary forces it).
- [ ] 4.3 Verify `cmd_trust` still compiles against unchanged trust-store APIs.

## 5. Migrate callers (one at a time, snapshot-verify after each)

- [ ] 5.1 Migrate `cmd_claude_code_hook`: replace `check_trust` (lines 123-186) and the filter block (lines 39-44) with one `trust_gate::evaluate(..., GateMode::Hook)` call. Snapshot-verify.
- [ ] 5.2 Migrate `cmd_check`: replace direct `trust_advisory::render` call with `trust_gate::evaluate(..., GateMode::Text)`; write returned advisory to stderr. Snapshot-verify.
- [ ] 5.3 Migrate `cmd_eval` text mode: replace advisory-render + filter sequence with one `evaluate(..., GateMode::Text)`. Snapshot-verify.
- [ ] 5.4 Migrate `cmd_eval` JSON mode: replace `check_trust_json_block` + filter sequence with one `evaluate(..., GateMode::Json)`. Snapshot-verify.

## 6. Delete duplicated logic

- [ ] 6.1 Remove the program-name extraction copy in `cmd_eval.rs` (lines ~249-261).
- [ ] 6.2 Remove the program-name extraction copy in `cmd_claude_code_hook.rs` (lines ~138-149).
- [ ] 6.3 Remove `cmd_eval::check_trust_json_block` and `cmd_claude_code_hook::check_trust` once the gate replaces them.

## 7. Verify and finalise

- [ ] 7.1 `cargo fmt`, `cargo clippy --all-targets`.
- [ ] 7.2 Full test suite + `cargo tarpaulin`; ensure trust-related branch coverage did not regress.
- [ ] 7.3 Replay all snapshots from step 1 — confirm byte-equal output.
- [ ] 7.4 Update `CONTEXT.md` "Three-Layer Model" section: under Trust, add a one-line note that the gate is the consumer-facing surface.
