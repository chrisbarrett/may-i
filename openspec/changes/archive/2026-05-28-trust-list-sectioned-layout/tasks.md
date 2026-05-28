## 1. Test-first

- [x] 1.1 Update unit tests in `src/output/trust_groups.rs` (`trust_listing_emits_groups_without_heading`, `trust_listing_emits_heading_before_groups`) to assert the new sectioned shape via insta snapshots; let them fail red.
- [x] 1.2 Add a unit test for the wide-row case: a single source file with enough program names to exceed `term.width`, asserting that wrapping occurs beneath the heading and no line exceeds `term.width`.
- [x] 1.3 Add a unit test for the long-file-path case: a heading whose `shorten_home` length exceeds half the terminal width, asserting the heading renders in full on its own line.

## 2. Implement sectioned renderer

- [x] 2.1 Rewrite `render_trusted_groups` in `src/output/trust_groups.rs` to build a `Layout::Stack` of per-file sections instead of `Layout::Columns`.
- [x] 2.2 Each section: `Stack( Text(dimmed(shorten_home(file))), Indent(2, Wrap(program_items, separator=", ")) )`, with `Blank` between sections.
- [x] 2.3 Outer indent stays at 2 (consistent with current call sites that pass groups in).
- [x] 2.4 Drop the now-unused `ColRow` / `ColContent::Text` construction in this module; keep imports minimal.

## 3. Update snapshots and integration tests

- [x] 3.1 Run `cargo insta review` for `src/output/snapshots/` and accept the new shape for the two listing snapshots.
- [x] 3.2 Search for integration tests under `tests/` that assert the old two-column trusted-listing format (`grep` for `│` near "trusted" or for the existing snapshot literals). Regenerate or rewrite as needed.
- [x] 3.3 Re-run the unit tests from §1 and confirm they pass.

## 4. Manual verification

- [x] 4.1 Build release: `cargo build --release`.
- [x] 4.2 Run `target/release/may-i trust` against a config with a wide row (multiple long program names from one file) in a standard 120-col terminal; confirm no horizontal overflow and program names wrap under the heading.
- [x] 4.3 Repeat at 80 cols and at a deliberately narrow width (e.g. `COLUMNS=60 may-i trust`); confirm graceful wrapping.
- [x] 4.4 Run `may-i trust --json` and confirm JSON output is byte-identical to before this change (no shape change to the JSON path).

## 5. Validation

- [x] 5.1 `cargo fmt`.
- [x] 5.2 `cargo test --workspace`.
- [x] 5.3 `cargo tarpaulin` and check coverage on `src/output/trust_groups.rs`; add a proptest if a generalisable property emerges.
- [x] 5.4 `openspec validate trust-list-sectioned-layout`.
