## 1. Define the prompting seam

- [x] 1.1 Create `src/trust/review/mod.rs` and `pub mod review;` from `src/trust/mod.rs`. Re-export the public surface (`UserPrompt`, `ReviewAction`, `RepairAction`, `StoreOp`, `ReviewSummary`, `run_review`, `run_integrity_repair`) from the module root.
- [x] 1.2 Add `src/trust/review/prompt.rs` defining the `UserPrompt` trait (`render`, `confirm`, `choose`, `read_key`, `clear_screen`) per design Decision 1.
- [x] 1.3 Define the `ReviewAction` enum (`Approve`, `Block`, `Skip`, `Quit`) and the `RepairAction` enum (`Reapprove`, `Drop`) in `prompt.rs`.
- [x] 1.4 Define the `StoreOp` enum (`ApproveRule`, `BlockRule`, `Reapprove`, `Drop`) and the `ReviewSummary` struct (moved from `src/interactive.rs`) in `prompt.rs` or a sibling `types.rs`.

## 2. Extract pure rendering helpers

- [x] 2.1 Move `pretty_form`, `doc_from_sexpr`, `render_pretty_diff`, `render_rule_detail`, `render_entry_detail`, `render_diff`, `render_suspect_detail`, and `print_summary` from `src/interactive.rs` into `src/trust/review/render.rs`. Each helper must return a `String` (or `Vec<String>`) rather than writing directly to a `Write` — the loop will feed the result to `UserPrompt::render`.
- [x] 2.2 Confirm `src/trust/review/render.rs` is the only place inside `src/trust/review/` that imports `may_i_pp`, `may_i_sexpr`, `similar`, or `colored`. The loop module must not import them.

## 3. Extract the pure loops

- [x] 3.1 Create `src/trust/review/review_loop.rs` (use this name to avoid the `loop` keyword filename ambiguity).
- [x] 3.2 Implement `pub fn run_review(prompt: &mut dyn UserPrompt, hashes: &TrustHashes, store_view: ...) -> miette::Result<(Vec<StoreOp>, ReviewSummary)>` containing the body of the existing `interactive_review` (`src/interactive.rs:134-285`). The function must not import `console`, `dialoguer`, or `colored`. It must call `render::*` helpers for display strings and `prompt.render` / `prompt.read_key` / `prompt.clear_screen` for IO.
- [x] 3.3 Implement `pub fn run_integrity_repair(prompt: &mut dyn UserPrompt, suspects: &[SuspectEntry], interactive: bool) -> miette::Result<Vec<StoreOp>>` containing the body of the existing `repair_integrity` (`src/interactive.rs:69-128`). Preserve the non-interactive branch that renders the advisory via `crate::trust::advisory::build_integrity_layout` + `crate::output::write_layout`.
- [x] 3.4 (Optional, per design Open Question) Implement `run_program_review` for the legacy `interactive_approve` path, or document why it stays as its own driver.

## 4. Implement the terminal `UserPrompt`

- [x] 4.1 In `src/interactive.rs`, define `pub(crate) struct TerminalPrompt { term: console::Term }` and `impl UserPrompt for TerminalPrompt` whose method bodies are direct delegations to `term.write_all` / `dialoguer::Confirm` / `dialoguer::Select` / `term.read_char` / `term.clear_screen` — the same calls the original loops made.
- [x] 4.2 Rewrite `pub fn repair_integrity`, `pub fn interactive_review`, and `pub fn interactive_approve` in `src/interactive.rs` as ≤10-line shims that build a `TerminalPrompt`, call the matching `crate::trust::review::run_*` function, and apply the returned `StoreOp`s to the `&mut TrustStore`.
- [x] 4.3 Remove now-unused imports from `src/interactive.rs` (`may_i_pp`, `may_i_sexpr`, `may_i_core::Doc`, `similar`). The file should retain only `TerminalPrompt`, the shim entry points, `is_interactive`, `pending_entries` (if kept here), and any small terminal helpers.

## 5. Unit-test the pure loops

- [x] 5.1 In `src/trust/review/review_loop.rs` (or a `#[cfg(test)] mod tests` submodule), define a `FakeUserPrompt` that records every `render` call into a `Vec<String>` and pops scripted answers from a `VecDeque` for each `confirm` / `choose` / `read_key` call. Assert that scripted answers for `read_key` are members of the closed key set; panic the test if not.
- [x] 5.2 Write a unit test exercising `run_review` over three pending rules with a `y/n/s` answer script. Assert the emitted `StoreOp` sequence is `[ApproveRule(…), BlockRule(…), <none for skip>]` and `ReviewSummary { approved: 1, blocked: 1, skipped: 1 }`.
- [x] 5.3 Write a unit test exercising the `Quit` short-circuit: with five pending rules and a `y/q` answer script, assert the loop emits exactly one `ApproveRule` and stops without further `render`/`read_key` calls.
- [x] 5.4 Write a unit test exercising `run_integrity_repair` with two suspects and a `[Reapprove, Drop]` choose-script. Assert the emitted `StoreOp` sequence and that the recorded `render` strings contain each program name.
- [x] 5.5 Write a unit test exercising the non-interactive branch of `run_integrity_repair` (`interactive: false`): assert no `confirm` / `choose` / `read_key` call is made and the returned `StoreOp` list is empty.
- [x] 5.6 (If 3.4 was done) Add a unit test for the program-level loop equivalent.

## 6. Verify behaviour and quality

- [x] 6.1 `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`.
- [x] 6.2 `cargo test --workspace`. Every existing snapshot / integration test for `may-i trust` must pass byte-for-byte without modification.
- [x] 6.3 `cargo tarpaulin`; inspect `lcov.info` for uncovered branches in `src/trust/review/`. Add surgical unit tests for any gaps in the pure loops. The `TerminalPrompt` impl may remain uncovered (delegations only); note this in the verify report.
- [x] 6.4 `rg -F 'console::Term' src/trust/review/` returns zero hits. `rg -F 'dialoguer' src/trust/review/` returns zero hits. `rg -F 'may_i_pp' src/trust/review/review_loop.rs` returns zero hits.
- [x] 6.5 `openspec validate decouple-interactive-prompting --strict` passes.
- [x] 6.6 Run `may-i trust` interactively against a config with both pending and suspect entries; confirm prompts, keybindings, screen-clear sequence, progress separator, trusted-summary line, and final summary are byte-identical to behaviour before the change.
