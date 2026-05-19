## Why

`src/interactive.rs` (553 LOC) owns two TTY-driven flows — integrity repair and
the per-rule review loop — and reaches directly into the trust data model
(`TrustStore`, `TrustHashes`, `SuspectEntry`, `RuleMeta`, `ProgramMeta`), the
pretty-printer (`may_i_pp`, `may_i_sexpr`, `Doc`), and the terminal
(`console::Term`, `dialoguer`, `colored`). The control flow is straightforward
(present an entry, prompt, mutate the store, loop) but it is impossible to
unit-test without spinning up a real TTY and a real `TrustStore`, and any change
to either the trust-store shape or the pretty-printed rendering forces edits
inside `interactive.rs`. New trust review actions can't be added without
threading them through the same TTY-coupled module.

## What Changes

- Introduce a `UserPrompt` trait that captures the small set of prompting
  primitives the review and repair loops actually need (yes/no, choose-one,
  render-a-doc). The terminal implementation (existing `console::Term` +
  `dialoguer` calls) becomes one `UserPrompt` impl in `interactive.rs`; tests
  use a scripted fake impl that records output and replays canned answers.
- Introduce a `ReviewAction` enum keying the per-entry decision the loop
  produces (`Approve`, `Block`, `Skip`, `Quit` for per-rule review;
  `Reapprove`, `Drop` for integrity repair). The loop body becomes a pure
  function over `(entry, ReviewAction) -> StoreOp` plus a `UserPrompt`-driven
  driver.
- Extract the loop logic (iteration, progress accounting, trusted-summary
  bookkeeping, screen clearing, summary printing) into a new pure module
  (`src/trust/review/`) that depends on `UserPrompt` and the trust-store
  surface only — no `console`, `dialoguer`, `colored`, `may_i_pp`, or
  `may_i_sexpr` imports.
- Reduce `src/interactive.rs` to the terminal `UserPrompt` impl plus thin
  entry-point shims (`repair_integrity`, `interactive_review`,
  `interactive_approve`) that wire the terminal impl into the pure loop.
- Add unit tests for the pure loop that drive it against a scripted fake
  `UserPrompt` and assert on emitted `StoreOp`s and the final
  `ReviewSummary`. Keep an integration / snapshot test covering the terminal
  impl so the rendered prompts and screens stay byte-stable.
- **BREAKING** (contributor surface only, pre-1.0): the public functions in
  `crate::interactive` (`repair_integrity`, `interactive_review`,
  `interactive_approve`, `pretty_form`, `ReviewSummary`, `pending_entries`)
  may be relocated, renamed, or marked `pub(crate)`. No user-visible
  behaviour change.

## Capabilities

### New Capabilities

_None._

### Modified Capabilities

- `trust-command`: the per-rule interactive review flow gains a normative
  requirement that the loop logic is keyed on a domain `ReviewAction` and is
  unit-testable in isolation from the terminal — the prompting seam is
  swappable. No change to displayed prompts, accepted keys, or screen
  contents.
- `trust-store`: the integrity-repair flow gains the same seam requirement —
  the repair loop drives a `UserPrompt` impl rather than calling `dialoguer`
  directly, so the repair branches (re-approve / drop / skip-in-non-tty) are
  unit-testable.
- `testing-strategy`: adds a requirement that interactive prompting flows are
  exercised by unit tests over a fake prompt impl, not only by end-to-end
  TTY-driven integration tests.

## Impact

- **Code:** `src/interactive.rs` shrinks to the terminal `UserPrompt` impl
  plus entry shims; new `src/trust/review/` module (or equivalent location
  inside `src/trust/`) for the pure loop; `src/trust/mod.rs` re-exports for
  the new types; call sites in `src/cmd_trust.rs` unchanged or trivially
  rewired.
- **APIs (contributor):** new `crate::trust::review::{UserPrompt,
  ReviewAction, run_review, run_integrity_repair}` (exact paths TBD in
  design); `crate::interactive` surface narrowed.
- **Tests:** new unit tests under `src/trust/review/` driving the pure loop
  against a `FakeUserPrompt`; existing integration tests for
  `may-i trust` (per `trust-command` scenarios) continue to pin the
  terminal-rendered behaviour byte-for-byte.
- **User-visible behaviour:** none. Same prompts, same keybindings, same
  screen layout, same summary line.
- **Dependencies:** no new crates. `dialoguer`, `console`, `colored`,
  `may_i_pp`, `may_i_sexpr` imports concentrate in the terminal
  `UserPrompt` impl rather than spreading through the loop.
- **Coordination:** the parallel `unify-trust-metadata` change (stub at
  `openspec/changes/unify-trust-metadata/`) intends to introduce a unified
  `TrustView` type. If that change lands first, the pure review loop should
  consume `TrustView` instead of `&TrustHashes` + `&TrustStore`; see
  design.md for the dependency note.
