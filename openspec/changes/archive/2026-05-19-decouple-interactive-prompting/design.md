## Context

`src/interactive.rs` (553 LOC, `src/interactive.rs:1-553`) carries two flows
that share the same shape — present an entry, take a user decision, mutate the
trust store, advance — but pull in a wide stack:

- Trust data: `TrustStore`, `TrustCheck`, `TrustStatus`, `SuspectEntry` from
  `crate::trust::store`; `TrustHashes`, `RuleMeta`, `ProgramMeta` from
  `may_i_engine::trust`.
- Rendering: `may_i_pp`, `may_i_sexpr`, `may_i_core::Doc`,
  `crate::output::{Terminal, write_layout, render_labelled_separator,
  shorten_home}`, `colored::Colorize`, `similar::TextDiff`.
- TTY: `console::Term`, `dialoguer::{Confirm, Select}`, `std::io::stderr`.

The loop bodies — `repair_integrity` (`src/interactive.rs:69-128`),
`interactive_review` (`src/interactive.rs:134-285`), `interactive_approve`
(`src/interactive.rs:372-418`) — interleave control flow ("for each pending
rule, render header, render detail, read key, branch") with display
(`writeln!`, `term.clear_screen`, ANSI styling) and store mutation
(`store.approve_rule`, `store.block_rule`, `store.reapprove`). The control flow
is the part worth testing — does the loop emit the right `StoreOp`s for a
given sequence of user decisions, does it update the trusted-summary counters
correctly, does it short-circuit on `Quit` — but it can only be reached today
by spawning the real TTY harness.

Two adjacent changes inform this one:

1. `2026-05-17-trust-pipeline-followups` (archived
   `openspec/changes/archive/2026-05-17-trust-pipeline-followups/`) decoupled
   `cmd_*` from `TrustStore::load` and pushed rendering into `output::`. It
   did not touch `interactive.rs`.
2. `openspec/changes/unify-trust-metadata/` (stub, no artifacts) intends to
   introduce a unified `TrustView` collapsing today's `TrustHashes` +
   `TrustStore` view-builder pattern.

## Goals / Non-Goals

**Goals:**

- A `UserPrompt` trait whose surface area is exactly what the two loops need:
  rendering pre-formatted output, prompting for a confirm (`y/N`-style),
  prompting for a choice (`Select`-style), and clearing the screen.
- A `ReviewAction` enum (per-rule variants: `Approve`, `Block`, `Skip`,
  `Quit`) and a `RepairAction` enum (`Reapprove`, `Drop`) keying the loop
  branches.
- A pure module (proposed: `src/trust/review/`) housing `run_review` and
  `run_integrity_repair` whose only inputs are the trust data view, a
  `UserPrompt` impl, and rendering helpers passed by reference. No
  `console::Term`, no `dialoguer`, no `std::io::stderr` direct writes.
- `src/interactive.rs` reduced to the terminal `UserPrompt` impl plus
  one-line entry-point shims.
- Unit tests for `run_review` and `run_integrity_repair` over a scripted
  `FakeUserPrompt` that asserts:
  - the sequence of `StoreOp`s applied for a given answer script,
  - `ReviewSummary` counters match (`approved` / `blocked` / `skipped`),
  - `Quit` exits the loop without consuming remaining entries,
  - non-interactive integrity repair returns `Ok(false)` without
    prompting.
- Existing integration tests for `may-i trust` (per `trust-command`) keep
  passing byte-for-byte.

**Non-Goals:**

- Changing what the user sees. Same prompts, same labels, same screen
  clear sequence, same summary line, same colour scheme.
- Replacing `dialoguer` / `console` with a different TTY library.
- Restructuring `TrustStore` mutation methods (`approve_rule`,
  `block_rule`, `reapprove`, `drop_entry`).
- Unifying the per-rule loop with the legacy per-program loop
  (`interactive_approve`). Both should benefit from the seam but the
  existing two-loop split stays.
- Changing the pretty-print pipeline. `pretty_form` keeps its current
  shape; if it moves, it moves to a rendering-helpers module, not into
  the pure loop.
- Pre-emptively consuming a `TrustView` type before the
  `unify-trust-metadata` change actually creates one.

## Decisions

### Decision 1: `UserPrompt` trait surface

The trait exposes the smallest set of operations that covers both loops:

```rust
pub trait UserPrompt {
    /// Render a pre-formatted block (with ANSI codes preserved on a real
    /// terminal, optionally stripped by a test impl).
    fn render(&mut self, block: &str);

    /// Yes/no prompt with a default answer; returns the user's choice.
    fn confirm(&mut self, prompt: &str, default: bool) -> miette::Result<bool>;

    /// Choose-one prompt; returns the index of the chosen item.
    fn choose(&mut self, prompt: &str, items: &[&str], default: usize)
        -> miette::Result<usize>;

    /// Read a single keystroke from a closed set; returns one of `keys`.
    /// Re-prompts on unrecognised input.
    fn read_key(&mut self, keys: &[char]) -> miette::Result<char>;

    /// Clear the screen (no-op for non-TTY impls).
    fn clear_screen(&mut self);
}
```

The `read_key` op is necessary because the per-rule review uses single-key
keybindings (`y/n/s/q`) via `console::Term::read_char`, which `dialoguer`
doesn't expose. Keeping it in the trait means the loop never reaches for
`console::Term` directly.

**Alternative considered: a single `prompt(PromptRequest) -> PromptResponse`
enum-tagged op.** Rejected — collapses the type-checked surface into a
runtime match, and `dialoguer`'s typed methods don't compose into a
single enum without losing the per-method error context.

**Alternative considered: trait-per-prompt (`Confirm`, `Choose`,
`ReadKey`).** Rejected — multiplies the impl burden for the fake without
buying composition; both loops want all the ops.

### Decision 2: `ReviewAction` / `RepairAction` enums plus a `StoreOp` projection

The per-rule loop classifies user input as a `ReviewAction`:

```rust
pub enum ReviewAction { Approve, Block, Skip, Quit }
```

The integrity-repair loop uses:

```rust
pub enum RepairAction { Reapprove, Drop }
```

The loop body is a pure function from `(entry, ReviewAction)` to an optional
`StoreOp` plus a control flag:

```rust
pub enum StoreOp {
    ApproveRule { hash: String, program: String, form: String },
    BlockRule   { hash: String, program: String, form: String },
    Reapprove   { program: String },
    Drop        { program: String },
}
```

Tests assert on the emitted `StoreOp` sequence rather than on the
`TrustStore` end-state. The driver applies each `StoreOp` to a real
`TrustStore` between iterations, so production behaviour is unchanged.

**Alternative considered: tests assert on `TrustStore` end-state.**
Rejected — couples tests to `TrustStore`'s internal representation; a
later `unify-trust-metadata` change would force test rewrites for a
pure refactor.

**Alternative considered: skip the `StoreOp` projection, let the loop
mutate a `&mut TrustStore` directly.** Rejected — keeps the trust-store
coupling the proposal aims to remove and forces test fakes to either
build a real store or implement a `TrustStore` trait, both heavier than
asserting on an op log.

### Decision 3: New module lives at `src/trust/review/`

The loop is trust-administrative behaviour; co-locating it with
`src/trust/{store,advisory,gate,rehash}.rs` matches the established
shape. The module split:

- `src/trust/review/mod.rs` — re-exports `UserPrompt`, `ReviewAction`,
  `RepairAction`, `StoreOp`, `ReviewSummary`, `run_review`,
  `run_integrity_repair`.
- `src/trust/review/loop.rs` — pure `run_review` and `run_integrity_repair`
  (rename if `loop` collides with the Rust keyword in `mod` form — likely
  `review_loop.rs`).
- `src/trust/review/prompt.rs` — `UserPrompt` trait + `StoreOp` /
  `ReviewAction` / `RepairAction` enums.
- `src/trust/review/render.rs` — pure formatting helpers (`pretty_form`
  and the diff/detail rendering) that produce strings; the loop calls
  these and passes the result into `UserPrompt::render`.
- `src/trust/review/tests.rs` (or inline `#[cfg(test)] mod tests`) —
  unit tests over `FakeUserPrompt`.

`src/interactive.rs` becomes the terminal `UserPrompt` impl
(`TerminalPrompt`) plus shim entry points that build a `TerminalPrompt`
and delegate.

**Alternative considered: keep everything in `src/interactive.rs` and
split internally.** Rejected — the proposal's testability win requires
the pure loop to not transitively import TTY crates, which means it
must live in a separate module.

**Alternative considered: new top-level `src/review/`.** Rejected — the
loops only exist to drive trust-store mutation; placing them outside
`src/trust/` hides that relationship from the module tree.

### Decision 4: `FakeUserPrompt` lives next to the loop tests

The fake records every `render` call and replays a scripted answer queue
for each `confirm` / `choose` / `read_key`. Implemented inline in the
test module (`#[cfg(test)]`), not exposed in the public crate. Asserting
on the recorded render strings doubles as a regression check on prompt
text.

### Decision 5: Non-interactive integrity repair stays in the loop module

`repair_integrity` currently branches on `interactive: bool` at
`src/interactive.rs:78-87` and writes the non-interactive advisory via
`crate::trust::advisory::build_integrity_layout` +
`crate::output::write_layout`. That non-interactive branch is logic too
(skip prompting, render advisory, return `false`) — keep it in
`run_integrity_repair` and let the test cover it by passing a
`FakeUserPrompt` plus a flag, rather than splitting it out. The advisory
rendering call stays as-is (it already uses the `output` seam).

### Decision 6: `unify-trust-metadata` coordination

The `unify-trust-metadata` change directory exists as a stub
(`openspec/changes/unify-trust-metadata/.openspec.yaml`, no artifacts).
If that change lands first and introduces a `TrustView`, the pure loop
should consume `&TrustView` instead of today's `(&TrustHashes, &TrustStore
view)` pair, and `run_review`'s signature should be updated accordingly.
Until then, the loop takes the existing types; the `StoreOp` projection
(Decision 2) keeps the test surface stable across that follow-up.

This change MUST NOT block on `unify-trust-metadata`. The seam introduced
here makes the future swap a single-signature change inside the pure
module.

## Risks / Trade-offs

- **[Risk]** Subtle drift in the rendered review screen if the helpers move
  between modules — line numbers, spacing, ANSI sequences. → **Mitigation:**
  keep the existing snapshot / integration coverage for `may-i trust`
  unchanged; the change is judged green only if every existing snapshot
  matches byte-for-byte.

- **[Risk]** `read_key` semantics differ subtly between `console::Term`
  (raw mode, single char, blocks on stdin) and a fake (scripted). The
  current loop re-prompts on unrecognised input
  (`src/interactive.rs:275-278`); the trait must make that contract
  explicit. → **Mitigation:** `UserPrompt::read_key(&[char])` takes the
  closed set and the trait contract says "re-prompts until a member of
  `keys` is returned"; the terminal impl loops, the fake validates each
  scripted answer against the closed set and panics in tests if a script
  is wrong.

- **[Risk]** Splitting `pretty_form` from the loop forces the pure module
  to either depend on `may_i_pp` / `may_i_sexpr` (which it should be free
  of) or to receive pre-rendered strings. → **Mitigation:** pre-render in
  `render.rs` — those helpers are pure functions over canonical-form
  strings, so they stay in `src/trust/review/render.rs` and the loop
  receives strings ready for `UserPrompt::render`. `render.rs` keeps the
  `may_i_pp` / `may_i_sexpr` imports; `loop.rs` does not.

- **[Trade-off]** A `StoreOp` enum adds an indirection layer between user
  input and `TrustStore` mutation. The cost is one extra match per loop
  iteration; the benefit is decoupled, testable loop logic and a clean
  swap-point for a future `TrustView`-based pure-store implementation.

- **[Trade-off]** Three trait ops (`confirm`, `choose`, `read_key`) feel
  redundant — they're all "ask the user something". Collapsing them
  loses the typed-input ergonomics of `dialoguer`'s methods and forces a
  custom enum-typed result. Keep them split.

- **[Risk]** Coverage: `cargo tarpaulin` may flag the trivial
  `TerminalPrompt` impl as uncovered (it only runs under a TTY).
  → **Mitigation:** acceptable — the integration tests cover the
  rendered output end-to-end; the trait impl bodies are direct
  delegations to `dialoguer` / `console`. Note in the verify report if
  coverage drops.

## Migration Plan

Pure internal refactor. No user migration. No trust-hash change. No DSL
change. Sequenced rollout (single PR):

1. Add `src/trust/review/` skeleton with `UserPrompt`, `ReviewAction`,
   `RepairAction`, `StoreOp`, `ReviewSummary`. Re-export from
   `src/trust/mod.rs`.
2. Move `pretty_form` and the diff helpers into `src/trust/review/render.rs`
   (or keep `pretty_form` in `interactive.rs` and import — decide during
   implementation based on what cleans up cleanest).
3. Implement `run_review` and `run_integrity_repair` in
   `src/trust/review/loop.rs` (or `review_loop.rs`) consuming `UserPrompt`.
4. Implement `TerminalPrompt` in `src/interactive.rs` (existing
   `console::Term` / `dialoguer` calls).
5. Rewrite `repair_integrity`, `interactive_review`, `interactive_approve`
   in `src/interactive.rs` as shims building a `TerminalPrompt` and calling
   the pure loop.
6. Add unit tests over `FakeUserPrompt` in the pure module.
7. Run `cargo test --workspace` and confirm every existing snapshot /
   integration test passes byte-for-byte.
8. `cargo tarpaulin`; verify the pure loop is covered.

Rollback: revert the PR. No persisted state changes.

## Open Questions

- Should `interactive_approve` (the legacy program-level loop) share
  `run_review` or stay as its own driver? Tentative answer: share, by
  classifying its `Confirm` answers into the existing `ReviewAction`
  variants (`Approve` / `Skip`). Settle during implementation.
- Should `pretty_form` move to a more central place
  (`src/output/` or a new `src/render/`) given it's not strictly
  trust-specific? Tentative answer: leave in `src/trust/review/render.rs`
  for now — it's only called from review flows. Promote later if a
  second caller appears.
- Module name: `src/trust/review/loop.rs` is technically fine
  (`loop` is a keyword but `loop.rs` is a filename, not an identifier).
  If clippy or rustfmt complains, fall back to `review_loop.rs`.
