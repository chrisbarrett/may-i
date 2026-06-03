## Why

Interactive `may-i trust` review presents the same rule form to the user twice (or more) in a row when a single loaded rule resolves to multiple programs — e.g. an OR-of-programs `(rule (or "git" "gh") allow)` or any rule whose textual form is repeated across loaded files. The user must press `y`/`n` once per duplicated view despite the prompt body being byte-identical each time, which is confusing and erodes trust in the approval surface.

## What Changes

- The per-rule interactive review loop SHALL present each unique canonical rule form at most once per session, regardless of how many program names a rule resolves to or how many times the same canonical form appears in the loaded config set.
- Approving (or blocking) a deduplicated form SHALL apply that decision to every underlying view that shares the form's hash, so no stale "pending" entries linger after a single keystroke.
- Trust listing, JSON output, and the trust gate are unaffected — dedup is scoped to the interactive review prompt sequence.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `trust-command`: per-rule interactive review SHALL deduplicate pending entries by canonical-form hash before prompting.

## Impact

- Code: `src/interactive.rs` (`build_pending`) and/or `src/trust/review/review_loop.rs` (`run_review`) — dedup boundary; `StoreOp` application loop must fan an approve/block across all hash-equal views.
- Tests: new unit coverage in `src/trust/review/review_loop.rs` (scripted prompt asserting one prompt per unique hash) and an integration test in `tests/trust_integration.rs` exercising an OR-of-programs config.
- No CLI flags, no JSON schema changes, no trust-store format change.
- Bucket: `trust`.
