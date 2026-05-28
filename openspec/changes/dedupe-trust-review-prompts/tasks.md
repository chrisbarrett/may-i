## 1. Red tests pinning the dedup behaviour

- [ ] 1.1 Add a unit test in `crates/engine/src/trust.rs` confirming `compute_trust_views` emits multiple views with identical `hash` and `canonical_form` for an OR-of-programs rule (documents the upstream condition the dedup defends against; not a regression assert).
- [ ] 1.2 Add a unit test in `src/trust/review/review_loop.rs` that drives `run_review` with two `PendingRule`s sharing the same hash and asserts the loop currently issues two prompts (red — will pass once the input is deduped upstream so the loop receives one).
- [ ] 1.3 Add a unit test in `src/interactive.rs` for `build_pending`: feed a `TrustCatalog` whose views contain a hash repeated twice, assert the returned `Vec<PendingRule>` has length 1, first-seen order preserved.
- [ ] 1.4 Add an integration test in `tests/trust_integration.rs` exercising `may-i trust` against a loaded config containing `(rule (or "git" "gh") (allow))` under a scripted prompt path (re-use the non-interactive batch path if a scripted TTY isn't available, or feed `--all` and assert the JSON `approved` list dedups correctly).

## 2. Catalog mutation fan-out

- [ ] 2.1 Change `TrustCatalog::set_state` in `src/trust/view.rs` from `find` to a `for v in self.views.iter_mut().filter(|v| v.hash == hash)` loop so a single hash transition updates every view sharing the hash.
- [ ] 2.2 Add a unit test in `src/trust/view.rs` proving the fan-out: catalog with two views sharing a hash → `set_state(hash, Approved)` → both views report `Approved`.

## 3. Dedup at the pending-rule boundary

- [ ] 3.1 In `src/interactive.rs::build_pending`, dedup the iteration by hash using a `BTreeSet<String>` (or `HashSet`) to skip hash-equal duplicates after the first, preserving first-seen order.
- [ ] 3.2 Confirm the unit tests from 1.2 and 1.3 now pass; confirm `compute_initial_trusted` is unaffected (still counts approved views at the catalog level, not the deduped review slice).

## 4. Verification

- [ ] 4.1 `cargo fmt`.
- [ ] 4.2 `cargo test -p may-i` and `cargo test -p may-i-engine` — all green, including the new tests.
- [ ] 4.3 `cargo tarpaulin` — confirm the new branches are covered; add targeted unit tests for any uncovered branch in `build_pending` or `set_state`.
- [ ] 4.4 Manual repro: write a temp config containing `(rule (or "git" "gh") (allow))`, run `may-i trust` interactively under a temp `XDG_DATA_HOME`, confirm exactly one prompt and that a follow-up invocation reports all trusted.
- [ ] 4.5 `openspec validate dedupe-trust-review-prompts --strict` — passes.
