## 1. Behavioural pin

- [ ] 1.1 Inventory existing snapshot/integration tests covering `may-i trust` (listing, JSON, interactive review) and `may-i eval` / `may-i check` / hook trust paths. Note any gaps where stdout+stderr bytes are not pinned for the listing UIs that the unified view will drive.
- [ ] 1.2 Add a snapshot/integration test for the per-rule join: a config with one approved Loaded rule, one pending Loaded rule, one blocked Loaded rule, and one PrimaryConfig-only rule; `may-i trust --json` output pins the state-tag for each.

## 2. Introduce `TrustView` and `TrustCatalog` in `crate::trust`

- [ ] 2.1 Define `pub struct TrustView { hash, canonical_form, program, source_file, position, state }` and `pub enum TrustState { Approved, Blocked, Pending }` in `src/trust/mod.rs` (or a new `src/trust/view.rs`). Fields private; smart constructor `TrustView::from_meta_and_entry(meta, entry: Option<&RuleEntry>)` is `pub(crate)`.
- [ ] 2.2 Define `pub struct TrustCatalog(Vec<TrustView>)` with methods: `iter`, `group_by_program() -> BTreeMap<&str, Vec<&TrustView>>`, `untrusted_loaded() -> impl Iterator<Item = &TrustView>`, `find_by_hash(&str) -> Option<&TrustView>`, `set_state(hash: &str, state: TrustState)`.
- [ ] 2.3 Add `pub(crate) fn build_catalog(config: &Config, store: &TrustStore) -> TrustCatalog` in `src/trust/mod.rs`. Body: call the engine's per-rule metadata factory, look up each rule's hash in the store, construct a `TrustView` per rule. Property-test: every store entry whose hash is present in the config maps to a `TrustView` with matching state; every Loaded rule absent from the store gets `state = Pending`.
- [ ] 2.4 Add a property test asserting per-rule join is deterministic and total: for any `(Config, TrustStore)` pair, `build_catalog` returns one `TrustView` per `Loaded`-touched rule in the config, in the same order as the engine's per-rule metadata iteration.

## 3. Narrow the engine surface

- [ ] 3.1 In `crates/engine/src/trust.rs`, add `pub fn compute_trust_views(config: &Config) -> Vec<TrustViewMeta>` (or rename existing function) producing per-rule descriptors with `hash`, `canonical_form`, `program`, `source_file`, `position`. The engine SHALL NOT know about trust-store state — `TrustViewMeta` is the join input, not the joined output.
- [ ] 3.2 Downgrade `RuleMeta`, `ProgramMeta`, and `TrustHashes` to `pub(crate)` in `may_i_engine::trust`, or delete them if `compute_trust_views` subsumes their usage. Update `crates/engine/src/lib.rs` re-exports accordingly.
- [ ] 3.3 In `src/trust/mod.rs`, update `build_catalog` to call the new engine factory; remove any CLI-side dependency on `RuleMeta`/`ProgramMeta`/`TrustHashes`.
- [ ] 3.4 Grep audit: zero matches for `may_i_engine::trust::{RuleMeta` (or `ProgramMeta`, `TrustHashes`) outside `crates/engine/`.

## 4. Port `cmd_trust` to consume `TrustCatalog`

- [ ] 4.1 Update every function signature in `src/cmd_trust.rs` that currently takes `&TrustHashes` + `&BTreeMap<String, ProgramMeta>` + `&TrustStore` to take `&TrustCatalog` (or `&mut TrustCatalog` for approval paths). Affected: `list_status` family, `list_status_json`, `interactive_approve`, the grouped-by-file listing helper.
- [ ] 4.2 Replace per-rule store lookups (`store.check_rule(hash)` cross-referenced against `RuleMeta`) with reads of `TrustView.state`.
- [ ] 4.3 Replace per-program zip patterns (`by_program: BTreeMap<&str, Vec<&RuleMeta>>`) with `catalog.group_by_program()` returns; iterate `&TrustView` directly.
- [ ] 4.4 Replace approval mutations (`store.approve_rule(...)`, `store.block_rule(...)`) with `catalog.set_state(hash, state)` calls plus one explicit `store.save(path)` call per command invocation.
- [ ] 4.5 Confirm `cmd_trust` snapshot tests pass byte-for-byte.

## 5. Port `interactive.rs` to consume `TrustCatalog`

- [ ] 5.1 Update every function in `src/interactive.rs` that currently takes `&TrustHashes` + `&BTreeMap<String, ProgramMeta>` to take `&TrustCatalog` (or `&mut TrustCatalog`). Affected sites include the review-screen entry point, the trusted-summary builder, the pending-rule iterator, the approve/skip handler.
- [ ] 5.2 The progress-counter and trusted-summary-line code (per the `trust-command` spec's "Progress counter in HRule separator" and "Trusted summary line always visible" requirements) read counts off the catalog (`catalog.iter().filter(|v| v.state == TrustState::Approved).count()`, `….source_files().collect::<BTreeSet<_>>().len()`). No behavioural change.
- [ ] 5.3 Confirm `interactive` snapshot tests pass byte-for-byte.

## 6. Port `trust/gate.rs` and `trust/advisory.rs`

- [ ] 6.1 In `src/trust/gate.rs`, replace the rule-by-rule `store.check_rule(hash)` filter with a single `catalog.untrusted_loaded()` scan that drops the corresponding rules from the pipeline's `Config` in place. The single-store-load invariant (per `trust-gate` spec) is preserved: the pipeline builds one catalog per invocation and reuses it for filtering, advisory, and block decisions.
- [ ] 6.2 In `src/trust/advisory.rs`, replace the per-program zip of `ProgramMeta` + `TrustStore` with reads off `catalog.group_by_program()`. The advisory body's "files" list is `view.source_file` per untrusted view, deduplicated.
- [ ] 6.3 In `src/pipeline.rs`, replace the cached `TrustStore` with a cached `TrustCatalog`. The pipeline's `consult_trust` returns `Ok(())` or `Err(TrustBlock)` exactly as today; only the internal representation changes.
- [ ] 6.4 Confirm `trust-gate` and `trust-advisory-boxes` integration tests pass byte-for-byte. Single-store-load property test from the `deepen-trust-pipeline` change still passes (loader invoked at most once per invocation).

## 7. Delete or hide legacy types

- [ ] 7.1 Remove `pub use` of `RuleEntry` from `src/trust/mod.rs` and `src/lib.rs`. Downgrade `RuleEntry` to `pub(crate)` if any internal callers remain after the port; otherwise delete it (the JSON serde shape stays as a private on-disk struct on `TrustStore`).
- [ ] 7.2 Remove `pub use` of `TrustHashes`, `RuleMeta`, `ProgramMeta` from the engine surface. Delete the types if `compute_trust_views` fully replaces them; otherwise keep as `pub(crate)`.
- [ ] 7.3 Grep audit: zero matches for `RuleEntry`, `RuleMeta`, `ProgramMeta`, `TrustHashes` in `src/cmd_*.rs`, `src/interactive.rs`, `src/pipeline.rs`. Any remaining matches are inside `src/trust/` or `crates/engine/src/trust.rs` only.

## 8. Optional on-disk format bump (only if cleanup demands it)

- [ ] 8.1 Decide v3 vs v4 based on implementation feedback (see design.md Open Questions). Default: stay on v3. If v4 is chosen, document the rationale in the implementation commit message.
- [ ] 8.2 If v4: define the v4 on-disk shape on `TrustStore`. Add a v3→v4 read path that converts on load and writes back v4 on the next save.
- [ ] 8.3 If v4: register a v3→v4 migration step with the migration system (`src/migration/` or wherever the existing v2→v3 step lives) so `may-i migrate` rehashes via `crate::trust::rehash_after_migration`.
- [ ] 8.4 If v4: extend `trust-store` spec's "Trust store v3 format with per-rule entries" requirement with a v3→v4 scenario (this is a follow-on spec edit, NOT part of this change's delta — open a separate change for it).

## 9. Verify

- [ ] 9.1 `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`.
- [ ] 9.2 `cargo test --workspace`. All existing snapshot and integration tests pass without modification; investigate any drift before accepting.
- [ ] 9.3 `cargo tarpaulin`; inspect `lcov.info` for newly uncovered branches in `src/trust/view.rs` (or `mod.rs`), `src/trust/gate.rs`, `src/trust/advisory.rs`, and any new engine-side factory. Add proptests preferentially; fall back to surgical unit tests for hard-to-hit branches.
- [ ] 9.4 `openspec validate unify-trust-metadata --strict`.
- [ ] 9.5 Run `may-i trust` against a real config with a mix of approved/pending/blocked Loaded rules; confirm listing, JSON, and interactive review output is identical to pre-change behaviour.
- [ ] 9.6 Run `may-i eval` against a command for a Loaded program with both an integrity advisory and an untrusted-program warning; confirm prelude ordering (integrity first, warning second) is preserved.
- [ ] 9.7 Final grep audit: zero matches for `RuleMeta`, `ProgramMeta`, `TrustHashes`, `RuleEntry` outside `src/trust/` and `crates/engine/src/trust.rs`.
