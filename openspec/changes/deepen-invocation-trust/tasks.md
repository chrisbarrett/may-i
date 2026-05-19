## 1. Move the single-load test from pipeline to trust

- [ ] 1.1 In `src/trust/mod.rs` (or a new `src/trust/invocation.rs` once the type exists), add a failing test `invocation_trust_loads_store_once` that builds an `InvocationTrust::with_loader(false, counting_loader)`, calls `render_prelude(&loaded, …)` + `consult(&mut loaded, "git status", TrustMode::Hook)` + `render_warning(…)`, and asserts the loader counter is `1`. Currently won't compile.
- [ ] 1.2 Add a failing `invocation_trust_prelude_is_idempotent` test asserting three `render_prelude` calls produce exactly one loader invocation and one rendered byte sequence.
- [ ] 1.3 Add a failing `invocation_trust_json_mode_skips_prelude` test asserting `InvocationTrust::with_loader(true, counting_loader).render_prelude(...)` invokes the loader zero times.

## 2. Define `InvocationTrust`

- [ ] 2.1 Create `src/trust/invocation.rs` (or extend `src/trust/mod.rs`) with the struct defined in design D1: private fields `loader`, `json`, `catalog: Option<InvocationCatalog>`, `attempted`, `prelude_rendered`, `warning_rendered`.
- [ ] 2.2 Add a private `InvocationCatalog` struct holding `catalog: TrustCatalog`, `suspects: Vec<SuspectEntry>`, `was_corrupt: bool`, `store_path: PathBuf` (lifted from today's `TrustCatalogState`).
- [ ] 2.3 Implement `InvocationTrust::new(json: bool) -> Self` wiring `default_store_loader` as the loader.
- [ ] 2.4 Implement `InvocationTrust::with_loader(json: bool, loader: StoreLoader) -> Self`.
- [ ] 2.5 Implement private `fn ensure_loaded(&mut self, config: &may_i_core::ast::Config)` — once-only loader invocation that builds `InvocationCatalog` via `build_catalog` and stores it in `self.catalog`.

## 3. Move free fns onto `InvocationTrust`

- [ ] 3.1 Migrate `trust::render_integrity_advisories` body into a private `InvocationTrust::render_integrity(&self, term, stderr)`.
- [ ] 3.2 Migrate `trust::build_warning_advisory` body into a private `InvocationTrust::build_warning(&self) -> Option<Layout>`.
- [ ] 3.3 Migrate `trust::filter_untrusted` body into a private `InvocationTrust::filter_untrusted(&self, config: &mut Config)`.
- [ ] 3.4 Migrate `trust::check_block` body into a private `InvocationTrust::check_block(&self, command, mode) -> Option<TrustBlock>`.
- [ ] 3.5 Migrate `trust::migration_note` body into a public `InvocationTrust::migration_note(&self, loaded: &LoadResult) -> Option<Layout>` (still publicly reachable; useful for tests and for the migration-note advisory renderer).
- [ ] 3.6 Migrate `trust::default_store_loader` into a private free fn next to `InvocationTrust::new`.

## 4. Define the three public methods

- [ ] 4.1 Implement `InvocationTrust::consult(&mut self, loaded: &mut LoadResult, command: &str, mode: TrustMode) -> Result<(), TrustBlock>`: calls `ensure_loaded(&loaded.config)`; if `check_block` returns `Some(block)`, return `Err(block)`; otherwise call `filter_untrusted(&mut loaded.config)` and return `Ok(())`.
- [ ] 4.2 Implement `InvocationTrust::render_prelude(&mut self, loaded: &LoadResult, term: &Terminal, stderr: &mut impl Write)`: respect `self.json` and `self.prelude_rendered` for idempotency; on first text-mode call, write `migration_note(loaded)` (if any) then `render_integrity(...)`; ensure the loader has been invoked even when the prelude is empty so the once-only invariant is observable from the JSON-mode test.
- [ ] 4.3 Implement `InvocationTrust::render_warning(&mut self, term: &Terminal, stderr: &mut impl Write)`: respect `self.json` and `self.warning_rendered`; on first text-mode call, write the result of `build_warning()` (when `Some`).
- [ ] 4.4 Verify the failing tests from §1 now pass.

## 5. Reshape `CommandPipeline`

- [ ] 5.1 Replace the four trust-related fields (`store_loader`, `catalog_cache`, `catalog_attempted`, `prelude_rendered`, `trust_warning_rendered`) with one `trust: InvocationTrust` field.
- [ ] 5.2 Replace `CommandPipeline::load(path, json)` body so it constructs `InvocationTrust::new(json)` and stores it on the new field.
- [ ] 5.3 Add `CommandPipeline::with_trust(loaded: LoadResult, json: bool, trust: InvocationTrust) -> Self` (the test constructor); delete `with_store_loader`.
- [ ] 5.4 Reshape `render_prelude_advisories` to `self.trust.render_prelude(&self.loaded, &self.terminal, &mut io::stderr())`.
- [ ] 5.5 Reshape `consult_trust` to `self.trust.consult(&mut self.loaded, command, mode)`.
- [ ] 5.6 Reshape `render_trust_warning` to `self.trust.render_warning(&self.terminal, &mut io::stderr())`.
- [ ] 5.7 Delete `ensure_trust_loaded`.
- [ ] 5.8 Update the pipeline tests (`store_loads_once_per_invocation`, `prelude_is_idempotent`, `json_mode_prelude_is_noop`) to either move to §1's trust-level tests entirely or remain as one thin integration test asserting the pipeline forwards correctly to `InvocationTrust`.

## 6. Tighten the public surface under `src/trust/`

- [ ] 6.1 Remove `pub` from `trust::migration_note`, `trust::render_integrity_advisories`, `trust::build_warning_advisory`, `trust::filter_untrusted`, `trust::check_block`, `trust::default_store_loader` once §3–§5 land — they are no longer reached from outside the module.
- [ ] 6.2 Remove `TrustStoreState` and `TrustCatalogState` from `pub` exports if they survive (the loader return type stays as `TrustStoreState`, but it becomes `pub(crate)` or `pub(super)`).
- [ ] 6.3 Confirm the `cmd_trust` carve-out still compiles — it should only consume `TrustStore`, `TrustCatalog`, `TrustView`, `TrustState`, and `build_catalog` directly, all of which remain public.

## 7. Verification

- [ ] 7.1 `cargo fmt`
- [ ] 7.2 `cargo check --workspace --all-targets`
- [ ] 7.3 `cargo test --workspace` — all green.
- [ ] 7.4 Grep guard: `! rg --no-messages 'pipeline\.store_loader|catalog_attempted|trust_warning_rendered|prelude_rendered: bool' src/` returns no hits.
- [ ] 7.5 Grep guard: `rg --no-messages 'InvocationTrust' src/` shows definitions in `src/trust/` and references in `src/pipeline.rs` plus tests — no scattered consumers.
- [ ] 7.6 Manual smoke: `cargo run -- eval "echo hi"` and `cargo run -- eval --json "echo hi"` produce byte-identical output before and after. `echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"}}' | cargo run --quiet --` produces the same hook envelope. `cargo run -- check` runs cleanly. Run against a config containing untrusted Loaded rules to exercise advisory paths.
- [ ] 7.7 `cargo tarpaulin` (per `CLAUDE.md`): coverage on `src/trust/` and `src/pipeline.rs` does not regress against the `lcov.info` baseline.
- [ ] 7.8 `openspec validate deepen-invocation-trust` passes.
