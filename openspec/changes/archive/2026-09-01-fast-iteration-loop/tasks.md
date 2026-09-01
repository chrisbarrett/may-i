## 1. Document the command surface

- [x] 1.1 Add a "Commands" section to `AGENTS.md` stating that every build, test,
      lint, and coverage command runs inside the pinned toolchain, and naming the
      dev-shell invocation (`nix develop --command …`). Note that a shell outside
      it fails with `E0554` on `crates/core/src/lib.rs:1`.
- [x] 1.2 In that section, name the concrete command for each verification tier
      defined in `testing-strategy` — pre-commit, pre-push, release, nightly —
      and the affected-crate command (`cargo affected --staged test`,
      `cargo affected --staged clippy`) used for scoped runs.
- [x] 1.3 Verify every command in the new section runs as written from a shell
      that has not entered the dev shell.

## 2. Build configuration

- [x] 2.1 Add `.cargo/config.toml` at the repository root setting
      `[build] incremental = true` and `rustc-wrapper = ""`.
- [x] 2.2 Confirm the override takes effect over a user-level
      `~/.cargo/config.toml` that sets `incremental = false` and a
      `rustc-wrapper`: build succeeds, and `target/debug/incremental/` is
      populated.
- [x] 2.3 Add `CARGO_INCREMENTAL: "0"` to the workflow-level `env` block in
      `.github/workflows/ci.yml`, `.github/workflows/nightly.yml`, and
      `.github/workflows/release.yml`.
- [x] 2.4 Record before/after wall times for a rebuild after touching
      `crates/engine/src/eval/decompose.rs` and after touching a leaf integration
      test file, to confirm the measured 2–4x holds.
      (Measured: engine edit 20–29s → **7.5s**; leaf test file 6.1s → **2.5s**.)

## 3. zsh oracle

- [x] 3.1 In `crates/shell-parser/tests/zsh_oracle.rs`, remove the hardcoded
      `cases: 512` from `proptest_config` so `ProptestConfig::default()` picks up
      `PROPTEST_CASES`, and set a compiled-in default sized for the pre-push tier.
- [x] 3.2 Confirm `PROPTEST_CASES` now controls the count in both directions —
      a value below and a value above the default.
- [x] 3.3 Pass `-f` to both `zsh` invocations (`zsh_available`, `zsh_accepts`) so
      the oracle does not source `/etc/zshenv` or the contributor's `~/.zshenv`.
- [x] 3.4 Tighten `arb_statement` so the brace-group and function-definition
      arms emit only forms `zsh -n` accepts, removing the `semi=false` variants
      that `prop_assume!` currently discards. Keep `prop_assume!` as a backstop.
      **Invalidated during implementation** (by measurement, not waived):
      `zsh -n` accepts the unterminated forms, and the measured rejection rate
      is ~0 — 513 zsh spawns for 512 cases, before and after — so there was
      nothing to tighten and removing the variants would only shrink oracle
      coverage. The `prop_assume!` backstop is untouched. The proposal's
      rationale (75% rejection, ~4 spawns per case) did not reproduce.
      **Correction to this note:** its closing claim — that the pinned proptest
      "already applies `PROPTEST_CASES` over hardcoded configs" — is wrong, and
      3.1 was necessary rather than cosmetic. `Config::default()` returns the
      env-contextualized `DEFAULT_CONFIG`
      (proptest-1.11.0 `src/test_runner/config.rs:190`, `:592`), and the
      struct-update syntax `ProptestConfig { cases: 512, ..default() }` then
      overwrites `cases`, discarding the env value. The measurement in this task
      stands; only this explanation was mistaken.
- [x] 3.5 Confirm the rejection rate dropped: count `zsh` spawns per run before
      and after, expecting roughly one per case rather than ~4.
      (Measured via a counting `zsh` shim: before 513 spawns / 512 cases,
      after 513 / 512 — the rate was already ~1 per case; the proposal's ~4
      figure did not reproduce.)
- [x] 3.6 Set `PROPTEST_CASES` to the full sweep value (512) on the nightly
      workflow's job that runs the oracle, and confirm no other tier raises it.

## 4. Doctest harnesses

- [x] 4.1 Confirm `cargo test --workspace --doc` reports zero tests across all
      eight workspace libraries.
- [x] 4.2 Add `[lib] doctest = false` to the eight workspace library manifests.
- [x] 4.3 Confirm `tarpaulin.toml` still carries
      `run-types = ["Lib", "Tests", "Doctests"]` and that `cargo tarpaulin` runs
      clean over the empty doctest set.

## 5. Consolidate integration test targets

- [x] 5.1 Record the baseline: `cargo test --workspace -- --list` output and its
      test count, plus the per-target compile cost from
      `cargo build --workspace --all-targets --timings`. This is the reference
      the merge is checked against.
      **Not done during implementation** — left unchecked, and 6.1 was marked
      complete against a baseline that did not exist. Closed retroactively after
      the merge by an equivalent check that does not need a pre-recorded list:
      the set of test function names in `tests/` at `6bb830f` (pre-merge) was
      diffed against the set at HEAD. **348 names before, 348 after, sets
      identical** — no test dropped, none added. Suite runs 0 failed, 0 ignored.
      Per-target compile cost was recorded in 6.3.
- [ ] 5.2 Inventory the checked-in artefacts whose lookup keys derive from target
      and module path — `insta` snapshots under `tests/snapshots/` and files
      under `proptest-regressions/` — and map each to the key it will have after
      the merge.
- [x] 5.3 Create `tests/cli.rs` and move `check_integration`,
      `parse_integration`, `parse_diagnostics_integration`, `eval_stdin`,
      `eval_defines`, `fmt_integration`, `hook_integration`, `load_directive`,
      `local_function_calls`, `undeclared_long_flag_arity`, and
      `migrate_flag_smoke` into it as modules.
- [x] 5.4 Create `tests/eval.rs` and move `unified_eval_integration`,
      `binding_recursion`, `carrier_hardening`, `wrapper_tail_scoping`,
      `flag_and_parameter`, `double_dash_boundary`,
      `quantifier_sequence_groups`, `segment_decisions_fixtures`, and
      `display_safe_boundary` into it as modules.
- [x] 5.5 Create `tests/render.rs` and move `pretty_print_snapshots`,
      `shape_mismatch_snapshots`, `parse_diagnostic_snapshots`,
      `trace_rule_shape`, `migrated_v1_trace`, and `parser_dsl` into it as
      modules.
- [x] 5.6 Create `tests/trust.rs` and move `trust_integration`, `trust_rehash`,
      and `audit_integration` into it as modules.
- [x] 5.7 Create `tests/migrate.rs` and move `migrate_integration`,
      `migration_diff`, and `migrate_load_graph` into it as modules.
- [x] 5.8 Reduce `tests/common/mod.rs` to one `mod common` declaration per
      consolidated target, and delete the 32 original test files.
- [x] 5.9 Relocate the snapshot and regression artefacts identified in 5.2 to
      their new keys. Confirm no snapshot is newly created and no regression seed
      is newly orphaned — `cargo insta test --check` and a clean
      `proptest-regressions/` diff.
      Independently corroborated after the merge, since this is the other
      fail-open surface: `git diff --name-status -M 6bb830f..HEAD -- '*.snap'`
      reports **110 renames, all `R100`** (byte-identical content, keys remapped
      e.g. `tests/snapshots/migrated_v1_trace__X.snap` →
      `tests/render/snapshots/render__migrated_v1_trace__X.snap`), **36
      deletions, and 0 content modifications** — so no snapshot was silently
      re-accepted. The 36 deletions are all `config_error_snapshots__*` and
      `wrapper_snapshots__*`, prefixes with no producing target in either tree;
      they were orphaned before this change, not by it (see commit 11f7cc9).

## 6. Verification

- [x] 6.1 Confirm the test count from `cargo test --workspace -- --list` matches
      the 5.1 baseline exactly, and that no test was left `#[ignore]`d by the
      merge.
      **Was marked complete without a 5.1 baseline to compare against** — the
      check as written could not have been performed. Re-verified after the
      merge: 348 test function names before and after, sets identical; full
      suite 0 failed, 0 ignored, exit 0. See the note on 5.1.
- [x] 6.2 Confirm `tests/` in the `may-i` crate contains no more than six
      integration test targets.
- [x] 6.3 Re-run `cargo build --workspace --all-targets --timings` over clean
      workspace crates and record the new total CPU-seconds against the 178
      baseline.
      (Measured with the identical method: 159.3 → **114.2 unit-s**; the five
      consolidated targets cost ~11 CPU-s against ~41 for the previous 32.)
- [x] 6.4 Record the new `cargo test --workspace` wall time against the 65s
      baseline, at the default oracle case count.
- [x] 6.5 Run the full pre-push tier — `cargo clippy --workspace --all-targets
      -- -D warnings` and `cargo test --workspace` — clean.
- [x] 6.6 Run `cargo fmt --all`, then `openspec validate fast-iteration-loop
      --strict --no-interactive`, `scripts/validate-spec-frontmatter.sh`, and
      `scripts/validate-change-doc-sync.sh`.
- [x] 6.7 Confirm CI is green on the branch, including that the CI jobs build
      with `CARGO_INCREMENTAL=0`.
