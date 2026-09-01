## 1. Document the command surface

- [ ] 1.1 Add a "Commands" section to `AGENTS.md` stating that every build, test,
      lint, and coverage command runs inside the pinned toolchain, and naming the
      dev-shell invocation (`nix develop --command …`). Note that a shell outside
      it fails with `E0554` on `crates/core/src/lib.rs:1`.
- [ ] 1.2 In that section, name the concrete command for each verification tier
      defined in `testing-strategy` — pre-commit, pre-push, release, nightly —
      and the affected-crate command (`cargo affected --staged test`,
      `cargo affected --staged clippy`) used for scoped runs.
- [ ] 1.3 Verify every command in the new section runs as written from a shell
      that has not entered the dev shell.

## 2. Build configuration

- [ ] 2.1 Add `.cargo/config.toml` at the repository root setting
      `[build] incremental = true` and `rustc-wrapper = ""`.
- [ ] 2.2 Confirm the override takes effect over a user-level
      `~/.cargo/config.toml` that sets `incremental = false` and a
      `rustc-wrapper`: build succeeds, and `target/debug/incremental/` is
      populated.
- [ ] 2.3 Add `CARGO_INCREMENTAL: "0"` to the workflow-level `env` block in
      `.github/workflows/ci.yml`, `.github/workflows/nightly.yml`, and
      `.github/workflows/release.yml`.
- [ ] 2.4 Record before/after wall times for a rebuild after touching
      `crates/engine/src/eval/decompose.rs` and after touching a leaf integration
      test file, to confirm the measured 2–4x holds.

## 3. zsh oracle

- [ ] 3.1 In `crates/shell-parser/tests/zsh_oracle.rs`, remove the hardcoded
      `cases: 512` from `proptest_config` so `ProptestConfig::default()` picks up
      `PROPTEST_CASES`, and set a compiled-in default sized for the pre-push tier.
- [ ] 3.2 Confirm `PROPTEST_CASES` now controls the count in both directions —
      a value below and a value above the default.
- [ ] 3.3 Pass `-f` to both `zsh` invocations (`zsh_available`, `zsh_accepts`) so
      the oracle does not source `/etc/zshenv` or the contributor's `~/.zshenv`.
- [ ] 3.4 Tighten `arb_statement` so the brace-group and function-definition
      arms emit only forms `zsh -n` accepts, removing the `semi=false` variants
      that `prop_assume!` currently discards. Keep `prop_assume!` as a backstop.
- [ ] 3.5 Confirm the rejection rate dropped: count `zsh` spawns per run before
      and after, expecting roughly one per case rather than ~4.
- [ ] 3.6 Set `PROPTEST_CASES` to the full sweep value (512) on the nightly
      workflow's job that runs the oracle, and confirm no other tier raises it.

## 4. Doctest harnesses

- [ ] 4.1 Confirm `cargo test --workspace --doc` reports zero tests across all
      eight workspace libraries.
- [ ] 4.2 Add `[lib] doctest = false` to the eight workspace library manifests.
- [ ] 4.3 Confirm `tarpaulin.toml` still carries
      `run-types = ["Lib", "Tests", "Doctests"]` and that `cargo tarpaulin` runs
      clean over the empty doctest set.

## 5. Consolidate integration test targets

- [ ] 5.1 Record the baseline: `cargo test --workspace -- --list` output and its
      test count, plus the per-target compile cost from
      `cargo build --workspace --all-targets --timings`. This is the reference
      the merge is checked against.
- [ ] 5.2 Inventory the checked-in artefacts whose lookup keys derive from target
      and module path — `insta` snapshots under `tests/snapshots/` and files
      under `proptest-regressions/` — and map each to the key it will have after
      the merge.
- [ ] 5.3 Create `tests/cli.rs` and move `check_integration`,
      `parse_integration`, `parse_diagnostics_integration`, `eval_stdin`,
      `eval_defines`, `fmt_integration`, `hook_integration`, `load_directive`,
      `local_function_calls`, `undeclared_long_flag_arity`, and
      `migrate_flag_smoke` into it as modules.
- [ ] 5.4 Create `tests/eval.rs` and move `unified_eval_integration`,
      `binding_recursion`, `carrier_hardening`, `wrapper_tail_scoping`,
      `flag_and_parameter`, `double_dash_boundary`,
      `quantifier_sequence_groups`, `segment_decisions_fixtures`, and
      `display_safe_boundary` into it as modules.
- [ ] 5.5 Create `tests/render.rs` and move `pretty_print_snapshots`,
      `shape_mismatch_snapshots`, `parse_diagnostic_snapshots`,
      `trace_rule_shape`, `migrated_v1_trace`, and `parser_dsl` into it as
      modules.
- [ ] 5.6 Create `tests/trust.rs` and move `trust_integration`, `trust_rehash`,
      and `audit_integration` into it as modules.
- [ ] 5.7 Create `tests/migrate.rs` and move `migrate_integration`,
      `migration_diff`, and `migrate_load_graph` into it as modules.
- [ ] 5.8 Reduce `tests/common/mod.rs` to one `mod common` declaration per
      consolidated target, and delete the 32 original test files.
- [ ] 5.9 Relocate the snapshot and regression artefacts identified in 5.2 to
      their new keys. Confirm no snapshot is newly created and no regression seed
      is newly orphaned — `cargo insta test --check` and a clean
      `proptest-regressions/` diff.

## 6. Verification

- [ ] 6.1 Confirm the test count from `cargo test --workspace -- --list` matches
      the 5.1 baseline exactly, and that no test was left `#[ignore]`d by the
      merge.
- [ ] 6.2 Confirm `tests/` in the `may-i` crate contains no more than six
      integration test targets.
- [ ] 6.3 Re-run `cargo build --workspace --all-targets --timings` over clean
      workspace crates and record the new total CPU-seconds against the 178
      baseline.
- [ ] 6.4 Record the new `cargo test --workspace` wall time against the 65s
      baseline, at the default oracle case count.
- [ ] 6.5 Run the full pre-push tier — `cargo clippy --workspace --all-targets
      -- -D warnings` and `cargo test --workspace` — clean.
- [ ] 6.6 Run `cargo fmt --all`, then `openspec validate fast-iteration-loop
      --strict --no-interactive`, `scripts/validate-spec-frontmatter.sh`, and
      `scripts/validate-change-doc-sync.sh`.
- [ ] 6.7 Confirm CI is green on the branch, including that the CI jobs build
      with `CARGO_INCREMENTAL=0`.
