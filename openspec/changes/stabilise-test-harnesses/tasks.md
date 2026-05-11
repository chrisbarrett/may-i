## 1. Fix `init_git` fixture

- [ ] 1.1 Add a failing unit test that asserts `discover_repo_root` returns the tempdir even when `$TMPDIR` is itself inside another git repo (simulate by also writing a `.git/` two levels up in a controlled tempdir tree)
- [ ] 1.2 Update `crates/config/src/io.rs::init_git` (test helper) to also write `.git/HEAD` (`ref: refs/heads/main\n`) and `.git/config` (`[core]\n\trepositoryformatversion = 0\n`)
- [ ] 1.3 Confirm the new and existing repo-local tests pass with `cargo test -p may-i-config io::tests::`

## 2. Isolate integration-test cwd

- [ ] 2.1 Audit `tests/*.rs` for `cargo_bin_cmd!("may-i")` call sites that do not go through `tests/common/mod.rs::may_i()` and list them
- [ ] 2.2 In `tests/common/mod.rs`, update `may_i(config)` to call `.current_dir(std::env::temp_dir())` on the returned `Command`
- [ ] 2.3 Add a `tests/common/mod.rs::may_i_cmd()` helper for tests that don't need a `MAYI_CONFIG` (returns `Command` with isolated cwd only); migrate the audited call sites to use it
- [ ] 2.4 Verify any tests that *do* require a specific cwd (e.g., repo-local-discovery integration tests, if any) override with an explicit `.current_dir(...)` and add a one-line comment naming why
- [ ] 2.5 Run `cargo test` and confirm no regressions

## 3. Deterministic cycle errors

- [ ] 3.1 Add a unit test in `crates/config/src/resolve.rs` that constructs a graph with two cycles and runs `detect_cycles` 50 times, asserting the error message is byte-identical every run
- [ ] 3.2 In `detect_cycles`, collect `define_map.names()` into a `Vec`, sort with `sort_unstable`, then iterate
- [ ] 3.3 Also sort the `Vec<String>` neighbour lists pushed into `adjacency` so DFS visits neighbours in a stable order
- [ ] 3.4 Confirm the new property test passes and existing cycle-error tests still pass

## 4. Document `ENV_LOCK` contract

- [ ] 4.1 Add a doc comment above `static ENV_LOCK` in `src/trust_gate.rs` per design Decision 4
- [ ] 4.2 Add a one-line `// SAFETY: see ENV_LOCK contract above` reference at each `unsafe { env::set_var(...) }` / `env::remove_var(...)` call site in the same module

## 5. Validate

- [ ] 5.1 Run `cargo fmt` and `cargo test --workspace`
- [ ] 5.2 Run `prek` if configured locally; confirm the four originally-flaky tests pass 10× in a row under `cargo test -p may-i-config -- --test-threads=8 io::tests::`
- [ ] 5.3 Run `cargo tarpaulin` and inspect `lcov.info`; add property/unit tests for any uncovered branches introduced by the changes
