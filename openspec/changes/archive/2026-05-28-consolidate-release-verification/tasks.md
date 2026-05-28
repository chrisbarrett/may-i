## 1. Release driver script

- [x] 1.1 Create `scripts/release.sh` with `set -euo pipefail` and a single positional `<version>` argument
- [x] 1.2 Implement precondition checks: clean working tree, current branch is `main`, local `main` matches `origin/main` after fetch
- [x] 1.3 Implement tooling preflight: detect missing `cargo-fuzz` or nightly toolchain and exit with an install hint before any mutation
- [x] 1.4 Implement verification block: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo tarpaulin`, `cargo +nightly fuzz run fuzz_evaluator -- -max_total_time=60`, `nix build .#default --no-link`
- [x] 1.5 Implement mutation block in strict order: rewrite `version` in `Cargo.toml`, run `cargo check` to refresh `Cargo.lock`, `git add` both, `git commit -m "Release v$VERSION"`, `git tag -a "v$VERSION" -m "v$VERSION"`, push branch then tag
- [x] 1.6 `chmod +x scripts/release.sh`
- [x] 1.7 Add `--dry-run` flag that runs preconditions + verification and exits before mutation, so the script can be smoke-tested on a real release-eligible state before cutting the tag

## 2. Tarpaulin and pre-push hook adjustments

- [x] 2.1 Update `tarpaulin.toml` `run-types` to `["Lib", "Tests", "Doctests"]`
- [x] 2.2 Remove the `cargo-test-full` hook (the tarpaulin entry) from `prek.toml` pre-push stage
- [x] 2.3 Add a plain `cargo-test-full` hook to `prek.toml` pre-push stage that runs `cargo test --workspace` without instrumentation
- [x] 2.4 Confirm pre-push hook set is now: `cargo-build-full`, `cargo-clippy-full`, `cargo-test-full` (plain), `nix-build`

## 3. Release workflow simplification

- [x] 3.1 Remove the `cargo test --release --workspace` step from each per-target job in `.github/workflows/release.yml`
- [x] 3.2 Verify the per-target job sequence is: checkout, toolchain, cache, build, package, upload

## 4. Nightly verification workflow

- [x] 4.1 Create `.github/workflows/nightly.yml` with a `schedule` trigger (cron, daily) and `workflow_dispatch` for manual runs
- [x] 4.2 Add a tarpaulin job that runs `cargo tarpaulin` against latest `main`
- [x] 4.3 Add a fuzz job that runs `cargo +nightly fuzz run fuzz_evaluator -- -max_total_time=600` and uploads any new crash artefacts as a workflow artefact
- [x] 4.4 Ensure neither job is referenced from branch-protection-required checks (no branch protection currently configured — vacuously satisfied)

## 5. Documentation

- [x] 5.1 Update the `# Release tagging` section of `CLAUDE.md` to instruct contributors to run `scripts/release.sh <version>` and describe the verify-before-mutate ordering (edited via the `AGENTS.md` symlink target)
- [x] 5.2 Note the nightly workflow's purpose (non-blocking coverage + fuzz signal) and where its results appear

## 6. Verification

- [x] 6.1 Smoke-test the verification block: standalone `cargo tarpaulin` exercises the widened `Lib + Tests + Doctests` configuration; argc help, precondition (`require_clean_tree`) and tooling preflight paths verified by direct invocation. Full `scripts/release.sh --dry-run` will be run immediately before the next real tag (it requires a clean main in sync with `origin/main` by design, so it cannot be smoke-tested from the same branch that introduces the script).
- [x] 6.2 Run `prek run --hook-stage pre-push --all-files` to confirm slimmed pre-push hooks pass on a clean tree
- [ ] 6.3 Trigger `nightly.yml` via `workflow_dispatch` once and confirm both jobs complete and report results to the Actions UI — deferred: requires the workflow to land on `main` first; run after merge.
- [x] 6.4 Run `openspec validate consolidate-release-verification --strict` and confirm zero errors
