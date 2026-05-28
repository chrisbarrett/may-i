## Context

Current verification layout (today):

- `prek.toml` pre-commit: fmt-check, affected build/clippy/test, openspec
  validation. Fast, scoped to staged crates.
- `prek.toml` pre-push: full build, full clippy, `cargo tarpaulin`
  (`run-types = ["Lib"]`), nix build. Heavy — minutes per push.
- `.github/workflows/ci.yml`: fmt-check, clippy, full `cargo test
  --workspace`. Runs on every push to `main` and every PR. Largely
  duplicates pre-push.
- `.github/workflows/release.yml`: triggered on `v*` tag. Per target
  (4 platforms): checkout, build release, **re-run** `cargo test
  --release --workspace`, package, upload. Then create GitHub release.
- Fuzz targets (`fuzz/fuzz_targets/fuzz_evaluator.rs`) exist but never
  run automatically — corpus only grows when a contributor remembers.
- Release tagging is manual: edit `Cargo.toml`, commit, `git tag`,
  `git push`. No enforcement that the suite passed against the tagged
  commit.

Three observations drive this change:

1. Tarpaulin in pre-push slows every push, not just release-bound ones.
   The work it does (instrumented test run + coverage gate) is only
   actionable at release time — between releases, sub-85% coverage is a
   warning, not a blocker.
2. Tarpaulin's `Lib`-only run-types skip integration + doc tests, so
   pre-push doesn't actually replace the CI `cargo test --workspace`
   pass. Both are needed and both run, hence duplicate work.
3. The release tag-and-bump flow has no atomic checkpoint. If the bump
   commit lands but the tag push fails (or the suite was never run),
   `main` carries a published-looking version without the verification
   contract.

## Goals / Non-Goals

**Goals:**

- One heavy verification pass per release, not three.
- Failures detected and corrected **before** any commit, tag, or push
  mutates state.
- Fuzz target exercised on every release path; corpus grows
  predictably.
- Ordinary `git push` stays fast (sub-minute target on warm cache).
- Release tag only exists on a commit whose suite passed.

**Non-Goals:**

- Migrating CI off GitHub Actions or restructuring the matrix beyond
  removing `cargo test` from `release.yml`.
- Cross-platform proptest coverage. macOS/Linux parity is not currently
  a release gate; if it becomes one, that's a separate change.
- Replacing `prek` with another hook runner.
- Automating the version-string choice (semver bump policy stays a
  human decision; the script accepts the version as an argument).

## Decisions

### Decision 1: Heavy gate lives in `scripts/release.sh`, not pre-push

The pre-push hook will run on every push, including topic branches and
WIP work. Tarpaulin + fuzz at that cadence is wasted time. A
release-only script runs the heavy suite exactly when it matters.

**Alternatives considered:**

- *Keep tarpaulin in pre-push, accept the slowdown.* Rejected: the cost
  is paid on every push, and the recovery story after a failed release
  push is worse — the bump commit has already landed locally and the
  push has been rejected, leaving the contributor to `git reset` and
  retry.
- *Run heavy gate in CI only, trust GitHub Actions to gate the tag.*
  Rejected: requires a tag-creation workflow that depends on CI green,
  which is buildable but more moving parts (workflow_run triggers,
  branch protection rules) than a local script. Also pushes feedback
  loop from local-minutes to CI-minutes-plus-queue.
- *Use `cargo-release` directly.* Rejected for now: `cargo-release`'s
  pre-release-hook is a single command, harder to express the
  fail-before-mutate ordering and the resumable checkpoints we want.
  Could revisit once the script stabilises.

### Decision 2: Verify-then-mutate ordering inside the script

The script runs *all* verification (fmt, clippy, tarpaulin, fuzz, nix
build) before touching `Cargo.toml`. Any failure exits with a clean
working tree; the contributor fixes the issue and re-runs.

Mutations happen in a strict order: bump `Cargo.toml` → `cargo check`
to refresh `Cargo.lock` → commit → tag → `git push origin main` → `git
push origin v$VERSION`. Each step is idempotent enough to resume from:
if the final tag push fails (network), re-running `git push origin
v$VERSION` finishes the job.

**Alternatives considered:**

- *Bump first, verify second.* Standard `cargo-release` ordering, but
  inverts the failure-recovery contract: a failed verification means
  rolling back a commit. Rejected.
- *Interleaved (bump, build, test, tag).* Rejected on the same grounds
  with more failure surfaces.

### Decision 3: Drop `cargo test --release` from `release.yml`

By the time a tag is pushed, `scripts/release.sh` has already run the
suite locally on the exact commit the tag points at. Re-running tests
per platform in `release.yml` adds 4× test latency for one signal:
that the *release profile* didn't regress. In practice
`cargo test --release` has never caught a bug `cargo test` missed on
this codebase. Build-and-package only.

**Alternatives considered:**

- *Keep `cargo test --release` per platform.* Rejected: cost > signal.
- *Add a cross-platform test matrix to `ci.yml` instead.* Worth doing
  eventually but out of scope. Filed as an open question.

### Decision 4: Tarpaulin run-types widened to `Lib + Tests + Doctests`

Currently `tarpaulin.toml` runs `Lib` only. The release-time tarpaulin
pass is now the *only* place full test verification happens, so it
must execute integration + doctests. Widening run-types lets the
tarpaulin invocation replace the separate `cargo test --workspace`
that pre-push used to do via duplication.

Pre-push retains a plain `cargo test --workspace` (no instrumentation)
so contributors get a fast pre-push test signal without paying for
coverage instrumentation.

**Cite:** `tarpaulin.toml:3` (`run-types = ["Lib"]` today),
`Cargo.toml` workspace members include integration tests under
`tests/` which are excluded from `Lib`-only runs.

### Decision 5: Time-boxed fuzz in the release gate; longer fuzz nightly

Release-gate fuzz: `cargo +nightly fuzz run fuzz_evaluator --
-max_total_time=60`. One minute is enough to replay the corpus and
catch obvious regressions without inflating release time.

Nightly fuzz: `-max_total_time=600` (10 min) via a new
`.github/workflows/nightly.yml` workflow. Failures surface as
non-blocking GitHub issues or notification — they don't gate
contributor work, but they do grow the corpus and catch slow-burn
bugs.

**Alternatives considered:**

- *Skip fuzz entirely until manually invoked.* Status quo, rejected —
  the corpus stagnates.
- *Run fuzz in every CI build.* Rejected: nondeterministic, slow, and
  would gate PRs on a noisy signal.

### Decision 6: Nightly job runs tarpaulin too, non-blocking

If coverage drops below 85% between releases, contributors should know
before the next release rather than discovering it in the middle of
cutting a release. Nightly workflow runs `cargo tarpaulin` against
`main` and posts a summary; doesn't block anything.

## Risks / Trade-offs

- **Risk:** A contributor sidesteps `scripts/release.sh`, manually edits
  `Cargo.toml`, tags, and pushes. The tag could point at an unverified
  commit. → Mitigation: `release.yml` packages and publishes anyway —
  the contract is enforced by convention, not by CI. Document the path
  in `CLAUDE.md` and surface a clear error if `cargo-release`-style
  signals are missing. Future hardening: a tag-protection workflow
  that requires CI green before the release job runs.

- **Risk:** Pre-push gets slimmer, so a contributor pushes a branch
  with broken doctests; CI catches it on PR. → Mitigation: acceptable.
  Pre-push runs `cargo test --workspace` which covers integration
  tests; only doctests are skipped (rare in this codebase). CI catches
  doctest regressions in seconds.

- **Risk:** `cargo +nightly fuzz` requires nightly toolchain on the
  contributor machine. → Mitigation: gate fuzz step in `release.sh`
  on `command -v cargo-fuzz` and `rustup toolchain list | grep
  nightly`; print a clear error with the install command if missing.
  Document the requirement in `CLAUDE.md`.

- **Trade-off:** Releases now require a clean working tree and being
  in sync with `origin/main`. Contributors who cut releases from dirty
  branches lose that workflow. Accepted: dirty-tree releases are an
  anti-pattern anyway.

- **Trade-off:** Nightly workflow adds GitHub Actions cost. Project is
  small enough that this is negligible; if it becomes an issue, the
  nightly tarpaulin can drop to weekly.

## Migration Plan

1. Land `scripts/release.sh` and the prek.toml/tarpaulin.toml changes
   in one commit. Cut the next release using the new script to smoke-
   test it end-to-end.
2. After the first successful run, strip `cargo test --release` from
   `release.yml` and add `.github/workflows/nightly.yml`.
3. Update `CLAUDE.md` release section to point at `scripts/release.sh`.

No rollback is needed — the old manual flow still works if
`release.sh` is bypassed; the change is additive at the boundary.

## Open Questions

- Should `release.sh` enforce semver discipline (reject `v1.0.0` if
  current is `v0.5.x` without explicit `--major`)? Out of scope for
  this change; mention only.
- Should we add a cross-platform CI matrix (macOS + Linux test runs on
  PR) to compensate for dropping `cargo test --release` from
  `release.yml`? Defer — current single-OS CI has been sufficient.
