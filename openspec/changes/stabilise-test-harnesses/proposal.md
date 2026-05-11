## Why

A recent transient CI failure in four repo-local discovery unit tests could not be reproduced after the fact. Investigation surfaced four real (or latent) sources of non-determinism in the test harness: the `init_git` helper produces an invalid git repo, integration tests inherit the workspace cwd (which is itself a git repo), the define-cycle detector iterates a `HashMap` (giving non-deterministic error messages), and the cross-test `env::set_var` contract in `trust_gate` relies on an undocumented module-local mutex. Fixing these tightens the harness so we stop chasing ghosts.

## What Changes

- `init_git` test helper writes a minimal but valid git repo (`.git/HEAD` + `.git/config`) so `git rev-parse --show-toplevel` cannot fall through to a parent repo.
- Integration-test harness (`tests/common/mod.rs::may_i`) sets the spawned `may-i` process's `current_dir` to an isolated temp directory so repo-local discovery does not walk into the workspace.
- `crates/config/src/resolve.rs::detect_cycles` iterates define names in a deterministic order so cycle error messages are reproducible across runs.
- Document the `ENV_LOCK` contract in `src/trust_gate.rs` so future env-mutating tests in the same binary opt in to the mutex rather than silently racing.

No user-facing behaviour changes. No CLI, config, or wire-format changes.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `test-infrastructure`: add requirements covering (1) valid git-repo fixtures, (2) integration-test cwd isolation, (3) deterministic validation error messages, and (4) the env-mutation locking contract.

## Impact

- `crates/config/src/io.rs` — `init_git` body; possibly `splice_repo_local` if we add a test hatch.
- `crates/config/src/resolve.rs` — `detect_cycles` iteration order.
- `tests/common/mod.rs` — `may_i()` helper sets `current_dir`.
- `src/trust_gate.rs` — comment documenting `ENV_LOCK` contract.
- No dependency changes. No public API changes.
