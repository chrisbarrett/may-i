# test-infrastructure Specification

## Purpose

Contributor-only. Shared integration-test helpers (`tests/common/mod.rs`) and the thread-safe contract for tests that mutate process-global environment variables.

## Requirements

### Requirement: Shared integration test helpers
Integration test files SHALL share common helper functions via a `tests/common/mod.rs` module rather than duplicating them.

#### Scenario: Helper functions used across test files
- **WHEN** multiple integration test files need write_config or bash_payload helpers
- **THEN** they SHALL import from tests/common/mod.rs

### Requirement: Thread-safe environment variable tests
Tests that manipulate environment variables SHALL use thread-safe mechanisms (e.g., temp_env crate) rather than unsafe direct env::set_var calls.

#### Scenario: Config path tests run in parallel
- **WHEN** config path resolution tests run concurrently
- **THEN** they SHALL not interfere with each other's environment state

### Requirement: Valid git-repo fixtures for discovery tests
Test helpers that create a `.git` marker to exercise repository-root discovery SHALL write enough of a git repository (at minimum `.git/HEAD` and `.git/config`) for `git rev-parse --show-toplevel` to recognise the directory as a valid repo, rather than relying on `git`'s tolerance of an empty `.git/` directory.

#### Scenario: `init_git` produces a repo git accepts
- **WHEN** a test calls the local `init_git(path)` helper to set up a discovery fixture
- **THEN** running `git rev-parse --show-toplevel` from `path` SHALL return `path`, regardless of git version or filesystem timing

#### Scenario: Discovery does not fall through to an ancestor repo
- **WHEN** a tempdir created under `$TMPDIR` is initialised with `init_git` and `$TMPDIR` itself lives below another git repo
- **THEN** `discover_repo_root(tempdir)` SHALL return the tempdir, not the ancestor repo

### Requirement: Integration-test cwd isolation
Integration tests that spawn the `may-i` binary via `assert_cmd` SHALL set the child process's working directory to a location outside any git repository, so that repo-local config discovery does not run against the workspace.

#### Scenario: Spawned `may-i` does not discover workspace as repo root
- **WHEN** an integration test invokes the `may-i` binary without explicitly overriding `current_dir`
- **THEN** the child's cwd SHALL be a directory with no ancestor `.git`, `.hg`, or `.jj` marker, so `discover_repo_root` returns `None`

#### Scenario: Tests that need a specific cwd opt in
- **WHEN** an integration test asserts behaviour that depends on a specific repo-local discovery cwd
- **THEN** it SHALL explicitly call `.current_dir(...)` on the command, overriding the default isolation, AND the test SHALL document why

### Requirement: Deterministic validation error messages
Validation routines whose error messages name specific entities (e.g., the `a -> b` pair in a cyclic-define error) SHALL produce the same message bytes across runs given the same input, so that tests and snapshots remain stable.

#### Scenario: Cycle detection picks a stable starting node
- **WHEN** define-cycle detection runs over the same set of defines twice
- **THEN** the error message SHALL be byte-identical between runs, including the name pair shown in the message

#### Scenario: Multiple cycles report the same one each run
- **WHEN** the input contains more than one cyclic define group
- **THEN** the cycle reported in the error SHALL be selected deterministically (e.g., by sorted name), not by `HashMap` iteration order

### Requirement: Environment-mutation locking contract is documented
Process-global locks used to serialise environment-variable mutation across parallel tests SHALL carry a doc comment at the definition site stating that any test in the binary which mutates a process-global env var must acquire the same lock.

#### Scenario: ENV_LOCK has a contract comment
- **WHEN** a reader views the definition of a static `Mutex` used to guard env-var mutation in test code
- **THEN** a doc comment SHALL describe the requirement to share the lock and the consequences of unguarded mutation

#### Scenario: New env-mutating test takes the existing lock
- **WHEN** a future test in the same binary needs to call `unsafe { env::set_var(...) }`
- **THEN** it SHALL acquire the documented shared lock rather than introduce a parallel one

