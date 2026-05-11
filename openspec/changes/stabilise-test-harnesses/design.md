## Context

A CI run failed in four `crates/config/src/io.rs` unit tests covering repo-local discovery:

- `discover_repo_root_finds_marker_via_walk`
- `load_and_resolve_with_cwd_splices_repo_local_rules`
- `repo_local_glob_files_load_in_lexical_order`
- `repo_local_rule_surfaces_with_source_path_in_trust`

The failure was not reproducible. The shared shape: all four create `tempfile::tempdir()`, call `init_git(dir.path())` (which only `mkdir`s an empty `.git/`), then call `discover_repo_root(dir.path())`. That function first runs `git rev-parse --show-toplevel` against the cwd, and only on failure falls back to a manual `.git`/`.hg`/`.jj` marker walk. An empty `.git/` directory is implementation-defined input to git — some versions accept it as a toplevel marker, some reject it and let discovery walk into a parent directory.

While auditing the harness for the specific bug, three additional sources of non-determinism surfaced:

- **Integration cwd inheritance.** `assert_cmd::cargo::cargo_bin_cmd!("may-i")` inherits the parent's `current_dir`, which under `cargo test` is the workspace root. The workspace is itself a git repo, so `load_and_resolve()` discovers the workspace as the repo root and globs `.may-i/**/*.lisp` under it. Today there are no such files, so it is a no-op — but anyone adding a `.may-i.lisp` for dogfooding would silently inject an extra rule into every integration test.
- **Non-deterministic cycle errors.** `crates/config/src/resolve.rs::detect_cycles` iterates `define_map.names()`, which is a `HashMap` iterator. With multiple candidate cycles the starting DFS node varies per run, so the `'a' -> 'b'` reference in the error message is non-deterministic. Any test (current or future) that asserts the exact cycle string would flake.
- **Undocumented env lock.** `src/trust_gate.rs` uses a module-private `ENV_LOCK: Mutex<()>` to serialise `unsafe { env::set_var("XDG_DATA_HOME", …) }` across parallel unit tests. Today no other test in the same binary mutates env vars, so the lock works. But the contract — "any test that mutates a process-global env var must take this lock" — is invisible to the next person to add an env-touching test.

The codebase already has a `test-infrastructure` capability covering related concerns (shared `tests/common/mod.rs`, thread-safe env mutation). The natural home for these new requirements is that same capability.

## Goals / Non-Goals

**Goals:**

- Make `init_git` produce a fixture that git unambiguously treats as a repo root.
- Make integration-test child processes isolated from the workspace's `.git`.
- Make define-cycle error messages bytewise stable across runs.
- Document the env-mutation contract so it survives future test additions.

**Non-Goals:**

- No new test framework / harness rewrite. Keep `assert_cmd` + `tempfile` + raw `#[test]`.
- No introduction of `temp_env` or other env-mutation crates. The existing `ENV_LOCK` mutex is fine; the gap is documentation.
- No change to user-visible cycle error wording — only that the chosen `name -> neighbor` pair is deterministic for a given set of defines.
- No change to `discover_repo_root` production logic. The git-shell-out behaviour is fine in production; the fix is in the fixture.

## Decisions

### Decision 1: `init_git` writes `HEAD` + `config`, not just the directory

```rust
fn init_git(path: &Path) {
    let git_dir = path.join(".git");
    std::fs::create_dir_all(&git_dir).unwrap();
    std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(
        git_dir.join("config"),
        "[core]\n\trepositoryformatversion = 0\n",
    )
    .unwrap();
}
```

This is the minimum git accepts as a valid repo (no objects, no refs needed for `rev-parse --show-toplevel`). With these files present, `git rev-parse --show-toplevel` returns the tempdir reliably across git versions, so the marker-walk fallback path is no longer taken under timing-sensitive conditions.

**Alternatives considered:**

- *Shell out to `git init`.* Slower (forks a process per test), adds a hard dependency on `git` being installed in CI. Rejected.
- *Remove the git path entirely and only use marker walk in tests.* `discover_repo_root` itself prefers git; testing only the fallback path would leave the primary path untested.
- *Use `gix` to init a real bare repo.* Heavyweight; we don't need any object-store behaviour.

### Decision 2: Integration tests set an isolated `current_dir`

`tests/common/mod.rs::may_i(config)` becomes:

```rust
pub fn may_i(config: &NamedTempFile) -> Command {
    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.env("MAYI_CONFIG", config.path());
    cmd.current_dir(std::env::temp_dir());  // ← new
    cmd
}
```

Using `std::env::temp_dir()` (rather than a fresh `tempdir()` per call) avoids leaking a `TempDir` guard through the helper's return type — `temp_dir()` returns a stable path that is not itself inside any git repo on supported platforms (macOS `/private/var/folders/...`, Linux `/tmp`). For tests that need a *specific* cwd (e.g., to test repo-local discovery end-to-end), they can override with `.current_dir(...)` after calling the helper.

**Alternatives considered:**

- *Per-call `tempdir()` for cwd.* Forces the helper to return both `Command` and a guard, breaking ergonomics for every call site. Rejected.
- *Add a `MAYI_REPO_ROOT_OVERRIDE` env var that short-circuits discovery.* More invasive and adds a permanent production code path for a test-only concern. Rejected for now; can be reconsidered if cwd isolation proves insufficient.
- *Set `current_dir` only in `cargo_bin_cmd!("may-i")` directly.* Bypasses callers that build the command without going through `may_i()` helper (e.g., `cargo_bin_cmd!("may-i")` used directly in `trust_integration.rs`). We will audit and migrate those call sites to the helper, or add the `current_dir` line at each spawn site.

Audit shows ~20 direct `cargo_bin_cmd!("may-i")` call sites outside `may_i()` helper (`trust_integration.rs`, `load_directive.rs`, `hook_integration.rs`, `migrate_load_graph.rs`, etc.). We will introduce a thin wrapper (e.g., `cmd::may_i_cmd()`) that does *not* require a config file and ensures `current_dir` is set, and migrate all direct callers to it.

### Decision 3: `detect_cycles` iterates a sorted view of define names

The fix is a one-line change in `crates/config/src/resolve.rs`:

```rust
let mut names: Vec<_> = define_map.names().collect();
names.sort_unstable();
for name in names {
    if !visited.contains(name) {
        dfs_check_cycle(name, &adjacency, &mut visiting, &mut visited, define_map)?;
    }
}
```

Sorting by name fixes the starting node deterministically. We also sort the `Vec<String>` of references inside `adjacency` to make the neighbour traversal stable.

**Alternatives considered:**

- *Switch `define_map` storage to `BTreeMap`.* Larger blast radius and a runtime cost paid by every lookup. Rejected — sorting once at cycle-detection entry is enough.
- *Leave the iteration order alone and assert error messages with `contains(...)` instead of exact equality.* Pushes the discipline onto every future test author. Rejected.

### Decision 4: `ENV_LOCK` contract documented at its definition site

Add a doc comment above `static ENV_LOCK` in `src/trust_gate.rs`:

```
/// Process-global lock for env-mutation tests in this binary.
///
/// Any test that calls `unsafe { env::set_var(...) }` or `env::remove_var(...)`
/// MUST take this lock before mutating and hold it until the variable is
/// restored. Cargo runs tests in parallel by default, so unguarded mutations
/// race with each other and with reads in other modules.
///
/// If a future test in this binary needs to mutate env vars, share this
/// lock — do not introduce a parallel one.
```

No code change beyond the comment. This is cheap, durable, and discoverable: anyone touching the file sees the contract.

**Alternatives considered:**

- *Move `ENV_LOCK` to a `tests/common/env_lock.rs` shared module.* The lock today only protects unit tests within the `may-i` binary, not across-binary tests (which can't share statics anyway). Premature.
- *Replace with `temp_env` crate.* Adds a dependency for a single-call-site need. Rejected.

## Risks / Trade-offs

- **Risk:** Setting `current_dir(std::env::temp_dir())` on integration commands could mask a real bug where the production binary depends on the caller's cwd. → Mitigation: existing `load_directive.rs` tests still exercise cwd-sensitive paths explicitly via `MAYI_CONFIG` and (where needed) `.current_dir(...)` overrides. We will audit those tests during implementation.
- **Risk:** A user with `$TMPDIR` set inside a git repo would still see the original ambiguity (their `tempdir()` lives inside another repo). → Mitigation: the `init_git` fix (Decision 1) addresses this case directly by writing a valid `.git/` so `git rev-parse` accepts the inner tempdir as the toplevel.
- **Risk:** Sorting `adjacency`'s neighbour lists changes the *order* in which cycles are reported when multiple cycles exist. → This is a deliberate, documented behaviour change. The error wording is unchanged; only the choice of which `a -> b` is named first is now stable. No existing test asserts a specific name pair (verified by grep), so no test breakage.
- **Risk:** `std::env::temp_dir()` on Windows returns a per-user dir that could in principle be inside a git repo. → Out of scope; we don't run on Windows. If/when we do, switch to a `OnceLock<TempDir>` guard at test-binary scope.
