## Context

See `proposal.md` — Why for the measurements motivating this change. What matters
for the approach:

- The contributor's user-level `~/.cargo/config.toml` sets `incremental = false`
  and `rustc-wrapper = <sccache>`. Cargo merges configuration from the workspace
  root upwards to the home directory, with the nearest file winning, so a
  repository-level `.cargo/config.toml` can override both keys.
- sccache does not degrade when handed an incremental invocation; it refuses.
  Reproduced with `CARGO_INCREMENTAL=1 cargo build -p may-i-pp --lib` inside the
  dev shell, which fails with:
  `sccache: incremental compilation is prohibited: Unset CARGO_INCREMENTAL to continue.`
  The two features are therefore mutually exclusive, not merely redundant.
- Environment variables beat configuration files in Cargo's precedence order, so
  CI can opt out of a repository-level setting without editing it.
- The 32 root-crate integration test targets are the largest single block of
  compile cost, and 14 of them do not use `tests/common/mod.rs` at all.
- `cargo test` runs test binaries one at a time, with threads inside each. That
  is the right shape here: the alternative runner's process-per-test model was
  measured and is slower (see Decisions).

## Goals / Non-Goals

**Goals:**

- Make a single-file edit rebuild in seconds, not tens of seconds.
- Remove per-target build cost that carries no verification value.
- Keep the pre-push tier's wall time proportional to what it actually proves.
- Leave every existing assertion in place; this change is about how tests are
  built and scheduled, not what they check.

**Non-Goals:**

- Deleting or weakening tests. Case counts move between tiers; no invariant
  stops being checked.
- Speeding up the crate-level unit test suites (`may_i_engine` at 5.6s,
  `may_i_config` at 5.5s). Those are real property-test work, and cutting them
  would trade coverage for time.
- Cross-worktree or cross-machine build caching. Removed here as a consequence,
  not replaced (see Risks).
- Changing the dev shell's package set or the toolchain pin.

## Decisions

### Enable incremental compilation locally; disable it in CI

A repository-level `.cargo/config.toml` sets `incremental = true` and
`rustc-wrapper = ""`. CI workflows set `CARGO_INCREMENTAL: 0` at the job level.

Measured, rebuilding all workspace targets after touching
`crates/engine/src/eval/decompose.rs`: 20–29s without incremental, **11.0s** with
(32 CPU-s against 68). After touching a leaf integration test file: 6.1s against
**1.6s**.

The split is deliberate. Incremental helps a warm working tree and hurts a cold
one — CI restores a dependency cache but never an incremental cache, so
incremental state there is pure write cost and cache bloat.

*Alternatives considered.*

- **Keep sccache, leave incremental off.** Rejected: sccache's measured hit rate
  in this workspace is 29.8%, and those hits are on third-party dependencies that
  are already warm in a live worktree. It pays off on a fresh checkout — roughly
  a one-time 40s — while incremental pays off on every edit for the life of the
  worktree.
- **Set `CARGO_INCREMENTAL=1` in the dev shell instead of `.cargo/config.toml`.**
  Rejected: it would not apply to a `cargo` invoked outside the dev shell, and
  it would not clear the inherited `rustc-wrapper`, so the build would still die
  in sccache. The failure would also be invisible to anyone reading the repo.
- **Share one `CARGO_TARGET_DIR` across worktrees instead of caching.** Rejected:
  Cargo takes an exclusive lock on a build directory, so concurrent agents in
  separate worktrees would serialise behind each other ("Blocking waiting for
  file lock on build directory"). That trades a compile-time win for a
  concurrency loss, in a repository whose workflow is explicitly parallel
  worktrees.
- **Ask contributors to change their global config.** Rejected: it is not the
  repository's to change, and it would affect their other projects.

### Consolidate the 32 integration test targets into five themed targets

Proposed grouping, all under `tests/`:

| Target | Absorbs |
| :--- | :--- |
| `cli.rs` | `check_integration`, `parse_integration`, `parse_diagnostics_integration`, `eval_stdin`, `eval_defines`, `fmt_integration`, `hook_integration`, `load_directive`, `local_function_calls`, `undeclared_long_flag_arity`, `migrate_flag_smoke` |
| `eval.rs` | `unified_eval_integration`, `binding_recursion`, `carrier_hardening`, `wrapper_tail_scoping`, `flag_and_parameter`, `double_dash_boundary`, `quantifier_sequence_groups`, `segment_decisions_fixtures`, `display_safe_boundary` |
| `render.rs` | `pretty_print_snapshots`, `shape_mismatch_snapshots`, `parse_diagnostic_snapshots`, `trace_rule_shape`, `migrated_v1_trace`, `parser_dsl` |
| `trust.rs` | `trust_integration`, `trust_rehash`, `audit_integration` |
| `migrate.rs` | `migrate_integration`, `migration_diff`, `migrate_load_graph` |

Each absorbed file becomes a module inside its target, so the test bodies move
unchanged and the grouping stays visible in test names.

The bound of six in the spec is the count above plus one, leaving room for a
target with a genuinely distinct harness need without another spec change.

*Alternatives considered.*

- **One target.** Rejected: a single target serialises the whole integration
  suite behind one link step, and `cargo test --test <name>` — the sharpest tool
  for a focused loop — stops being able to select anything.
- **Split by whether the test spawns the binary** (17 do, 15 do not). Rejected:
  the split is real but cuts across the themes a contributor navigates by, and
  the fixed cost is per target, not per subprocess, so two targets and five cost
  nearly the same.
- **Move the 15 non-spawning files into crate unit tests.** Rejected as a
  separate concern: it changes what the tests can reach (private items become
  visible), which invites scope creep into the tests themselves. The consolidated
  targets get the compile win without touching test semantics.

### Make the zsh oracle tunable, generate valid inputs, and suppress startup files

Three independent edits to `crates/shell-parser/tests/zsh_oracle.rs`:

1. Drop `cases: 512` from `proptest_config` so `ProptestConfig::default()` reads
   `PROPTEST_CASES`. Compiled-in default sized for pre-push; nightly sets 512.
2. Emit only forms `zsh -n` accepts, rather than generating invalid ones and
   discarding them through `prop_assume!`. The measured ~2,000 spawns for 512
   cases means roughly three quarters of generated cases are thrown away, and
   each rejection still costs a process spawn.
3. Pass `-f` to both `zsh` invocations.

The third is a correctness fix that happens to belong here. `zsh -nc` sources
`/etc/zshenv` and `~/.zshenv`; options set there can change how zsh parses input,
so the oracle's ground truth currently varies with the contributor's dotfiles. It
was measured as no faster — the win is hermeticity.

*Alternatives considered.*

- **Memoise `zsh_accepts`.** Rejected: the generator's statement space is roughly
  two thousand forms and a command line composes up to three of them, so the
  duplicate rate over a few thousand draws is low. The cache would add state for
  almost no hits.
- **Keep one long-lived zsh and feed it inputs.** Rejected: the cost is zsh's own
  startup (~12–17ms measured), not Rust-side process creation, and syntax-checking
  a fresh input needs a fresh parse. A persistent process would still spawn per
  input.
- **Mark the test `#[ignore]` and run it only at nightly.** Rejected: it would
  give the pre-push tier no signal at all from the oracle. A reduced case count
  keeps a real, if thinner, check on every push.

### Keep `cargo test`; do not adopt `cargo-nextest` for the default loop

Measured on this workspace: `cargo nextest run --workspace` takes **107s** where
`cargo test --workspace` takes **65s**. nextest runs one process per test, and
with 3,051 tests the per-test process cost dominates — trivial tests in
`parser_snapshots` were observed at 0.22s each under 8-way parallelism, against
~31ms for a bare test-binary launch.

This workspace's shape — many small tests, a few slow ones — is the case where
nextest's model loses. It stays in `nix flake check`, where it already runs and
where the isolation is worth the cost.

### Disable doctest harnesses

All eight workspace libraries get `[lib] doctest = false`. `cargo test
--workspace --doc` reports zero tests across all of them, so the harnesses build
and run nothing.

`tarpaulin.toml` keeps `run-types = ["Lib", "Tests", "Doctests"]`, which
`release-verification` requires. That list stays correct over an empty doctest
set; if a doctest is added later, re-enabling the harness on that one crate is a
one-line change.

## Risks / Trade-offs

**Losing sccache inside this repository means a fresh worktree rebuilds all
dependencies.** → Measured at roughly 40s, paid once per worktree against a 2–4x
win on every subsequent edit. Contributors who prefer the trade can override
locally; `.cargo/config.toml` is repository policy, not a lock.

**Incremental compilation is a known source of stale-artefact and disk-growth
problems, and `target/` is already 1.3–3.5 GB.** → `cargo clean -p <crate>` is
the escape hatch and is cheap once dependencies are cached. Growth is worth
watching after the change lands.

**Consolidation can silently drop tests.** Merging 32 files into five is
mechanical but wide, and a test lost in the move fails open — the suite still
passes. → The spec requires assertion count to be preserved; the tasks pin it to
a recorded before-and-after count from `cargo test -- --list`, not to review.

**Consolidation changes `insta` and `proptest-regressions` lookup keys**, which
derive from target and module path. A stale key means a snapshot silently
re-accepts or a regression seed stops replaying. → Called out as its own spec
scenario and its own task, done before the merge is considered complete.

**Reducing the oracle's default case count moves real coverage to nightly**, so a
zsh-dialect regression can reach `main` and be caught hours later rather than at
push. → Accepted deliberately: that is the tier's purpose, and 29s on every push
for one test is the worse trade. The reduced default still samples the same
generator on every push.

**`cargo affected` at pre-commit and the new `.cargo/config.toml` are
independent**, and a contributor whose shell is outside the dev shell still hits
`E0554` before any of this helps. → The `AGENTS.md` requirement in
`build-environment` is what addresses that, and it is sequenced first in the
tasks so the documentation lands even if the rest is split across sittings.

## Migration Plan

No user-facing migration: no config format, DSL form, or CLI surface changes.

The four workstreams — build configuration, documentation, test consolidation,
oracle — are independent and land in that order. Each is separately revertible;
the consolidation is the only one with a wide diff, and reverting it is a file
move back.
