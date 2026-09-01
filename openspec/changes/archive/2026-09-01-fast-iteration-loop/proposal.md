## Why

The verification loop every contributor and agent runs is roughly three times
slower than the work it performs, and most of the loss is structural rather than
inherent to the tests.

Measured on an 8-core aarch64-darwin host inside `nix develop`, with the
dependency graph already built:

| Loop | Measured |
| :--- | :--- |
| `cargo build --workspace --all-targets` (workspace crates clean) | 31s wall, **178 CPU-s** |
| `cargo test --workspace` (warm) | **65s** |
| Edit `crates/engine/src/eval/decompose.rs`, rebuild all targets | **20–29s** |
| Edit `tests/trace_rule_shape.rs` (109 lines), rebuild that target | **6.1s** |

Three structural costs dominate.

**Incremental compilation is off.** `~/.cargo/config.toml` sets
`incremental = false` alongside `rustc-wrapper = sccache`, because sccache
refuses to run when rustc is invoked with `-C incremental` — it exits non-zero
and fails the build rather than degrading. Every edit therefore recompiles the
whole crate from scratch. Enabling incremental measures 20–29s → **11.0s** for
an engine edit, and 6.1s → **1.6s** for a leaf test file.

**Thirty-two integration test binaries in the root crate cost 70 of the 178
CPU-s** — 39% of all workspace compile time — and the cost is almost entirely
fixed per target rather than proportional to content:
`tests/migrate_flag_smoke.rs` is 38 lines and costs 1.92 CPU-s;
`tests/trust_integration.rs` is 573 lines and costs 1.75 CPU-s. The floor is
~1.4 CPU-s per target, and each linked binary is 20 MB. 6,139 lines of test code
are paying for 32 link steps and 32 monomorphisations of the same `clap` /
`miette` / `serde` generic chains.

**One test is 45% of the test run.** `crates/shell-parser/tests/zsh_oracle.rs`
takes **29s of the 65s** total. It runs 512 proptest cases, each shelling out to
`zsh -nc`; `prop_assume!` rejections multiply that to roughly 2,000 process
spawns at ~15ms each. Its `#![proptest_config(… cases: 512 …)]` hardcodes the
count, which also overrides `PROPTEST_CASES`, so there is no way to dial it down
for a fast local run.

> [!WARNING]
> **Correction (post-implementation).** The rejection claim above is wrong.
> Measured during implementation with a counting `zsh` shim: **513 spawns for
> 512 cases** — approximately one per case, not four. `prop_assume!` was
> discarding almost nothing, because `zsh -n` does accept the unterminated
> brace-group and function-definition forms the generator produces.
>
> The error was in the derivation, not the observation: the spawn count was
> inferred by dividing the test's wall time by a per-spawn cost measured in a
> shell loop on trivial input (~15ms). The real in-test cost is ~55–60ms per
> spawn, which accounts for the full 29s at one spawn per case.
>
> Consequence: the generator-tightening work below was correctly abandoned (see
> `tasks.md` 3.4) — it would have shrunk oracle coverage for no gain. The
> case-count and `-f` changes stand. The sentence about `PROPTEST_CASES` being
> overridden by the hardcoded config **is** correct; see the correction note in
> `tasks.md` 3.4.

Two further defects make the loop worse than the numbers suggest. An ambient
shell outside `nix develop` resolves stable `rustc`, and every `cargo` command
then fails immediately with `E0554: #![feature] may not be used on the stable
release channel` from `crates/core/src/lib.rs:1` — a failure mode agents burn
turns rediscovering. And `AGENTS.md` documents `cargo fmt`, `cargo tarpaulin`
and `scripts/release.sh` but never states how to run the tests, that commands
must go through the dev shell, or that `cargo affected` exists.

## What Changes

- **Enable incremental compilation for local builds.** A repo-level
  `.cargo/config.toml` sets `incremental = true` and clears `rustc-wrapper`,
  overriding the contributor's global sccache wiring inside this repository. CI
  keeps non-incremental builds via `CARGO_INCREMENTAL=0`, which is what its cold
  cache wants.
- **Consolidate the root crate's 32 integration test targets** into a small
  number of themed targets, so per-target link and monomorphisation cost is paid
  a handful of times instead of 32.
- **Make the zsh oracle's case count environment-tunable** with a small default,
  and run the full sweep at the nightly tier. ~~Tighten its generator so it emits
  zsh-valid forms directly rather than discarding roughly three quarters of
  generated cases through `prop_assume!`~~ (withdrawn — see the correction above;
  the rejection rate was already ~0), and pass `-f` to `zsh` so the
  contributor's `~/.zshenv` cannot change what the oracle considers valid syntax.
- **Document the command surface.** `AGENTS.md` gains the dev-shell requirement,
  the per-tier commands, and `cargo affected`.
- Disable doctest harnesses on the eight workspace libraries, none of which
  contain a doctest.

Not in scope: adopting `cargo-nextest` for the default loop. It was measured and
is **slower** here — 107s against `cargo test`'s 65s, because it runs one process
per test and process startup is ~0.22s across 3,051 tests. It stays where it is,
in `nix flake check`. See `design.md`.

No user-facing behaviour changes: no DSL form, decision, trace, or CLI surface is
touched.

## Capabilities

Bucket: **testing** for the verification-loop requirements;
**contributor-internals** for the build-environment requirements.

### New Capabilities

- `build-environment`: contributor-facing. The pinned toolchain and the
  requirement that build and test commands run inside it; the incremental-
  compilation and rustc-wrapper policy and its split between local and CI; and
  the requirement that `AGENTS.md` names the command for each verification tier.

### Modified Capabilities

- `testing-strategy`: the verification tiers requirement moves the full zsh
  oracle sweep from pre-push to nightly and names the reduced pre-push sweep.
  Adds a requirement bounding the number of integration test targets in the root
  crate, and a requirement that oracle-style tests taking a case count expose it
  through `PROPTEST_CASES` rather than hardcoding it.

## Impact

**Build configuration.** New `.cargo/config.toml` at the repo root. `.github/workflows/ci.yml`
and `.github/workflows/nightly.yml` gain `CARGO_INCREMENTAL: 0` and the nightly
workflow gains the full-sweep `PROPTEST_CASES` for the oracle job. `Swatinem/rust-cache`
already keys on the lockfile and is unaffected.

**Tests.** The 32 files under `tests/` collapse into themed targets. Fourteen of
them (`display_safe_boundary`, `flag_and_parameter`, `migrated_v1_trace`,
`binding_recursion`, `carrier_hardening`, `migrate_flag_smoke`,
`double_dash_boundary`, `migration_diff`, `parser_dsl`,
`shape_mismatch_snapshots`, `pretty_print_snapshots`, `trace_rule_shape`,
`parse_diagnostic_snapshots`, `wrapper_tail_scoping`) do not use
`tests/common/mod.rs` at all, and fifteen spawn no subprocess — they are library
tests sitting in an integration-test target. Merging is mechanical but must
preserve every test name, since `proptest-regressions/` files and
`insta` snapshots are keyed by module path. `tests/common/mod.rs` becomes a
single `mod common` per consolidated target instead of one per file.

**zsh oracle.** `crates/shell-parser/tests/zsh_oracle.rs:113` hardcodes
`cases: 512`; `:31` and `:20` invoke `zsh -nc` without `-f`. ~~The generator's
`semi=false` variants at `:72` and `:85` are the main source of `prop_assume!`
rejection.~~ (Withdrawn — `zsh -n` accepts those forms; measured rejection rate
was ~0. See the correction above.)

**Cargo manifests.** `[lib] doctest = false` on the eight workspace libraries.
`tarpaulin.toml` keeps `run-types = ["Lib", "Tests", "Doctests"]` — the
release-verification spec requires that list, and it stays correct over an empty
doctest set.

**Docs.** `AGENTS.md` gains a commands section. No `REFERENCE.md` surface change:
every capability touched here is contributor-facing.
