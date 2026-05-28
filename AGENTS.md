This project defines a Bash command analysis & authorisation tool for agent
harnesses.

Read `CONTEXT.md` for the project's domain vocabulary before discussing design
or writing user-facing docs. It distinguishes user-facing terms (_decision_,
_pattern_, _rule_) from contributor-only ones (_effect_, _predicate_, the
`ArgPattern`/`Expr<T>` split). Using the wrong word in the wrong audience is
a recurring source of bugs.

Run `cargo fmt` before staging files. The analog for `.lisp` configs in
`examples/` is `may-i fmt` — it canonicalises whitespace and declaration
order; run it before staging changes to example configs.

> [!IMPORTANT]
> Project is pre-1.0; back-compatibility not required. Use migration system to
> define user config migrations if necessary.

## Testing

Prefer property tests; fall back to targeted unit tests for hard-to-hit
branches.

At the end of any significant unit of work, run `cargo tarpaulin` to check
coverage. Inspect `lcov.info` to see what was uncovered, then

- look for program properties that should have proptests
- write unit tests for hitting specific branches surgically--proptests are
  preferred.

Files under `**/proptest-regressions/` are always checked in.

# Release tagging

Cut releases with `scripts/release.sh <version>` (e.g. `scripts/release.sh
0.5.2`). The script enforces a verify-before-mutate ordering: it runs the
full verification suite (fmt, clippy, `cargo tarpaulin`, time-boxed fuzz,
`nix build`) before touching `Cargo.toml`. If any step fails, the working
tree is left untouched and the release can be retried after the fix.

Preconditions: clean working tree, on `main`, in sync with `origin/main`,
`cargo-fuzz` + a nightly toolchain installed.

After verification passes the script bumps `Cargo.toml`, refreshes
`Cargo.lock`, commits, tags `v$VERSION`, and pushes the branch and tag.
The `release.yml` workflow then builds and packages release artefacts —
it does not re-run tests.

## Nightly verification

`.github/workflows/nightly.yml` runs `cargo tarpaulin` and a longer fuzz
pass (`-max_total_time=600`) against `main` daily. It is non-blocking:
failures surface as workflow-run failures in the Actions UI but do not
gate PRs or releases. Use it to spot coverage regressions and grow the
fuzz corpus between releases.
