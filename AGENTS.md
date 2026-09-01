Bash command analysis & authorisation tool for agent harnesses.

Read `CONTEXT.md` before discussing design or writing user-facing docs — it
separates user-facing terms (_decision_, _pattern_, _rule_) from
contributor-only ones (_effect_, _predicate_, `ArgPattern`/`Expr<T>`). Mixing
audiences is a recurring source of bugs.

Before staging:

- Rust sources → `cargo fmt`
- `examples/*.lisp` → `may-i fmt`

> [!IMPORTANT]
> Pre-1.0; no back-compat guarantee. Use the migration system for user-config
> changes.

## Commands

Every build, test, lint, and coverage command runs inside the pinned toolchain
via the dev shell: prefix it with `nix develop --command …` (or enter the shell
first). A shell outside it fails with `E0554` on `crates/core/src/lib.rs:1`
because `crates/core` uses an unstable feature on nightly.

Verification tiers (defined in `testing-strategy`):

| Tier | Command |
| :--- | :--- |
| pre-commit | `nix develop --command prek run --stage pre-commit` |
| pre-push | `nix develop --command prek run --stage pre-push` |
| release | `nix develop --command scripts/release.sh <version>` |
| nightly | scheduled CI on `main` (`gh workflow run Nightly` to trigger manually) |

Scoped runs over only the crates a staged edit affects:

- `nix develop --command cargo affected --staged test`
- `nix develop --command cargo affected --staged clippy`

## Testing

Prefer proptests; fall back to unit tests only for branches a proptest can't
hit. `**/proptest-regressions/` is checked in.

After significant work, run `cargo tarpaulin` and inspect `lcov.info` for
uncovered code.

## Releases

Cut a release with `scripts/release.sh <version>` (e.g. `0.5.2`). The script
verifies its own preconditions.
