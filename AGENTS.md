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

## Testing

Prefer proptests; fall back to unit tests only for branches a proptest can't
hit. `**/proptest-regressions/` is checked in.

After significant work, run `cargo tarpaulin` and inspect `lcov.info` for
uncovered code.

## Releases

Cut a release with `scripts/release.sh <version>` (e.g. `0.5.2`). The script
verifies its own preconditions.
