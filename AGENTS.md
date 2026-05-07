This project defines a Bash command analysis & authorisation tool for agent
harnesses.

Run `cargo fmt` before staging files.

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

Before creating a release tag, bump the `version` field in `Cargo.toml` to match
the tag being created. The Cargo version and the git tag must agree.
