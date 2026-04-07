This project defines a Bash command analysis & authorisation tool for agent
harnesses.

Run `cargo fmt` before staging files.

## Testing

Prefer property tests; fall back to targeted unit tests for hard-to-hit
branches.

At the end of any significant unit of work, run `cargo tarpaulin` to check
coverage. Inspect `lcov.info` to see what was uncovered, then

- look for program properties that should have proptests
- write unit tests for hitting specific branches surgically--proptests are
  preferred.

Files under `**/proptest-regressions/` are always checked in.
