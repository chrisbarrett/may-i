This project defines a Bash command analysis & authorisation tool for agent
harnesses.

Run `cargo fmt` before staging files.

## Testing

Prefer property tests; fall back to targeted unit tests for hard-to-hit
branches.

If tarpaulin coverage is under threshold, inspect `lcov.info` to see what was
uncovered.
