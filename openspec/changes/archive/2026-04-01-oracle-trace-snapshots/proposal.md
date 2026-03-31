## Why

The rewritten `may-i` tool must produce trace output identical to the previous
release (the oracle) for V1 configs. Currently the dev build diverges in tree
structure, which rules are shown, annotation format, and pattern expansion. We
need snapshot tests that lock in the oracle's exact output—including ANSI colour
codes—so we can iterate on the trace renderer until it matches.

## What Changes

- Add an integration test harness that evaluates commands against a reduced V1
  config fixture and compares rendered trace output against oracle snapshots.
- Oracle snapshots (`.raw` with ANSI, `.txt` stripped) have already been
  captured in `tests/snapshots/oracle_v1/` from the previous release binary.
- A V1 fixture config and test case manifest already exist in
  `tests/fixtures/v1/`.
- The trace renderer will need to recover original V1 source structure when
  displaying migrated configs (source recovery problem), rather than showing the
  rewritten V2 AST structure.

## Capabilities

### New Capabilities

- `oracle-trace-testing`: Integration test harness that loads a V1 config,
  evaluates commands via the Rust API, captures rendered output (with forced
  colour at COLUMNS=80), and asserts against oracle snapshots. Covers both raw
  ANSI and stripped plain-text comparison.
- `v1-source-recovery`: When a V1 config is transparently migrated, the trace
  renderer must display the original V1 s-expression structure (e.g.
  `(command ...)`, `(args ...) (effect ...)` as siblings) rather than the
  rewritten V2 AST structure. Spans already point to original source; this
  capability uses them to recover display structure.

### Modified Capabilities

## Impact

- `src/cmd_eval.rs` — test harness calls into eval pipeline
- `src/annotation.rs` — TracingFold may need V1-aware Doc construction
- `src/output.rs` — trace renderer must produce oracle-equivalent output
- `crates/config/src/io.rs` — source_text preservation is relied upon
- `tests/` — new integration test file, fixtures, and snapshot files
