## Context

Property-based testing is used extensively in some crates (engine, sexpr, shell-parser) but has gaps in others (config parsing, CST pretty-printing, layout). The review identified 7 specific proptest opportunities.

## Goals / Non-Goals

**Goals:**
- Add property tests for the 7 identified gaps
- Leverage existing test generators where possible

**Non-Goals:**
- Achieving 100% property coverage
- Rewriting existing unit tests as property tests

## Decisions

### Config parse roundtrip
Generate `Config` AST → serialize each rule/define to sexpr string → parse back via `may_i_config::parse::parse` → compare. Requires a `to_source()` or similar serialization method on Config types. If serialization doesn't exist, generate sexpr strings directly via the existing sexpr generators and parse at the config level.

### CST pretty_serialize roundtrip
Use existing `sexpr_shape` generator. Parse → `pretty_serialize(width)` → parse again → compare structure (ignoring whitespace trivia). Test with widths from 20 to 120 columns.

### Positional backtracking properties
Generate random arg lists and positional patterns. Verify: (1) matched + unconsumed = original, (2) ZeroOrMore is greedy, (3) result is deterministic.

### Cycle detection: generate adjacency lists
Generate random `(define NAME BODY)` graphs as adjacency lists. For acyclic graphs, verify validation passes. For graphs with cycles, verify rejection. Use proptest's `prop_flat_map` to conditionally inject cycles.

### Keep proptest case counts reasonable
Use `#[proptest_config(ProptestConfig::with_cases(256))]` for expensive tests (CST roundtrip, config roundtrip) and default counts for cheap tests.

## Risks / Trade-offs

- [Config parse roundtrip needs serialization support] → Fall back to generating valid sexpr strings if Config lacks to_source().
- [Pretty-serialize roundtrip may have false positives from trivia differences] → Compare only the structural skeleton (atoms, lists), not whitespace.
