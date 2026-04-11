## Context

The migration pipeline applies 15 rewrite rules iteratively. Individual rules are well-tested, but compound v1 forms that trigger multiple rules simultaneously have no evaluation-equivalence tests. This is a security-critical gap — silent semantic changes in migration could alter permission decisions.

## Goals / Non-Goals

**Goals:**
- Guarantee evaluation equivalence for all legal v1 config patterns through migration
- Cover real-world wrapper patterns from the user's actual config
- Add proptest generators for compound v1 forms
- Test comment/trivia preservation through the full pipeline

**Non-Goals:**
- Testing migration of malformed configs (best-effort is acceptable)
- Pretty-printing quality (formatting, not semantics)

## Decisions

### Eval-equivalence test pattern
For each v1 config, verify: parse v1 → evaluate with test inputs → collect decisions. Then: migrate v1 → parse result → evaluate with same inputs → compare decisions. This catches semantic drift even when structural output looks reasonable.

### Proptest generators build on existing infrastructure
The existing `any_v1_command_rule`, `any_v1_defcontext`, `any_v1_has_expr` generators in `crates/config/src/migrate/property_tests.rs` provide the foundation. New generators compose these: `any_v1_rule_with_context` wraps a command rule with a context predicate, etc.

### Place tests in crates/config/src/migrate/
Keep migration tests close to the migration code. New files:
- `regression_tests.rs` — hand-written eval-equivalence tests for specific patterns
- Extended `property_tests.rs` — new generators and properties

### Use may-i binary as oracle for complex cases
For compound evaluation scenarios, invoke the `may-i` binary to verify both v1 and v2 configs produce the same output, leveraging the oracle pattern from `tests/oracle_trace_v1.rs`.

## Risks / Trade-offs

- [Proptest generators for compound forms increase test time] → Use `proptest::test_runner::Config` with reduced case count for compound generators.
- [Eval-equivalence requires building evaluation infrastructure in config crate tests] → The engine crate's `evaluate` function is the canonical evaluator. Config tests can depend on engine as a dev-dependency.
