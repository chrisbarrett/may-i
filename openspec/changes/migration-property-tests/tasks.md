## 1. Setup

- [x] 1.1 Add `proptest` and `may-i-engine` as dev-dependencies to `crates/config/Cargo.toml`
- [x] 1.2 Create `crates/config/src/migrate/property_tests.rs` with `#[cfg(test)]` module and add `mod property_tests;` to `migrate/mod.rs`

## 2. Canonical syntax generators

- [x] 2.1 Write `any_command_sexpr()` — generates command patterns: literal strings, `(or ...)`, `(regex ...)`
- [x] 2.2 Write `any_terminal_effect_sexpr()` — generates `(effect :allow/:ask/:deny ["reason"])`
- [x] 2.3 Write `any_predicate_sexpr(depth)` — generates `(fact? :key)`, `(and P1 P2)`, `(or P1 P2)`, `(not P)`
- [x] 2.4 Write `any_effect_sexpr(depth)` — generates terminals, `(when P E)`, `(if P E1 E2)`, `(cond ...)`
- [x] 2.5 Write `any_rule_sexpr()` — generates `(rule CMD EFFECT)`
- [x] 2.6 Write `any_config_sexpr()` — generates multi-rule configs joined with newlines

## 3. Canonical fixed-point property

- [x] 3.1 Write property test: for random canonical configs, `to_sexpr(migrate(parse_cst(s)))` equals `parse(s)` per form
- [x] 3.2 Verify test catches a mutation (e.g., temporarily break a rule) then revert

## 4. Idempotency property

- [x] 4.1 Write property test: `serialize(migrate(migrate(parse_cst(s)))) == serialize(migrate(parse_cst(s)))` for random canonical configs

## 5. Parseability property

- [x] 5.1 Write property test: `parse_config(serialize(migrate(parse_cst(s))))` succeeds for random canonical configs

## 6. V1 syntax paired generators

- [x] 6.1 Write `any_v1_command_rule()` — generates `(rule (command X) E)` paired with canonical `(rule X E)`
- [x] 6.2 Write `any_v1_defcontext()` — generates `(defcontext name pred)` paired with `(define name pred)`
- [x] 6.3 Write `any_v1_has_expr()` — generates `(has :key)` paired with `(fact? :key)`, used inside rule predicates

## 7. Eval preservation property

- [x] 7.1 Write eval helper: `configs_evaluate_equal(config1, config2, cmd, args, facts) -> bool`
- [x] 7.2 Write property test: for random v1/canonical pairs and random eval context, both produce the same decision
- [x] 7.3 Write property test: for random canonical configs and random eval context, eval is identical before and after migration round-trip

## 8. Convergence property

- [x] 8.1 Write property test: migration of random s-expression strings completes within a timeout

## 9. Verification

- [x] 9.1 Run full test suite (`cargo test --workspace`) — all tests pass including new property tests
- [x] 9.2 Temporarily break a rewrite rule, verify at least one property test catches it, then revert
