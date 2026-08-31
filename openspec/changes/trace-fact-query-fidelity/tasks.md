## 1. Query spelling

- [ ] 1.1 Failing test: rendering a trace for `(rule "echo" (if (fact? [:via "ssh"]) (deny "remote") (allow)))` produces a left column containing `fact?` and not `has`
- [ ] 1.2 Make `fact_query_to_doc` (`src/annotation.rs:237`) defer to the rendering `Predicate::to_doc` already performs (`crates/core/src/ast.rs:439`) rather than carrying its own `Doc::atom("has")`
- [ ] 1.3 Grep the repo for any remaining `has` spelling reachable from output; confirm the only surviving occurrences are the migration rule that consumes it (`crates/config/src/migrate/rename_has_to_fact.rs`) and its tests

## 2. Witness recorded at evaluation

- [ ] 2.1 Failing test: `(fact? [:o/all "a=1"])` against `:o/all` = `{"BAD", "a=1"}` renders `yes` and does not name `BAD`
- [ ] 2.2 Change `evaluate_fact_query`'s `FactQuery::Value` arm (`crates/engine/src/eval/predicates.rs:301-311`) from `set.iter().any(…)` to a search that keeps the matching member
- [ ] 2.3 Add the witness to `Evidence::FactValues` (`src/trace/node.rs:66`) and thread it from evaluation through the fold to the trace node
- [ ] 2.4 Update the exhaustive `Evidence` matches the new field breaks — `src/output/render_rule.rs`, `src/output/json.rs`, `src/annotation.rs` — leaving the JSON shape unchanged
- [ ] 2.5 Proptest: for any fact set and any matching query, the rendered witness is a member of the set that satisfies the query

## 3. Multi-member rendering rules

- [ ] 3.1 Replace `observed.iter().next()` (`src/output/render_rule.rs:116`) with witness-driven selection
- [ ] 3.2 Render a bare `no` when the query does not match and the set holds more than one member
- [ ] 3.3 Keep exact-query success rendering as `yes` without echoing the value
- [ ] 3.4 Pin "scalar value available" to a single-member set, matching `ContextFacts::get_scalar` (`crates/core/src/context.rs:46-51`)
- [ ] 3.5 Tests for each case in the modified requirement: multi-member exact match, multi-member pattern match, multi-member mismatch, and the four preserved scalar cases
- [ ] 3.6 Proptest: a rendered annotation never names a fact value that fails the query

## 4. Verification

- [ ] 4.1 `cargo fmt` and `cargo clippy`
- [ ] 4.2 Full test suite; review trace snapshot diffs and confirm every change is a `has` → `fact?` correction or a witness correction
- [ ] 4.3 Confirm the JSON trace surface is byte-identical for a fixture exercising presence, exact, and pattern queries
- [ ] 4.4 REFERENCE.md: check the trace examples for the `has` spelling; edit, or record "verified, no surface change"
- [ ] 4.5 `scripts/validate-change-doc-sync.sh`
- [ ] 4.6 `openspec validate trace-fact-query-fidelity --strict`
