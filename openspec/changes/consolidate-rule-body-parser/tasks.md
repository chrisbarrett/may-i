## 1. Confirm zero external callers of the soon-to-be-private functions

- [ ] 1.1 `rg 'may_i_config::parse_effect' src/ crates/ tests/ fuzz/` returns zero hits
- [ ] 1.2 `rg 'may_i_config::parse_predicate' src/ crates/ tests/ fuzz/` returns zero hits
- [ ] 1.3 `rg 'may_i_config::parse_arg_pattern' src/ crates/ tests/ fuzz/` returns zero hits
- [ ] 1.4 `rg 'may_i_config::parse_positional_arg' src/ crates/ tests/ fuzz/` returns zero hits

## 2. Capture canonical-form baseline

- [ ] 2.1 Add an integration test in `crates/engine/tests/` (or a unit
  test in `crates/engine/src/trust.rs`) that loads the prelude via
  `may_i_config::parse_config`, walks every resolved rule and define
  through the canonical-form serialiser, and snapshots the concatenated
  output with `insta`
- [ ] 2.2 Run the test once to write the snapshot; commit the snapshot
  file
- [ ] 2.3 Verify the snapshot is stable: re-run twice; it SHALL accept
  unchanged

## 3. Add `parse_rule_body` aggregator

- [ ] 3.1 In `crates/config/src/lib.rs`, add
  `pub fn parse_rule_body(sexpr: &Sexpr) -> Result<Spanned<Effect>, RawError>`
  forwarding to `crate::effect::parse_effect`
- [ ] 3.2 Document the function with a `///` comment naming it as the
  single public entry point for rule-body parsing and pointing to
  `parse_rule` for the surrounding `(rule …)` form
- [ ] 3.3 Add a unit test asserting `parse_rule_body` agrees with
  `crate::effect::parse_effect` on a representative input covering
  every effect variant (Terminal, And, Or, Not, When, Unless, If,
  Cond, ArgPattern, CommandPattern, Authorise)
- [ ] 3.4 Extend `parser_properties.rs` with a proptest asserting
  `parse_rule_body` and `parse_effect` produce structurally equal
  results on `any_canonical_effect_cst(2)` and on `any_sexpr(3)`

## 4. Downgrade sub-parser visibility

- [ ] 4.1 In `crates/config/src/lib.rs`, remove `pub use effect::parse_effect;` (replace with `pub(crate) use effect::parse_effect;` if still needed inside the crate via the top-level path, or rely on `crate::effect::parse_effect` and drop the re-export entirely)
- [ ] 4.2 Same treatment for `pub use predicate::parse_predicate;`
- [ ] 4.3 Same treatment for `pub use pattern::{parse_arg_pattern, parse_positional_arg};`
- [ ] 4.4 The function definitions in `effect.rs`, `predicate.rs`, and
  `pattern.rs` themselves SHALL remain `pub` at the module level (so
  intra-crate callers can reach them via `crate::effect::parse_effect`,
  etc.) — only the crate-root re-exports change
- [ ] 4.5 `cargo build --workspace --all-targets` succeeds

## 5. Verify trust-hash invariance

- [ ] 5.1 Re-run the canonical-form snapshot test from step 2; it SHALL
  pass with no snapshot diff
- [ ] 5.2 `cargo test --workspace` passes
- [ ] 5.3 `cargo tarpaulin` runs to completion; inspect `lcov.info` to
  confirm `parse_rule_body` is covered

## 6. Validate change and stage

- [ ] 6.1 `cargo fmt` (per CLAUDE.md, before staging)
- [ ] 6.2 `openspec validate consolidate-rule-body-parser` passes
- [ ] 6.3 `openspec status --change consolidate-rule-body-parser` shows
  4/4 artifacts complete
- [ ] 6.4 `rg '\bpub use (effect|predicate|pattern)::' crates/config/src/lib.rs`
  returns zero hits for the four downgraded names
