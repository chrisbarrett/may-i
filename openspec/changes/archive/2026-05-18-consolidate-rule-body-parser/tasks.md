## 1. Confirm zero external callers of the soon-to-be-private functions

- [x] 1.1 `rg 'may_i_config::parse_effect' src/ crates/ tests/ fuzz/` returns zero hits
- [x] 1.2 `rg 'may_i_config::parse_predicate' src/ crates/ tests/ fuzz/` returns zero hits
- [x] 1.3 `rg 'may_i_config::parse_arg_pattern' src/ crates/ tests/ fuzz/` returns zero hits
- [x] 1.4 `rg 'may_i_config::parse_positional_arg' src/ crates/ tests/ fuzz/` returns zero hits

## 2. Capture canonical-form baseline

- [x] 2.1 Add a unit test in `crates/engine/src/trust.rs` that parses
  an inline rule-body fixture covering every `Effect` variant (Terminal,
  And, Or, Not, When, Unless, If, Cond, ArgPattern, CommandPattern,
  Authorise), every `Predicate` variant (Fact, NamedRef, And, Or, Not),
  every `ArgPattern` shape (positional, exact, anywhere, forbidden,
  flag, parameter), and a `(define …)`. The test walks every resolved
  rule and define through the canonical-form serialiser
  (`canonical_rule`, `canonical_define`) and snapshots the concatenated
  output with `insta`. (Prelude rejected: zero rules/defines.
  `starter_config.lisp` rejected: still carries legacy `(check :deny …)`
  syntax that no longer parses — a separate bug, out of scope for this
  change.)
- [x] 2.2 Run the test once to write the snapshot; commit the snapshot
  file
- [x] 2.3 Verify the snapshot is stable: re-run twice; it SHALL accept
  unchanged

## 3. Add `parse_rule_body` aggregator

- [x] 3.1 In `crates/config/src/lib.rs`, add
  `pub fn parse_rule_body(sexpr: &Sexpr) -> Result<Spanned<Effect>, RawError>`
  forwarding to `crate::effect::parse_effect`
- [x] 3.2 Document the function with a `///` comment naming it as the
  single public entry point for rule-body parsing and pointing to
  `parse_rule` for the surrounding `(rule …)` form
- [x] 3.3 Add a unit test asserting `parse_rule_body` agrees with
  `crate::effect::parse_effect` on a representative input covering
  every effect variant (Terminal, And, Or, Not, When, Unless, If,
  Cond, ArgPattern, CommandPattern, Authorise)
- [x] 3.4 Extend `parser_properties.rs` with a proptest asserting
  `parse_rule_body` and `parse_effect` produce structurally equal
  results on `any_canonical_effect_cst(2)` and on `any_sexpr(3)`

## 4. Downgrade sub-parser visibility

- [x] 4.1 In `crates/config/src/lib.rs`, remove `pub use effect::parse_effect;` (replace with `pub(crate) use effect::parse_effect;` if still needed inside the crate via the top-level path, or rely on `crate::effect::parse_effect` and drop the re-export entirely)
- [x] 4.2 Same treatment for `pub use predicate::parse_predicate;`
- [x] 4.3 Same treatment for `pub use pattern::{parse_arg_pattern, parse_positional_arg};`
- [x] 4.4 The function definitions in `effect.rs`, `predicate.rs`, and
  `pattern.rs` are reachable to intra-crate callers via
  `crate::effect::parse_effect`, etc. The workspace lint
  `unreachable_pub = "warn"` flagged `pub fn` inside `pub(crate) mod`
  as unreachable, so the function visibilities were tightened to
  `pub(crate) fn`. The crate-root re-exports are dropped entirely
  (intra-crate callers updated to use the module path). The seam
  outcome — no external `may_i_config::parse_*` for the four
  downgraded names — is unchanged.
- [x] 4.5 `cargo build --workspace --all-targets` succeeds

## 5. Verify trust-hash invariance

- [x] 5.1 Re-run the canonical-form snapshot test from step 2; it SHALL
  pass with no snapshot diff
- [x] 5.2 `cargo test --workspace` passes
- [x] 5.3 `cargo tarpaulin` runs to completion; inspect `lcov.info` to
  confirm `parse_rule_body` is covered (FNDA: 536 hits)

## 6. Validate change and stage

- [x] 6.1 `cargo fmt` (per CLAUDE.md, before staging)
- [x] 6.2 `openspec validate consolidate-rule-body-parser` passes
- [x] 6.3 `openspec status --change consolidate-rule-body-parser` shows
  4/4 artifacts complete
- [x] 6.4 `rg '\bpub use (effect|predicate|pattern)::' crates/config/src/lib.rs`
  returns zero hits for the four downgraded names
