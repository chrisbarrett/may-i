## ADDED Requirements

### Requirement: Rule-body parsing has a single public entry point

The config crate (`may_i_config`) SHALL expose exactly one public function for parsing the body of a `(rule …)` form: `parse_rule_body(sexpr: &Sexpr) -> Result<Spanned<Effect>, RawError>`. The four sub-parsers it dispatches to — `parse_effect`, `parse_predicate`, `parse_arg_pattern`, and `parse_positional_arg` — SHALL be `pub(crate)`, not `pub`. This pins the contributor-only Pattern-internals split (`ArgPattern` / `Predicate` / `Effect`, per CONTEXT.md "Pattern internals") inside the crate boundary so renaming a sub-parser or a variant becomes a one-crate change.

The top-level form parsers `parse_rule`, `parse_define`, `parse_parser_form`, `parse_style_definition`, and `parse_command_pattern` MAY remain `pub`: they correspond to user-vocabulary nouns (Rule, Define, Parser, Style, Command) and do not surface the contributor-only sub-parser split.

#### Scenario: `parse_rule_body` is exported from `may_i_config`

- **WHEN** `may_i_config::parse_rule_body` is named in a downstream crate
- **THEN** it SHALL resolve to a function with signature
  `fn parse_rule_body(sexpr: &may_i_sexpr::Sexpr) -> Result<may_i_core::ast::Spanned<may_i_core::ast::Effect>, may_i_sexpr::RawError>`

#### Scenario: Rule-body sub-parsers are not public

- **WHEN** the workspace is scanned for `pub use` re-exports of `parse_effect`, `parse_predicate`, `parse_arg_pattern`, or `parse_positional_arg` from `crates/config/src/lib.rs`
- **THEN** zero matches SHALL be reported
- **AND** importing any of those four names as `may_i_config::<name>` from outside the config crate SHALL fail to compile

#### Scenario: `parse_rule_body` and `parse_effect` agree on every input

- **WHEN** the same `Sexpr` is passed to `may_i_config::parse_rule_body` and to the crate-internal `crate::effect::parse_effect`
- **THEN** both calls SHALL return structurally equal `Result<Spanned<Effect>, RawError>` values
- **AND** this SHALL hold across the canonical-effect proptest generator used by `parser_properties.rs`

### Requirement: Rule-body consolidation preserves canonical form byte-for-byte

The canonical-form serialisation produced by `may_i_engine`'s trust hashing for a hand-crafted rule-body fixture (covering every `Effect`, `Predicate`, and `ArgPattern` variant) SHALL be byte-identical before and after the rule-body parser consolidation. This guards the trust hash against an accidental parse-time normalisation slip during the consolidation, since invalidating canonical-form output would silently invalidate user trust entries that depend on the same rule shapes.

#### Scenario: Rule-body fixture canonical form is unchanged

- **WHEN** the fixture is parsed via `may_i_config::parse_config` and each resolved rule and define is rendered through the canonical-form serialiser used by trust hashing
- **THEN** the concatenated canonical output SHALL be byte-equal to a snapshot captured before this change
