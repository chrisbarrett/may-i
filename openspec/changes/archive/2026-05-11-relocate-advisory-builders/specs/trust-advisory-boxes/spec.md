## ADDED Requirements

### Requirement: Trust advisory builders are pure functions
The Trust advisory builders SHALL be pure functions returning `Option<Layout>` (warning box) or `Layout` (integrity box), performing no IO. They SHALL live in `src/trust_advisory.rs` (the module owning the data) rather than in `src/output/mod.rs`. Their input shapes SHALL NOT leak across module boundaries: callers pass the trust config or the trust-store result, not flattened internal data structures.

#### Scenario: Warning builder returns None when no untrusted rules
- **WHEN** `trust_advisory::build_warning_layout(&config)` is called and no
  loaded rules are untrusted
- **THEN** the function returns `None`
- **AND** no IO occurs

#### Scenario: Warning builder returns a Layout when untrusted rules exist
- **WHEN** the same call is made against a config with untrusted loaded
  rules
- **THEN** the function returns `Some(Layout)` whose rendered output
  matches the existing requirement scenarios in this spec (heading,
  body, suggestion)
- **AND** the function performs no IO

#### Scenario: Integrity builder returns a Layout
- **WHEN** `trust_advisory::build_integrity_layout(store_path, suspects)`
  is called
- **THEN** the function returns a `Layout` matching the existing integrity
  requirement scenarios
- **AND** the function performs no IO

#### Scenario: Output module no longer exports advisory builders
- **WHEN** the `src/output/mod.rs` public API is inspected
- **THEN** `migration_note`, `trust_warning_note`, and
  `trust_integrity_note` are no longer exported from `output`
- **AND** the trace-rendering functions (`print_trace`, `write_trace`,
  `trace_to_json`, `colorize_decision_keyword`) remain
- **AND** layout primitive re-exports (`Layout`, `Advisory`, `Note`,
  `Terminal`, `ColRow`, `ColAlign`, `write_layout`, `strip_ansi`,
  `HRuleLabel`, `NoteLevel`) remain

### Requirement: Migration note builder lives outside output
The migration advisory note builder SHALL live in the module that owns its data (the migration command or a sibling notes module), not in `src/output/mod.rs`. Its signature SHALL remain `(loaded, config_path) -> Option<Layout>` and its rendered text SHALL be byte-equal to today's output.

#### Scenario: Builder lives in cmd_migrate or a notes module
- **WHEN** `migration_note` is imported by `cmd_eval` or `cmd_check`
- **THEN** the import path is the migration / notes module, not `output`

#### Scenario: Rendered output is unchanged
- **WHEN** a config with pre-migration forms is loaded and the migration
  note is rendered to stderr
- **THEN** the produced text is byte-equal to today's output for the same
  config
