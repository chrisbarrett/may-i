---
audience: contributor
bucket: contributor-internals
---
# code-quality Specification

## Purpose

Contributor-only. Code-quality invariants enforced by review and tooling: bans on bare `unwrap()` in production paths, bounded rewrite convergence, and no unused Cargo dependencies.

## Requirements

### Requirement: No bare unwrap in production code paths

Production code (non-test, non-debug) SHALL NOT use bare `.unwrap()`. Use `.expect("reason")` for safe invariants or proper error propagation for fallible operations.

#### Scenario: Production source is free of bare .unwrap()

- **WHEN** a CI lint or grep scans non-test, non-debug source for `\.unwrap\(\)`
- **THEN** zero matches SHALL be reported

### Requirement: Rewrite convergence is bounded

The `rewrite_until_convergence` function SHALL terminate after a maximum number of iterations (100) to prevent infinite loops from oscillating rules.

#### Scenario: Iteration cap is enforced

- **WHEN** `rewrite_until_convergence` runs against an input that never reaches a fixed point
- **THEN** it SHALL halt after at most 100 iterations and return the partially-rewritten value

### Requirement: No unused dependencies in Cargo.toml

The root binary crate SHALL NOT declare dependencies that are unused in production or test code.

#### Scenario: cargo-machete finds no unused deps

- **WHEN** `cargo-machete` (or equivalent unused-dep linter) runs against the root crate
- **THEN** zero unused dependencies SHALL be reported

### Requirement: Engine positional args use &str not &String

All functions in the engine positional arg chain SHALL accept `&str` references, not `&String`.

#### Scenario: No &String in engine positional signatures

- **WHEN** scanning the engine positional arg call chain
- **THEN** no function signature SHALL accept `&String`

### Requirement: Effect::reason returns Option<&str>

`Effect::reason()` SHALL return `Option<&str>`, not `Option<&String>`.

#### Scenario: Reason accessor signature is &str

- **WHEN** inspecting the type of `Effect::reason()`
- **THEN** the return type SHALL be `Option<&str>`

### Requirement: No redundant #[must_use] on Result functions

Functions returning `Result` SHALL NOT have `#[must_use]` attributes, since `Result` is already `#[must_use]`.

#### Scenario: No redundant attribute on Result fns

- **WHEN** grepping source for `#[must_use]` attached to a `Result`-returning function
- **THEN** zero matches SHALL be reported

### Requirement: Config submodules use minimal visibility

Config crate submodules that are only accessed via re-exports SHALL be `pub(crate)`, not `pub`.

#### Scenario: Internally re-exported modules are pub(crate)

- **WHEN** a config submodule is only used through a re-export
- **THEN** the module declaration SHALL be `pub(crate)`

### Requirement: No unused function parameters

All function parameters SHALL be used in the function body.

#### Scenario: Clippy flags unused params

- **WHEN** `cargo clippy` runs on the workspace
- **THEN** no `unused_variables` or unused-parameter lint SHALL fire

### Requirement: No stale task comments

Source files SHALL NOT contain leftover task-tracking comments.

#### Scenario: No TODO/FIXME task markers

- **WHEN** grepping source for task-tracking markers (e.g. `TODO`, `FIXME`, `XXX`)
- **THEN** zero matches SHALL be reported in committed code

### Requirement: Decision parsing is not duplicated

A single `parse_decision` function SHALL handle `:allow`/`:deny`/`:ask` parsing in the config crate.

#### Scenario: One parse_decision in the config crate

- **WHEN** searching the config crate for decision-keyword parsers
- **THEN** exactly one `parse_decision` function SHALL exist

### Requirement: ContextFacts insert_scalar and push are clarified

`ContextFacts` SHALL NOT have two methods with identical implementations and different names.

#### Scenario: insert_scalar and push are distinct or merged

- **WHEN** inspecting `ContextFacts` methods
- **THEN** any two methods SHALL differ in implementation or be collapsed into one

### Requirement: Unnecessary clones are eliminated

Code SHALL use `std::mem::take` or move semantics instead of cloning values that are about to be discarded.

#### Scenario: Clippy redundant_clone is clean

- **WHEN** `cargo clippy` runs on the workspace
- **THEN** no `redundant_clone` lint SHALL fire

### Requirement: CommandPattern matching uses single implementation

All command pattern matching in the engine SHALL use `CommandPattern::is_match` from core. No separate matching function SHALL exist in the engine crate.

#### Scenario: Only CommandPattern::is_match in engine

- **WHEN** scanning the engine crate for command-pattern matching call sites
- **THEN** every site SHALL call `CommandPattern::is_match`; no parallel matcher SHALL be defined in the engine

### Requirement: Word-to-string conversion uses single implementation

All code converting `Word` AST nodes to strings SHALL use `Word::to_str()` from shell-parser.

#### Scenario: Single Word-to-string path

- **WHEN** scanning for `Word` → `String` / `&str` conversions
- **THEN** every conversion SHALL go through `Word::to_str()`

### Requirement: Command parsing uses shared helper

A single function SHALL parse a shell string into (command_name, args) pairs. Both `cmd_eval` and `check` SHALL use this shared function.

#### Scenario: cmd_eval and check share the parser

- **WHEN** inspecting `cmd_eval` and `check` for the shell-string split
- **THEN** both SHALL call the same shared helper

### Requirement: Arg pattern evaluation branches are unified

The Positional and Exact evaluation paths SHALL share a single code path parameterised by match mode.

#### Scenario: One code path for Positional and Exact

- **WHEN** inspecting arg-pattern evaluation
- **THEN** Positional and Exact SHALL be implemented by one function dispatching on match mode

### Requirement: Span type is not duplicated

The config/migrate module SHALL use `may_i_core::Span` instead of defining its own Span struct.

#### Scenario: config/migrate imports core Span

- **WHEN** inspecting `config/migrate` for `Span` definitions
- **THEN** no local `Span` struct SHALL exist; the module SHALL import `may_i_core::Span`

### Requirement: to_source derived from to_doc

`FactPattern::to_source()` and `FactQuery::to_source()` SHALL be implemented in terms of `to_doc()` followed by serialisation, not as independent implementations.

#### Scenario: to_source delegates to to_doc

- **WHEN** inspecting the implementations of `FactPattern::to_source()` and `FactQuery::to_source()`
- **THEN** each SHALL be expressed as `self.to_doc().serialize()` (or equivalent), not a parallel walk

### Requirement: CstNode to_doc methods share implementation

`CstNode::to_doc()` SHALL be implemented in terms of `to_doc_with_trivia()`, not as a separate traversal.

#### Scenario: to_doc calls to_doc_with_trivia

- **WHEN** inspecting `CstNode::to_doc()`
- **THEN** the body SHALL call `to_doc_with_trivia()` rather than re-walking the tree

### Requirement: Migration rewrite helpers exist

Helper functions `tagged_list` and `rebuild_list` (or equivalent) SHALL exist to reduce boilerplate in migration rewrite rules.

#### Scenario: Helpers are defined and used

- **WHEN** inspecting the migration crate
- **THEN** `tagged_list` and `rebuild_list` (or equivalents) SHALL exist and SHALL be used by rewrite rules

### Requirement: Named reference checking is not duplicated

A single function SHALL check that named predicate references are defined, used by both the defines check and the rules check.

#### Scenario: One named-reference checker

- **WHEN** inspecting the defines check and the rules check
- **THEN** both SHALL call the same named-reference checker

### Requirement: Integration test JSON parsing uses shared helper

A `parse_json` helper function SHALL exist in `tests/common/` for parsing JSON from command output.

#### Scenario: tests/common provides parse_json

- **WHEN** an integration test parses JSON from `may-i` command output
- **THEN** it SHALL call `tests/common::parse_json`

### Requirement: TracingFold has config constructor

`TracingFold` SHALL have a constructor that takes config metadata (source text, pre-migration forms) in one call.

#### Scenario: Single constructor accepts metadata

- **WHEN** instantiating `TracingFold` from CLI code
- **THEN** a single constructor SHALL accept source text and pre-migration forms in one call

### Requirement: Advisory note builders are pure functions owned by their data module

Advisory `Layout` builders for trust state (warning, integrity) and migration notices SHALL be pure functions returning `Option<Layout>` or `Layout` and performing no IO. Each builder SHALL live in the module that owns its data — `trust_advisory` for trust-state advisories; the migration command or a sibling notes module for migration notices — NOT in `output`. The `output` module SHALL expose only layout primitives and trace-rendering functions; it SHALL NOT export domain-specific advisory builders. Builder inputs SHALL be the domain data (`Config`, trust-store result, loaded forms) and SHALL NOT leak flattened internal structs across module boundaries.

#### Scenario: Trust advisory warning builder is pure and returns None when nothing to warn about

- **WHEN** `trust_advisory::build_warning_layout(&config)` is called against a config whose loaded rules are all trusted
- **THEN** the function returns `None`
- **AND** no IO occurs

#### Scenario: Trust advisory warning builder returns Some(Layout) when untrusted rules exist

- **WHEN** `trust_advisory::build_warning_layout(&config)` is called against a config with untrusted loaded rules
- **THEN** the function returns `Some(Layout)` matching the rendered output specified in `trust-advisory-boxes`
- **AND** no IO occurs

#### Scenario: Output module exposes only primitives

- **WHEN** the public API of `output` is inspected
- **THEN** no domain-specific advisory builders (e.g. `trust_warning_note`, `trust_integrity_note`, `migration_note`) are exported
- **AND** layout primitives (`Layout`, `Advisory`, `Note`, `write_layout`, `strip_ansi`, `HRuleLabel`, `NoteLevel`, `Terminal`, `ColRow`, `ColAlign`) and trace-rendering functions (`print_trace`, `write_trace`, `trace_to_json`, `colorize_decision_keyword`) remain

#### Scenario: Migration note imported from migration / notes module

- **WHEN** `migration_note` is imported by `cmd_eval` or `cmd_check`
- **THEN** the import path is the migration / notes module, not `output`

#### Scenario: Migration note rendered output is byte-equal to existing form

- **WHEN** a config with pre-migration forms is loaded and the migration note is rendered to stderr
- **THEN** the produced text is byte-equal to today's output for the same config
