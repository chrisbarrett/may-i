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

### Requirement: Output-rendering crate is named may-i-output

The workspace crate hosting the `Layout` ADT, `Terminal` detection, `write_layout`, and the advisory/note/columns combinators SHALL be named `may-i-output` (Cargo package, directory, and Rust extern name `may_i_output`); the earlier name `may-i-layout` SHALL NOT appear.

#### Scenario: Cargo manifest exposes the renamed package

- **WHEN** `cargo metadata --no-deps --format-version 1` is queried for
  workspace members
- **THEN** a package named `may-i-output` is present at
  `crates/may-i-output`
- **AND** no package named `may-i-layout` is present

#### Scenario: No source file imports the old extern name

- **WHEN** the workspace is scanned for `may_i_layout` (Rust import
  identifier) under `src/` and `crates/`
- **THEN** zero matches are found
- **AND** every former import resolves to `may_i_output`

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

### Requirement: Engine crate public surface is bounded

The `may-i-engine` crate SHALL export only items that have at least one consumer outside the crate. The supported `eval` surface comprises `Evaluator`, `EvalContext`, `PredicateResult`, `evaluate`, `evaluate_with_fold`, `evaluate_command`, and `evaluate_command_with_fold`. The crate-level surface additionally comprises `EvalResult`, `SegmentDecision`, `EvalError`, the `check` module, the `trust` module, and the `fold` module's `EvalFold`, `ChildResult`, and `PureFold` items.

Items not listed above SHALL be `pub(crate)` or narrower. Re-exports for items that lack an external caller SHALL NOT exist in `crates/engine/src/eval/mod.rs` or `crates/engine/src/lib.rs`.

#### Scenario: Demoted re-exports are crate-private

- **WHEN** `crates/engine/src/eval/mod.rs` is inspected
- **THEN** `BindingValue`, `Bindings`, `parse_argv`, `EvalUnit`, `decompose`, `parser_positional_args`, and `tokenise` SHALL NOT appear in a `pub use` statement

#### Scenario: Documented surface compiles in isolation

- **WHEN** `cargo check --workspace` runs against the workspace after the visibility change
- **THEN** the build SHALL succeed without any consumer reaching for a demoted item

### Requirement: Config crate public surface is bounded

The `may-i-config` crate SHALL export only items that have at least one consumer outside the crate. The supported surface comprises `LoadResult`, `ConfigError`, `parse_rule`, `parse_config`, `parse_config_from_sexprs`, `canonicalise_forms`, `load`, `load_and_resolve`, `resolve_path`, and `walk_load_graph`, plus the `migrate` and `prelude` modules and the `resolve::validate_and_resolve` entry.

Items not listed above SHALL be `pub(crate)` or narrower. In particular, sub-form parsers that return contributor-vocabulary types (`Effect`, `Predicate`, `ArgPattern`, `Define`, `Parser`, `Style`, `CommandPattern`) SHALL NOT be publicly callable, and crate-internal helpers without external consumers (`parse_config_from_tagged_sexprs`, `load_and_resolve_with_cwd`, `discover_repo_root`, `discover_repo_local_files`) SHALL NOT be publicly callable.

#### Scenario: Demoted parsers are crate-private

- **WHEN** `crates/config/src/lib.rs` is inspected
- **THEN** `parse_define`, `parse_parser_form`, `parse_style_definition`, `parse_command_pattern`, `parse_rule_body`, and `canonicalise_node` SHALL NOT appear in a `pub use` or `pub fn` statement

#### Scenario: Unused loader and tagged-sexpr helpers are crate-private

- **WHEN** `crates/config/src/lib.rs` is inspected
- **THEN** `parse_config_from_tagged_sexprs`, `load_and_resolve_with_cwd`, `discover_repo_root`, and `discover_repo_local_files` SHALL NOT appear in a `pub use` or `pub fn` statement

#### Scenario: Documented surface compiles in isolation

- **WHEN** `cargo check --workspace` runs after the visibility change
- **THEN** the build SHALL succeed without any consumer reaching for a demoted item
