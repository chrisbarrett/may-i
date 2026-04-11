## ADDED Requirements

### Requirement: CommandPattern matching uses single implementation
All command pattern matching in the engine SHALL use `CommandPattern::is_match` from core. No separate matching function SHALL exist in the engine crate.

#### Scenario: Nested Or pattern matches correctly
- **WHEN** evaluating a command pattern `Or(vec![Or(vec![Literal("git"), Literal("hg")]), Literal("svn")])` against "git"
- **THEN** the match SHALL succeed via recursive dispatch through `CommandPattern::is_match`

#### Scenario: No duplicate matching function exists
- **WHEN** searching the engine crate for command pattern matching
- **THEN** no function named `match_command_pattern` SHALL exist

### Requirement: Word-to-string conversion uses single implementation
All code converting `Word` AST nodes to strings SHALL use `Word::to_str()` from shell-parser. No separate `word_to_string` function SHALL exist in the engine crate.

#### Scenario: Check module uses Word::to_str
- **WHEN** the check module converts a `Word` to a string
- **THEN** it SHALL call `word.to_str()` directly

### Requirement: Command parsing uses shared helper
A single function SHALL parse a shell string into (command_name, args) pairs. Both `cmd_eval` and `check` SHALL use this shared function.

#### Scenario: Eval command parsing
- **WHEN** `cmd_eval` parses `"git push origin main"`
- **THEN** it SHALL use the shared parser and receive `("git", ["push", "origin", "main"])`

#### Scenario: Check command parsing
- **WHEN** `check` parses a command pattern
- **THEN** it SHALL use the same shared parser

### Requirement: Arg pattern evaluation branches are unified
The Positional and Exact evaluation paths SHALL share a single code path parameterised by match mode. The only behavioural difference SHALL be whether exact count matching is enforced.

#### Scenario: Positional evaluation
- **WHEN** evaluating an Ordered pattern with mode Positional
- **THEN** matching SHALL succeed if all patterns match, regardless of remaining args

#### Scenario: Exact evaluation
- **WHEN** evaluating an Ordered pattern with mode Exact
- **THEN** matching SHALL succeed only if all patterns match AND all args are consumed

### Requirement: Span type is not duplicated
The config/migrate module SHALL use `may_i_core::Span` instead of defining its own Span struct.

#### Scenario: Migration code references core Span
- **WHEN** the migrate module needs a span
- **THEN** it SHALL use `may_i_core::Span`

### Requirement: to_source derived from to_doc
`FactPattern::to_source()` and `FactQuery::to_source()` SHALL be implemented in terms of `to_doc()` followed by serialisation, not as independent match implementations.

#### Scenario: to_source output matches to_doc serialisation
- **WHEN** calling `fact_pattern.to_source()`
- **THEN** the result SHALL equal the serialised form of `fact_pattern.to_doc()`

### Requirement: CstNode to_doc methods share implementation
`CstNode::to_doc()` SHALL be implemented in terms of `to_doc_with_trivia()` (mapping annotations away), not as a separate traversal.

#### Scenario: to_doc produces same structure as to_doc_with_trivia
- **WHEN** calling `node.to_doc()` and `node.to_doc_with_trivia().map(|_| ())`
- **THEN** the results SHALL be structurally identical

### Requirement: Migration rewrite helpers exist
Helper functions `tagged_list` and `rebuild_list` (or equivalent) SHALL exist to reduce boilerplate in migration rewrite rules.

#### Scenario: Rewrite rule uses helpers
- **WHEN** a migration rewrite function checks for a tagged list and rebuilds it
- **THEN** it SHALL use the shared helpers instead of inline guard/extract/rebuild

### Requirement: Named reference checking is not duplicated
A single function SHALL check that named predicate references are defined, used by both the defines check and the rules check in resolve.rs.

#### Scenario: Undefined ref in define
- **WHEN** a define references an undefined predicate
- **THEN** the shared checker SHALL produce an error with help text

#### Scenario: Undefined ref in rule
- **WHEN** a rule references an undefined predicate
- **THEN** the same shared checker SHALL produce an error with help text

### Requirement: Integration test JSON parsing uses shared helper
A `parse_json` helper function SHALL exist in `tests/common/` for parsing JSON from command output.

#### Scenario: Test parses JSON output
- **WHEN** an integration test needs to parse JSON from stdout
- **THEN** it SHALL call `parse_json(&output)` instead of inline `serde_json::from_slice`

### Requirement: TracingFold has config constructor
`TracingFold` SHALL have a constructor that takes config metadata (source text, pre-migration forms) in one call, replacing the chained `.with_source_text().with_pre_migration_forms()` pattern.

#### Scenario: TracingFold created from config
- **WHEN** creating a TracingFold for evaluation
- **THEN** a single constructor call SHALL set up source text and pre-migration forms
