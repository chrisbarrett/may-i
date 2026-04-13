## Requirements

### Requirement: No bare unwrap in production code paths
Production code (non-test, non-debug) SHALL NOT use bare `.unwrap()`. Use `.expect("reason")` for safe invariants or proper error propagation for fallible operations.

### Requirement: Rewrite convergence is bounded
The `rewrite_until_convergence` function SHALL terminate after a maximum number of iterations (100) to prevent infinite loops from oscillating rules.

### Requirement: No unused dependencies in Cargo.toml
The root binary crate SHALL NOT declare dependencies that are unused in production or test code.

### Requirement: Engine positional args use &str not &String
All functions in the engine positional arg chain SHALL accept `&str` references, not `&String`.

### Requirement: Effect::reason returns Option<&str>
`Effect::reason()` SHALL return `Option<&str>`, not `Option<&String>`.

### Requirement: No redundant #[must_use] on Result functions
Functions returning `Result` SHALL NOT have `#[must_use]` attributes, since `Result` is already `#[must_use]`.

### Requirement: Config submodules use minimal visibility
Config crate submodules that are only accessed via re-exports SHALL be `pub(crate)`, not `pub`.

### Requirement: No unused function parameters
All function parameters SHALL be used in the function body.

### Requirement: No stale task comments
Source files SHALL NOT contain leftover task-tracking comments.

### Requirement: Decision parsing is not duplicated
A single `parse_decision` function SHALL handle `:allow`/`:deny`/`:ask` parsing in the config crate.

### Requirement: ContextFacts insert_scalar and push are clarified
`ContextFacts` SHALL NOT have two methods with identical implementations and different names.

### Requirement: Unnecessary clones are eliminated
Code SHALL use `std::mem::take` or move semantics instead of cloning values that are about to be discarded.

### Requirement: CommandPattern matching uses single implementation
All command pattern matching in the engine SHALL use `CommandPattern::is_match` from core. No separate matching function SHALL exist in the engine crate.

### Requirement: Word-to-string conversion uses single implementation
All code converting `Word` AST nodes to strings SHALL use `Word::to_str()` from shell-parser.

### Requirement: Command parsing uses shared helper
A single function SHALL parse a shell string into (command_name, args) pairs. Both `cmd_eval` and `check` SHALL use this shared function.

### Requirement: Arg pattern evaluation branches are unified
The Positional and Exact evaluation paths SHALL share a single code path parameterised by match mode.

### Requirement: Span type is not duplicated
The config/migrate module SHALL use `may_i_core::Span` instead of defining its own Span struct.

### Requirement: to_source derived from to_doc
`FactPattern::to_source()` and `FactQuery::to_source()` SHALL be implemented in terms of `to_doc()` followed by serialisation, not as independent implementations.

### Requirement: CstNode to_doc methods share implementation
`CstNode::to_doc()` SHALL be implemented in terms of `to_doc_with_trivia()`, not as a separate traversal.

### Requirement: Migration rewrite helpers exist
Helper functions `tagged_list` and `rebuild_list` (or equivalent) SHALL exist to reduce boilerplate in migration rewrite rules.

### Requirement: Named reference checking is not duplicated
A single function SHALL check that named predicate references are defined, used by both the defines check and the rules check.

### Requirement: Integration test JSON parsing uses shared helper
A `parse_json` helper function SHALL exist in `tests/common/` for parsing JSON from command output.

### Requirement: TracingFold has config constructor
`TracingFold` SHALL have a constructor that takes config metadata (source text, pre-migration forms) in one call.
