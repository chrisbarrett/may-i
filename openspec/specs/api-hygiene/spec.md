## Requirements

### Requirement: Engine positional args use &str not &String
All functions in the engine positional arg chain SHALL accept `&str` references, not `&String`.

#### Scenario: positional_args return type
- **WHEN** calling `positional_args(args)`
- **THEN** it SHALL return `Vec<&str>`, not `Vec<&String>`

#### Scenario: match_positional_patterns parameter
- **WHEN** `match_positional_patterns` is called
- **THEN** its args parameter SHALL be `&[&str]`

### Requirement: Effect::reason returns Option<&str>
`Effect::reason()` SHALL return `Option<&str>`, not `Option<&String>`.

#### Scenario: Accessing reason
- **WHEN** calling `.reason()` on an Effect
- **THEN** the return type SHALL be `Option<&str>`

### Requirement: No redundant #[must_use] on Result functions
Functions returning `Result` SHALL NOT have `#[must_use]` attributes, since `Result` is already `#[must_use]`.

#### Scenario: parse_config
- **WHEN** inspecting `parse_config`'s attributes
- **THEN** it SHALL NOT have `#[must_use]`

### Requirement: Config submodules use minimal visibility
Config crate submodules that are only accessed via re-exports SHALL be `pub(crate)`, not `pub`.

#### Scenario: command module visibility
- **WHEN** inspecting the `command` module in config crate
- **THEN** it SHALL be `pub(crate) mod command`

### Requirement: No unused function parameters
All function parameters SHALL be used in the function body.

#### Scenario: extract_inner_command
- **WHEN** inspecting `extract_inner_command`
- **THEN** it SHALL NOT have an unused `_pattern` parameter

### Requirement: No stale task comments
Source files SHALL NOT contain leftover task-tracking comments.

#### Scenario: config.rs task comment
- **WHEN** inspecting `crates/config/src/config.rs`
- **THEN** it SHALL NOT contain "Task 2.10" or similar task references

### Requirement: Decision parsing is not duplicated
A single `parse_decision` function SHALL handle `:allow`/`:deny`/`:ask` parsing in the config crate.

#### Scenario: parse_check uses shared function
- **WHEN** `parse_check` needs to parse a decision keyword
- **THEN** it SHALL call the shared `parse_decision` function

### Requirement: ContextFacts insert_scalar and push are clarified
`ContextFacts` SHALL NOT have two methods with identical implementations and different names. Either merge them or differentiate their behaviour.

#### Scenario: Single insertion method
- **WHEN** inserting a scalar fact
- **THEN** only one method name SHALL exist for this operation, OR the two methods SHALL have clearly different semantics

### Requirement: Unnecessary clones are eliminated
Code SHALL use `std::mem::take` or move semantics instead of cloning values that are about to be discarded.

#### Scenario: Layout line accumulation
- **WHEN** pushing a completed line buffer to the output
- **THEN** the code SHALL use `take` or equivalent instead of `clone` followed by `clear`
