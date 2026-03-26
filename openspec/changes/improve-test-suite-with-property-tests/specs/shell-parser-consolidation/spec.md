## ADDED Requirements

### Requirement: Parser tests focus on behavior not structure
The shell parser test suite SHALL focus on behavioral assertions rather than structural pattern matching.

#### Scenario: Parse simple command
- **WHEN** "echo hello world" is parsed
- **THEN** extract_all_words SHALL return words containing "echo", "hello", and "world"

#### Scenario: Parse command with arguments
- **WHEN** a command with multiple arguments is parsed
- **THEN** the arguments SHALL be accessible without deep pattern matching

#### Scenario: Parse pipeline
- **WHEN** "cmd1 | cmd2 | cmd3" is parsed
- **THEN** extract_simple_commands SHALL return 3 commands

#### Scenario: Parse complex structure
- **WHEN** nested control structures are parsed
- **THEN** traversal functions SHALL visit all nested commands correctly

### Requirement: Parser tests use shared helpers
The shell parser test suite SHALL provide shared helper functions to reduce boilerplate.

#### Scenario: Parse helper function
- **WHEN** using the parse helper
- **THEN** it SHALL return a Command or panic with a clear message on parse error

#### Scenario: Assert words helper
- **WHEN** using assert_words helper
- **THEN** it SHALL verify all expected words are present in the command

#### Scenario: Assert no dynamic parts helper
- **WHEN** using assert_no_dynamic helper
- **THEN** it SHALL verify the command contains no dynamic word parts

### Requirement: Critical regression tests are preserved
The shell parser test suite SHALL preserve critical regression tests that verify specific bug fixes.

#### Scenario: Heredoc parsing edge cases
- **WHEN** parsing heredocs with various delimiters
- **THEN** all previously identified edge cases SHALL continue to work

#### Scenario: Quote handling edge cases
- **WHEN** parsing complex quote combinations
- **THEN** previously fixed quote handling bugs SHALL remain fixed

#### Scenario: Parameter expansion edge cases
- **WHEN** parsing complex parameter expansions
- **THEN** previously fixed expansion bugs SHALL remain fixed

### Requirement: Parser tests verify semantic preservation
The shell parser test suite SHALL verify that parsing preserves semantic meaning.

#### Scenario: Roundtrip serialization
- **WHEN** a command is parsed and serialized
- **THEN** the result SHALL be semantically equivalent to the original

#### Scenario: Word extraction is complete
- **WHEN** extract_all_words is called on any command
- **THEN** all literal words in the source SHALL be found

#### Scenario: Command extraction is complete
- **WHEN** extract_simple_commands is called on any command
- **THEN** all simple commands SHALL be found, including nested ones
