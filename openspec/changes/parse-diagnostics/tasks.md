## 1. Diagnostic Types

- [x] 1.1 Define `ParseDiagnostic` struct in `crates/shell-parser/src/` — fields: `span: Span`, `kind: ParseDiagnosticKind`, `severity: Severity`
- [x] 1.2 Define `ParseDiagnosticKind` enum — variants: `UnterminatedDoubleQuote`, `UnterminatedSingleQuote`, `UnterminatedBacktick`, `UnterminatedCommandSubstitution`, `UnterminatedArithmetic`, `UnterminatedParameterExpansion`, `MissingClosingKeyword { expected: &'static str }`, `EmptyCommand`
- [x] 1.3 Define `Severity` enum — variants: `Warning`, `Error`
- [x] 1.4 Define `ParseResult` struct — fields: `command: Command`, `diagnostics: Vec<ParseDiagnostic>`. Add `into_command()` convenience method.
- [x] 1.5 Add `Span` dependency from `crates/core` to `crates/shell-parser` (or define a local span type if avoiding the dependency)

## 2. Lexer Diagnostic Emission

- [x] 2.1 Add `diagnostics: Vec<ParseDiagnostic>` field to `Lexer` struct, with `take_diagnostics()` method
- [x] 2.2 Emit `UnterminatedSingleQuote` in `read_until_char('\'')` when it hits EOF (in `read_word_parts` single-quote branch)
- [x] 2.3 Emit `UnterminatedDoubleQuote` in `read_double_quoted_parts` when it hits EOF
- [x] 2.4 Emit `UnterminatedBacktick` in `read_until_char('`')` when it hits EOF (in `read_word_parts` backtick branch)
- [x] 2.5 Emit `UnterminatedCommandSubstitution` in `read_balanced_parens` when it hits EOF (called from `read_dollar` for `$(...)`)
- [x] 2.6 Emit `UnterminatedArithmetic` in `read_until_double_paren` when it hits EOF
- [x] 2.7 Emit `UnterminatedParameterExpansion` in `read_parameter_expansion` when it hits EOF
- [x] 2.8 Track the byte offset of the opening construct (quote char, `$(`, `$((`, `${`) to set `span.start` correctly
- [x] 2.9 Write unit tests: each unterminated construct produces exactly one diagnostic with correct kind, severity, and span

## 3. Parser Diagnostic Emission

- [x] 3.1 Transfer lexer diagnostics to `Parser` after tokenization via `lexer.take_diagnostics()`
- [x] 3.2 Add `diagnostics: Vec<ParseDiagnostic>` field to `Parser` struct
- [x] 3.3 Emit `MissingClosingKeyword("fi")` in `parse_if` when `expect(Fi)` fails
- [x] 3.4 Emit `MissingClosingKeyword("done")` in `parse_for`, `parse_while`, `parse_until` when `expect(Done)` fails
- [x] 3.5 Emit `MissingClosingKeyword("esac")` in `parse_case` when `expect(Esac)` fails
- [x] 3.6 Emit `MissingClosingKeyword(")")` in `parse_subshell` when `expect(RParen)` fails
- [x] 3.7 Emit `MissingClosingKeyword("}")` in `parse_brace_group` when `expect(RBrace)` fails
- [x] 3.8 Emit `EmptyCommand` in `parse_simple_command` when the result has no words and no assignments
- [x] 3.9 Write unit tests: each missing keyword produces correct diagnostic

## 4. Public API Change

- [x] 4.1 Change `parse()` return type from `Command` to `ParseResult`
- [x] 4.2 Change `parse_simple_command()` to use `ParseResult` internally
- [x] 4.3 Update all callers of `parse()` — cmd_eval, cmd_parse, cmd_claude_code_hook, engine (if any), shell-parser tests
- [x] 4.4 Update snapshot tests in `crates/shell-parser/tests/` to account for new return type

## 5. Evaluator Integration

- [x] 5.1 In `evaluate_command` (from unify-eval-pipeline), check `parse_result.diagnostics` for Error-severity items
- [x] 5.2 If any Error-severity diagnostic exists, set `decision = max(decision, Ask)`
- [x] 5.3 Include diagnostics in trace output (add to `TracingFold` trace entries)
- [x] 5.4 Add `parse_diagnostics` array to JSON eval output when diagnostics are non-empty

## 6. miette Rendering

- [x] 6.1 Define `ShellParseError` in `src/` implementing `miette::Diagnostic` with `#[source_code]`, `#[label]`, `#[help]`
- [x] 6.2 Implement `ShellParseError::from_diagnostic(diag: &ParseDiagnostic, source: &str)` following the ConfigError pattern
- [x] 6.3 Add help text per diagnostic kind (e.g., "the parser treated EOF as the closing quote, but this may hide operators")
- [x] 6.4 Render diagnostics in the pretty eval trace output
- [x] 6.5 Write integration test: `echo "unterminated` shows miette-formatted diagnostic on stderr

## 7. Integration Tests

- [x] 7.1 Integration test: `echo "hello; rm -rf /` with echo allowed → `:ask` (Error diagnostic floors decision)
- [x] 7.2 Integration test: `if true; then echo hello` with echo allowed → `:allow` (Warning doesn't floor)
- [x] 7.3 Integration test: `rm "unterminated` with rm denied → `:deny` (floor is ask but deny > ask)
- [x] 7.4 Integration test: `echo hello` → no diagnostics in JSON output
- [x] 7.5 Integration test: JSON output for malformed input includes `parse_diagnostics` array with correct fields
