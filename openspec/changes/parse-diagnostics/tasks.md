## 1. Diagnostic Types

- [ ] 1.1 Define `ParseDiagnostic` struct in `crates/shell-parser/src/` — fields: `span: Span`, `kind: ParseDiagnosticKind`, `severity: Severity`
- [ ] 1.2 Define `ParseDiagnosticKind` enum — variants: `UnterminatedDoubleQuote`, `UnterminatedSingleQuote`, `UnterminatedBacktick`, `UnterminatedCommandSubstitution`, `UnterminatedArithmetic`, `UnterminatedParameterExpansion`, `MissingClosingKeyword { expected: &'static str }`, `EmptyCommand`
- [ ] 1.3 Define `Severity` enum — variants: `Warning`, `Error`
- [ ] 1.4 Define `ParseResult` struct — fields: `command: Command`, `diagnostics: Vec<ParseDiagnostic>`. Add `into_command()` convenience method.
- [ ] 1.5 Add `Span` dependency from `crates/core` to `crates/shell-parser` (or define a local span type if avoiding the dependency)

## 2. Lexer Diagnostic Emission

- [ ] 2.1 Add `diagnostics: Vec<ParseDiagnostic>` field to `Lexer` struct, with `take_diagnostics()` method
- [ ] 2.2 Emit `UnterminatedSingleQuote` in `read_until_char('\'')` when it hits EOF (in `read_word_parts` single-quote branch)
- [ ] 2.3 Emit `UnterminatedDoubleQuote` in `read_double_quoted_parts` when it hits EOF
- [ ] 2.4 Emit `UnterminatedBacktick` in `read_until_char('`')` when it hits EOF (in `read_word_parts` backtick branch)
- [ ] 2.5 Emit `UnterminatedCommandSubstitution` in `read_balanced_parens` when it hits EOF (called from `read_dollar` for `$(...)`)
- [ ] 2.6 Emit `UnterminatedArithmetic` in `read_until_double_paren` when it hits EOF
- [ ] 2.7 Emit `UnterminatedParameterExpansion` in `read_parameter_expansion` when it hits EOF
- [ ] 2.8 Track the byte offset of the opening construct (quote char, `$(`, `$((`, `${`) to set `span.start` correctly
- [ ] 2.9 Write unit tests: each unterminated construct produces exactly one diagnostic with correct kind, severity, and span

## 3. Parser Diagnostic Emission

- [ ] 3.1 Transfer lexer diagnostics to `Parser` after tokenization via `lexer.take_diagnostics()`
- [ ] 3.2 Add `diagnostics: Vec<ParseDiagnostic>` field to `Parser` struct
- [ ] 3.3 Emit `MissingClosingKeyword("fi")` in `parse_if` when `expect(Fi)` fails
- [ ] 3.4 Emit `MissingClosingKeyword("done")` in `parse_for`, `parse_while`, `parse_until` when `expect(Done)` fails
- [ ] 3.5 Emit `MissingClosingKeyword("esac")` in `parse_case` when `expect(Esac)` fails
- [ ] 3.6 Emit `MissingClosingKeyword(")")` in `parse_subshell` when `expect(RParen)` fails
- [ ] 3.7 Emit `MissingClosingKeyword("}")` in `parse_brace_group` when `expect(RBrace)` fails
- [ ] 3.8 Emit `EmptyCommand` in `parse_simple_command` when the result has no words and no assignments
- [ ] 3.9 Write unit tests: each missing keyword produces correct diagnostic

## 4. Public API Change

- [ ] 4.1 Change `parse()` return type from `Command` to `ParseResult`
- [ ] 4.2 Change `parse_simple_command()` to use `ParseResult` internally
- [ ] 4.3 Update all callers of `parse()` — cmd_eval, cmd_parse, cmd_claude_code_hook, engine (if any), shell-parser tests
- [ ] 4.4 Update snapshot tests in `crates/shell-parser/tests/` to account for new return type

## 5. Evaluator Integration

- [ ] 5.1 In `evaluate_command` (from unify-eval-pipeline), check `parse_result.diagnostics` for Error-severity items
- [ ] 5.2 If any Error-severity diagnostic exists, set `decision = max(decision, Ask)`
- [ ] 5.3 Include diagnostics in trace output (add to `TracingFold` trace entries)
- [ ] 5.4 Add `parse_diagnostics` array to JSON eval output when diagnostics are non-empty

## 6. miette Rendering

- [ ] 6.1 Define `ShellParseError` in `src/` implementing `miette::Diagnostic` with `#[source_code]`, `#[label]`, `#[help]`
- [ ] 6.2 Implement `ShellParseError::from_diagnostic(diag: &ParseDiagnostic, source: &str)` following the ConfigError pattern
- [ ] 6.3 Add help text per diagnostic kind (e.g., "the parser treated EOF as the closing quote, but this may hide operators")
- [ ] 6.4 Render diagnostics in the pretty eval trace output
- [ ] 6.5 Write integration test: `echo "unterminated` shows miette-formatted diagnostic on stderr

## 7. Integration Tests

- [ ] 7.1 Integration test: `echo "hello; rm -rf /` with echo allowed → `:ask` (Error diagnostic floors decision)
- [ ] 7.2 Integration test: `if true; then echo hello` with echo allowed → `:allow` (Warning doesn't floor)
- [ ] 7.3 Integration test: `rm "unterminated` with rm denied → `:deny` (floor is ask but deny > ask)
- [ ] 7.4 Integration test: `echo hello` → no diagnostics in JSON output
- [ ] 7.5 Integration test: JSON output for malformed input includes `parse_diagnostics` array with correct fields
