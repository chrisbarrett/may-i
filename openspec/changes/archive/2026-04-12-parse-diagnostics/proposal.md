## Why

The shell parser currently never fails — it silently recovers from all malformed
input, producing a best-effort AST. This means syntactically invalid commands
like `echo "hello; rm -rf /` (unterminated quote that could hide operators)
are evaluated without any indication that the parse was ambiguous. In a security
tool, silent recovery from ambiguous input is dangerous: it can produce
`:allow` decisions for input the parser didn't fully understand.

See: [shell-command-security-model](../../specs/shell-command-security-model/spec.md)
requirement R4.

## What Changes

1. **The parser returns `ParseResult` instead of `Command`**, containing both
   the best-effort AST and a list of diagnostics.

2. **Each recovery point in the parser/lexer emits a diagnostic** with a byte
   span, a kind enum, and a severity level (Warning or Error).

3. **Error-severity diagnostics cause the evaluator to floor the decision at
   `:ask`** — the best-effort AST is still evaluated for trace output, but the
   final decision cannot be `:allow` if the parse was ambiguous.

4. **Diagnostics convert to miette `Diagnostic` at the CLI boundary** using the
   same two-stage pattern as config errors (`ParseDiagnostic` → `ShellParseError`).

5. **JSON output includes a `parse_diagnostics` array** when diagnostics are
   present.

## Capabilities

### Spec Alignment

- [shell-command-security-model](../../specs/shell-command-security-model/spec.md)
  — R4 (parse error reporting), R4.1–R4.4

### Affected Components

- `crates/shell-parser/src/lib.rs` — new `ParseResult` return type
- `crates/shell-parser/src/parse.rs` — emit diagnostics at recovery points
- `crates/shell-parser/src/lexer/` — emit diagnostics for unterminated
  quotes/substitutions
- `crates/core/src/span.rs` — reuse existing `Span` type
- `src/cmd_eval.rs` — check diagnostics, floor decision, include in trace
- `src/cmd_claude_code_hook.rs` — check diagnostics, include in response

### New Types

```rust
// In crates/shell-parser
pub struct ParseResult {
    pub command: Command,
    pub diagnostics: Vec<ParseDiagnostic>,
}

pub struct ParseDiagnostic {
    pub span: Span,
    pub kind: ParseDiagnosticKind,
    pub severity: Severity,
}
```

### Unchanged

- Parser error recovery behaviour — the AST output for any given input should be
  identical. We are adding diagnostics alongside the existing recovery, not
  changing the recovery itself.

## Dependencies

- Should be implemented after `unify-eval-pipeline`, since that change
  establishes the single evaluation function where diagnostic checking is added.

## Risks

- **Breaking API change in shell-parser**: `parse()` return type changes from
  `Command` to `ParseResult`. All callers must be updated. This is a small,
  contained set (cmd_eval, cmd_parse, cmd_claude_code_hook, tests, engine).

- **False positives**: Overly aggressive Error severity could cause legitimate
  commands to be blocked. The severity guidelines in the spec (R4.2) are
  conservative — only unterminated quotes/substitutions are Error severity,
  because those are the cases where the parse boundary is genuinely ambiguous.

- **Unterminated single quotes**: These are Error severity even though bash
  itself would wait for the closing quote. In may-i's context, input is always
  a complete command string — an unterminated quote means the input is malformed,
  not incomplete.
