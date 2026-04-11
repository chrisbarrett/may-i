## Context

The shell parser (`crates/shell-parser`) currently has an infallible API:
`parse(input: &str) → Command`. It silently recovers from all malformed input
— unterminated quotes, missing closing keywords, bare operators — producing a
best-effort AST without signalling that the parse was ambiguous.

This is a security concern: `echo "hello; rm -rf /` (unterminated double quote)
currently parses as `echo "hello; rm -rf /"` (everything after the opening
quote becomes a single quoted string). The evaluator sees `echo` with one
argument and may return `:allow`, not realising that a semicolon and `rm` may
have been intended as separate commands.

The config parser (`crates/config`) already has a mature two-stage error
pattern:

1. **RawError** (crates/sexpr): internal, carries `Span` + message, no source
2. **ConfigError** (crates/config): miette `Diagnostic` with `#[source_code]`,
   `#[label]`, `#[help]` — rendered at the CLI boundary

The shell parser should adopt the same pattern.

## Goals / Non-Goals

**Goals:**

- Parser returns diagnostics alongside the best-effort AST
- Each diagnostic has a byte-offset span, kind enum, and severity level
- Error-severity diagnostics cause the evaluator to floor the decision at `:ask`
- Diagnostics render as miette diagnostics in the CLI (pretty and JSON)
- The parser's recovery behaviour is unchanged — same AST output for same input
- JSON eval output includes a `parse_diagnostics` array when diagnostics exist

**Non-Goals:**

- Changing what the parser recovers to (the AST remains best-effort)
- Adding miette as a dependency to `crates/shell-parser` (diagnostics use
  `Span` from `crates/core`, converted to miette at the CLI boundary)
- Handling all possible POSIX syntax errors (we target the constructs already
  in the parser)

## Decisions

### D1: `ParseResult` replaces `Command` as the public return type

**Decision**: `parse()` returns `ParseResult { command: Command, diagnostics:
Vec<ParseDiagnostic> }`. A convenience method `.into_command()` provides
migration ease for callers that don't need diagnostics.

**Alternatives considered**:

- *Return `Result<Command, ParseError>`*: This would make the parser fallible
  and force callers to handle errors. But the parser always produces a useful
  AST — we don't want to discard it. Rejected.
- *Thread diagnostics through a callback/collector*: More flexible but more
  complex. The parser is single-pass, so collecting into a Vec is simpler and
  sufficient. Rejected.

### D2: Diagnostics collected by the Parser, not the Lexer

**Decision**: The `Parser` struct owns a `Vec<ParseDiagnostic>` and passes a
mutable reference to `Lexer` methods that need to emit diagnostics. The lexer
methods that currently silently recover (e.g., `read_until_char` at EOF,
`read_balanced_parens` at EOF) will push diagnostics when they hit EOF
unexpectedly.

**Rationale**: The lexer is stateless between tokens (it produces a flat token
stream). The parser has the structural context to determine severity — e.g., an
unterminated quote in the lexer is always an Error, but a missing `fi` is only
detectable in the parser.

**Implementation**: The `Lexer` gains a `diagnostics: Vec<ParseDiagnostic>`
field. The `Parser` takes ownership of it after tokenization via
`lexer.take_diagnostics()`.

### D3: Two severity levels: Warning and Error

**Decision**: Per the spec (R4.2):

- **Error**: The parse boundary is genuinely ambiguous — the AST might not
  represent what the shell would execute. Unterminated quotes and substitutions.
- **Warning**: The parser recovered and the AST is likely correct, just
  structurally incomplete. Missing closing keywords, empty commands.

**Alternatives considered**:

- *Single severity*: Simpler, but conflates harmless incompletes (missing `fi`)
  with dangerous ambiguities (unterminated quotes). The evaluator needs to
  distinguish these to decide whether to floor at `:ask`.
- *Three levels (Info/Warning/Error)*: No clear use case for Info in a
  security context.

### D4: Diagnostic emission points

The following recovery points emit diagnostics:

**Lexer (during tokenization):**

| Recovery point | Kind | Severity |
|---|---|---|
| `read_until_char('\'')` hits EOF | `UnterminatedSingleQuote` | Error |
| `read_double_quoted_parts` hits EOF | `UnterminatedDoubleQuote` | Error |
| `read_until_char('`')` hits EOF | `UnterminatedBacktick` | Error |
| `read_balanced_parens` hits EOF | `UnterminatedCommandSubstitution` | Error |
| `read_until_double_paren` hits EOF | `UnterminatedArithmetic` | Error |
| `read_parameter_expansion` hits EOF | `UnterminatedParameterExpansion` | Error |

**Parser (during AST construction):**

| Recovery point | Kind | Severity |
|---|---|---|
| `parse_if`: `expect(Fi)` fails | `MissingClosingKeyword("fi")` | Warning |
| `parse_for`/`parse_while`/`parse_until`: `expect(Done)` fails | `MissingClosingKeyword("done")` | Warning |
| `parse_case`: `expect(Esac)` fails | `MissingClosingKeyword("esac")` | Warning |
| `parse_subshell`: `expect(RParen)` fails | `MissingClosingKeyword(")")` | Warning |
| `parse_brace_group`: `expect(RBrace)` fails | `MissingClosingKeyword("}")` | Warning |
| `parse_simple_command`: produces empty command | `EmptyCommand` | Warning |

### D5: miette conversion at the CLI boundary

**Decision**: A new `ShellParseError` type in `src/` (not in the parser crate)
implements `miette::Diagnostic`:

```rust
#[derive(Debug, Error, Diagnostic)]
#[error("{message}")]
pub struct ShellParseError {
    message: String,
    #[source_code]
    src: NamedSource<String>,
    #[label]
    span: SourceSpan,
    #[help]
    help: Option<String>,
}
```

Constructed from `ParseDiagnostic` + the original command string, following the
same pattern as `ConfigError::from_raw`.

### D6: Evaluator integration

**Decision**: The unified `evaluate_command` function (from
`unify-eval-pipeline`) checks `parse_result.diagnostics` after parsing:

1. Evaluate the AST normally (for trace output)
2. If any diagnostic has `Severity::Error`, set `decision = max(decision, Ask)`
3. Include diagnostics in the trace and JSON output

The JSON response gains an optional field:

```json
{
  "decision": "ask",
  "reason": "...",
  "parse_diagnostics": [
    {
      "span": { "start": 5, "end": 5 },
      "kind": "unterminated_double_quote",
      "severity": "error",
      "message": "unterminated double quote"
    }
  ]
}
```

### D7: Span tracking in the lexer

**Decision**: The lexer already tracks `byte_pos`. Each diagnostic records
`Span { start, end }` where `start` is the byte offset of the opening
construct (e.g., the `"` that starts a double quote) and `end` is the byte
offset where recovery occurred (typically EOF = `input.len()`).

No additional tracking infrastructure is needed.

## Risks / Trade-offs

**[Breaking API change]** `parse()` return type changes from `Command` to
`ParseResult`. → Provide `.into_command()` for simple migration. The number of
call sites is small (cmd_eval, cmd_parse, cmd_claude_code_hook, engine tests,
shell-parser tests).

**[False positives for Error severity]** Unterminated single quotes are
flagged as Error even though the parser's recovery (treating EOF as close) is
usually correct. → In may-i's context, the input is always a complete command.
An unterminated quote is genuinely malformed, not "waiting for more input". The
`:ask` floor is the correct conservative response.

**[Diagnostic noise]** Some commands intentionally use unusual quoting that
the parser handles fine but might trigger warnings. → Only Error diagnostics
affect the decision. Warnings are informational and appear in the trace but
don't change the outcome.
