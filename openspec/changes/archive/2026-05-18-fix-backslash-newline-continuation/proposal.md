## Why

The lexer does not implement POSIX line continuation: an unquoted
`\<newline>` is preserved as a literal `\n` inside the following word
instead of being removed before tokenisation. Multi-line shell commands
that Claude Code and other harnesses routinely emit (e.g.
`mkdir -p foo && \<NL>   ls bar`) parse with a phantom `"\n"` as the
first word of every continuation segment, so evaluation reports
`No rule for command `\n`` and the user sees a corrupted permission
prompt instead of a decision against the real command name.

## What Changes

- Treat an unquoted `\<newline>` as line continuation: consume both
  characters during lexing without emitting any `WordPart`, in both
  word-start and mid-word positions.
- Apply the same removal inside double-quoted strings, where POSIX
  also defines `\<newline>` as a continuation.
- Leave `\<newline>` inert (literal) inside single quotes and inside
  quoted heredoc bodies (`<<'EOF'`), matching POSIX.
- Add property and unit tests covering line continuation across
  unquoted, double-quoted, single-quoted, and heredoc contexts, plus
  a regression test reproducing the multi-line `&& \` chain from the
  2026-05-18 incident.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `shell-command-security-model`: add a requirement that unquoted
  `\<newline>` is removed before tokenisation (and the same inside
  double quotes), so the command name extracted from each segment
  matches the real shell's view.

## Impact

- Code: `crates/shell-parser/src/lexer/word_parts.rs` (unquoted and
  double-quoted readers). Heredoc reader and single-quoted reader
  verified to be unaffected.
- Tests: new cases in `crates/shell-parser/src/tests/` and an engine
  integration test exercising the multi-line `&&` chain end-to-end.
- Trust hashing: rules are hashed by their source text, not by parsed
  AST shape, so existing trust entries are unaffected. Evaluation
  outcomes change only for inputs that previously parsed incorrectly.
- No migration needed (pre-1.0; behaviour change is a bug fix that
  brings the parser closer to POSIX and to real shells).
