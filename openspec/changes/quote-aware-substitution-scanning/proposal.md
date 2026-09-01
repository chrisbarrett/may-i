# Proposal: Quote-aware substitution scanning

## Why

The lexer's substitution scanners count delimiters (`)`, `))`, `]`, `}`) without
honouring shell quoting. A quoted delimiter inside a command substitution — e.g.
`n=$(grep -c 'may_i(' f)` — corrupts the parse: the substitution swallows the
rest of the command, the parser loses the remaining commands, and `may-i` returns
`ask` with the misleading reason `empty command` for a well-formed bash command.
This class of mis-parse breaks authorisation for common grep/sed patterns and
masks the real command structure from every downstream decision.

## What Changes

- Make the command-substitution and process-substitution scans
  (`$(…)`, `<(…)`, `>(…)`) quote-aware: `(`, `)` and `\` inside single or double
  quotes no longer affect paren depth or terminate the scan. Backtick bodies
  inside `$(…)` are skipped like bash (quote-blind, backslash-aware).
- Make the arithmetic scans (`$((…))`, deprecated `$[…]`) quote-aware *and*
  depth-aware: nested parens/brackets are counted so a quoted or nested closing
  delimiter no longer terminates the scan early.
- Make parameter-expansion operand scanning (`${x:-…}` and every other operator
  form) respect quoting and backslash escapes: a quoted or escaped `}`, `/`, or
  `:` inside an operand no longer terminates it.
- Make array-subscript scanning (`${arr[…]}`) respect quoting for the closing
  `]`.
- Make backtick-body scanning (word context and inside double quotes) skip a
  backslash-escaped closing backtick, matching the heredoc-body scanner.
- Apply the same quote-awareness to the heredoc-body scanners so an embedded
  `$(…)` whose body contains quoted parens is captured whole.
- Unify the duplicated scanners (word-lexer readers vs heredoc byte scanners)
  on one quote-aware implementation so the two contexts cannot drift again.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `shell-command-security-model`: new requirement — quoted and escaped
  delimiter characters inside substitution/expansion constructs are literal and
  do not terminate the construct's scan; each construct family gets a scenario.

## Impact

- `crates/shell-parser/src/lexer/` — `mod.rs` (`find_balanced_paren_close`,
  `find_double_paren_close`), `string_readers.rs`
  (`read_balanced_parens_checked`, `read_until_double_paren_checked`),
  `word_parts.rs` (`$[…]` scan, backtick readers), `param_expansion.rs`
  (`read_operand`, `read_subscript`).
- Decisions for previously mis-parsed commands change from `ask` (`empty
  command` / parse-error floors) to the decision the command's real structure
  warrants. This can only narrow toward the *correct* outcome; mis-parses never
  widened toward allow (truncation always produced parse errors or lost
  commands, both of which floor at `ask`).
- No config-syntax, migration, or output-format changes.
