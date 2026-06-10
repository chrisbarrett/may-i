## Context

`crates/shell-parser/src/lexer/mod.rs::read_word_or_keyword` classifies a word
as a keyword token (`If`, `While`, `Do`, `Done`, …) whenever the word is a
single literal matching the spelling — with no regard to position. The
token-driven parser (`parse.rs`) then treats those tokens structurally. When a
keyword spelling lands in argument position, `parse_simple_command` hits the
keyword token, breaks its word-collection loop, and the trailing tokens are
swallowed by compound-command parsing without a diagnostic. Result: `find .
-name done` → `find . -name`, `kubectl get pods in default` → `kubectl get
pods`, with empty `diagnostics`. `may-i` evaluates a command bash never runs and
nothing floors the decision.

POSIX 2.10.2 recognises reserved words only in command-word position. Bash
follows this. The fix is to make the parser positional and to refuse to drop
tokens silently.

## Goals / Non-Goals

**Goals:**

- A reserved-word spelling in argument position stays a literal `Word` and is
  preserved in argv.
- Compound commands (`if`/`while`/`until`/`for`/`case`/brace groups) parse
  identically to today.
- No token is silently discarded; an unplaceable reserved word emits an Error
  diagnostic so the existing floor engages.

**Non-Goals:**

- A full rewrite to a parser-side reserved-word resolver (lexer always emits
  `Word`). Tempting and more POSIX-faithful, but a larger refactor of the
  token-matching parser; deferred.
- History expansion, `[[ … ]]` conditional-expression keywords, and other
  bash-only lexical contexts.

## Decisions

### D1 — Track command-word position in the lexer

`read_word_or_keyword` classifies a keyword only when an `at_command_position`
flag is set. The flag is:

- `true` at start of input;
- set `true` after emitting a separator/operator (`;`, `&`, newline, `|`, `||`,
  `&&`, `(`) and after a list-introducing keyword (`do`, `then`, `else`,
  `elif`, `{`);
- left `true` across leading assignment words (`VAR=val`) so the command word
  that follows is still eligible;
- set `false` after emitting an ordinary `Word` (an argument).

So `done` after `-name` (position `false`) stays a `Word`; `done` after `;`
(position `true`) is the `Done` keyword.

- *Why a lexer flag over parser-side resolution:* the parser matches concrete
  `Token::If/While/…` variants throughout; threading positional resolution into
  it is a broad change. The command-position flag is the standard shell-lexer
  technique and localises the fix. The fuller refactor is recorded as a
  non-goal, not foreclosed.

### D2 — Resolve `in` in the parser, not the lexer

`for NAME in WORDS` and `case WORD in` put `in` *after* an argument-position
word, so a command-position flag cannot recognise it. Remove `in` from lexer
keyword classification entirely and have `parse_for`/`parse_case` consume a
literal `in` `Word` (replacing the current `matches!(peek, Token::In)` check).

- This makes `in` as an argument (`kubectl get pods in default`) always literal,
  and keeps for/case working by handling `in` where its grammar position is
  actually known.

### D3 — Emit a diagnostic instead of dropping tokens

Where `parse_simple_command` (and the list parser) currently `break` on an
unexpected reserved-word token and let it fall away, the parser SHALL instead,
when no enclosing construct claims that token, push an Error-severity
`ParseDiagnostic`. The existing "Error-severity diagnostics floor decision at
ask" requirement then forces the decision to `:ask`. This backstops any
positional case D1/D2 do not perfectly cover — divergence becomes visible
rather than silent.

## Risks / Trade-offs

- **for/case regressions** → `in`/`esac`/`do`/`done` recognition changes shape;
  guard with explicit parse scenarios and the existing `parser_snapshots.rs`
  suite (AST for well-formed compound commands must be unchanged).
- **Assignment-prefixed commands** (`FOO=1 do_thing`) → position must stay
  `true` through assignments; covered by D1 and a unit test.
- **Brace groups** (`{ cmd; }`) → `{`/`}` recognised only in command position;
  `echo }` keeps `}` literal. Verify both.
- **Under-flooring** → if D3's diagnostic is missed for some construct, a token
  could still be dropped silently. Mitigation: a proptest asserting that the
  concatenation of evaluated tokens covers the input's command words (no word
  vanishes without a diagnostic).

## Open Questions

- Should `function` keep keyword status at all? Agent commands rarely define
  functions; if it causes friction it could be downgraded to always-literal,
  but default is to keep it positional like the others.
