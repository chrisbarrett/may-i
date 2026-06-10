## Why

The shell lexer classifies any single-literal word matching a reserved word
(`if then elif else fi for in while until do done case esac function { }`) as
that keyword token regardless of grammatical position. POSIX recognises reserved
words only in command-word position; as ordinary arguments they are literal. The
mismatch makes `may-i` **silently drop** arguments: `find . -name done` parses to
`find . -name`, `kubectl get pods in default` to `kubectl get pods`, `rm -rf done`
to `rm -rf` — with no diagnostic. `may-i` then decides on a command bash never
runs, and because nothing floors the decision, the divergence is invisible. This
is a security-model defect: argument-bearing policy can misfire or be evaded.

## What Changes

- Recognise reserved words **only in command-word position** (the start of a
  command — first word of the input, or after a command separator/operator or a
  list-introducing keyword). A reserved-word spelling appearing as an argument
  SHALL be a literal `Word` and preserved in the command's argv.
- **No silent token loss.** If a reserved-word token is encountered where the
  grammar cannot place it, the parser SHALL emit an Error-severity diagnostic so
  the decision floors to `:ask`, rather than discarding tokens. This backstops
  any residual positional case the primary rule does not cover.
- Add regression coverage: reserved words as positionals, flag values, and
  trailing arguments survive parsing; genuinely misplaced keywords floor to ask.

## Capabilities

### New Capabilities

<!-- none -->

### Modified Capabilities

- `shell-command-security-model`: add a requirement that reserved words are
  recognised only in command-word position (arguments matching a keyword
  spelling stay literal), and a requirement that the parser never silently
  discards tokens — an unplaceable reserved word emits an Error diagnostic and
  floors the decision.

## Impact

- `crates/shell-parser/src/lexer/mod.rs` — gate `read_word_or_keyword`'s keyword
  classification on a command-position flag tracked across the token stream.
- `crates/shell-parser/src/parse.rs` — emit an Error diagnostic for an
  unplaceable reserved-word token instead of breaking the simple-command loop
  and dropping it.
- Tests: `crates/shell-parser` proptests + unit scenarios; `crates/engine` if a
  decision-level regression is warranted.
- No DSL, config, or trust-hash surface change; no migration required. Compound
  commands (`if/while/for/case`) must continue to parse identically.
