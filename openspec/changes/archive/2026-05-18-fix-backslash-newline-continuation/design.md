## Context

POSIX 2.2.1 specifies that an unquoted `\<newline>` is a line
continuation: both characters are removed before the input is split
into tokens. The current lexer in `crates/shell-parser/src/lexer/`
treats `\` followed by any character (including `\n`) as a
quote-the-next-character escape and emits the escaped character as a
`WordPart::Literal`.

Concretely, for input ending `… && \<NL>   ls bar`:

1. `tokenize_with_offsets` at `crates/shell-parser/src/lexer/mod.rs:121`
   tokenises `&&`, then `skip_whitespace` at `mod.rs:95` consumes the
   space after `&&` (it does not look at `\`).
2. The default branch at `mod.rs:183` calls `read_word_or_keyword`,
   which drops into `read_word_parts`.
3. In `read_word_parts` at `crates/shell-parser/src/lexer/word_parts.rs:123`,
   the backslash case advances past `\\`, then advances past the next
   byte (`\n`) and pushes it as `WordPart::Literal("\n")`.
4. The very next byte is `' '` — a metacharacter — so the word ends.
   The resulting first word of the continuation segment is `["\n"]`.
5. `decompose` at `crates/engine/src/eval/decompose.rs:75` calls
   `first_word.to_str()` and sets the command name to `"\n"`. The
   engine reports `No rule for command `\n``.

Reproduced live with `may-i parse -f -` on the 2026-05-18 incident
input from the multi-bulk-archive command.

POSIX line-continuation rules (2.2.1 and 2.3) by context:

| Context                          | `\<NL>` behaviour                                  |
|----------------------------------|----------------------------------------------------|
| Unquoted                         | Both characters removed (line continuation)        |
| Inside `"…"`                     | Both characters removed (line continuation)        |
| Inside `'…'`                     | Literal `\` followed by literal `\n` (no escape)   |
| Inside `<<'EOF' … EOF`           | Literal (heredoc body, no expansion)               |
| Inside `<<EOF … EOF` (unquoted)  | Literal `\<NL>` — heredoc bodies do not continue   |

## Goals / Non-Goals

**Goals:**

- Make the lexer's first-word output for a continuation segment match
  what a real shell sees: the command name on the line after `\<NL>`,
  not a phantom `"\n"`.
- Cover unquoted and double-quoted contexts; preserve correct
  (literal) behaviour in single quotes and heredoc bodies.
- Add property-test coverage so future lexer rewrites cannot regress.

**Non-Goals:**

- Reworking the lexer's escape model in general. Only the
  `\<newline>` pair changes; `\$`, `\"`, `\\`, etc. keep current
  behaviour.
- Surfacing line continuation in diagnostics or the AST. It is
  silently elided per POSIX.
- Touching the segmentation / span bookkeeping. Spans continue to
  refer to byte offsets in the original input; the `\<NL>` bytes are
  inside the segment range but contribute no word content.

## Decisions

### Decision 1: Handle line continuation inside the `\\` arm of each word reader, not as an input pre-pass

Two viable approaches were considered:

- **Pre-pass over the input bytes**, deleting every unquoted
  `\<newline>` before the lexer runs. Simplest implementation; but
  it would corrupt byte spans across the parser/engine boundary
  (every offset after the deletion shifts), violating the
  `parser-engine-invariants` requirements on span bounds and
  embedded-source-equals-slice. It would also have to know about
  every quoting context to skip them — duplicating logic the lexer
  already encodes.

- **Per-reader handling**: detect `'\\' '\n'` inside the existing
  backslash arms in `read_word_parts` and `read_double_quoted_parts`
  and consume both characters without emitting a `WordPart`. The
  byte cursor (`self.pos` / `self.byte_pos`) advances past both, so
  spans continue to refer to the original input. The single-quoted
  reader and heredoc body reader are not modified, so POSIX
  literal-in-single-quotes / literal-in-heredoc behaviour is
  preserved by construction.

**Chosen: per-reader handling.** Preserves span invariants, contains
the change to two short arms, and keeps the lexer state machine
intact.

Two follow-on adjustments fall out of the chosen approach:

- **Empty-word fallback in `read_word_or_keyword`.** When `\<NL>` is
  the only content at a tokenizer dispatch boundary (e.g. the input
  ends `&& \<NL>   ls bar` — `skip_whitespace` consumes the single
  space after `&&`, the dispatcher then calls into the word reader
  on `\`), `read_word_parts` consumes both bytes and returns an empty
  parts vector. The previous invariant — "called at non-metachar ⇒
  at least one part" — is loosened: `read_word_or_keyword` returns
  `None` in that case, and the outer tokenizer loop makes progress
  via the cursor advance and re-enters `skip_whitespace`.
- **Adjacent-`Literal` merge in the default literal arm of
  `read_word_parts`.** Mid-word continuation (`ec\<NL>ho`) would
  otherwise produce two adjacent `Literal` parts (`"ec"`, `"ho"`),
  and `SimpleCommand::command_name` only inspects the first literal
  — it would report `"ec"`. The default arm now appends into the
  trailing `Literal` when one is present, collapsing the word to a
  single `Literal("echo")`. The merge is unconditional (not gated
  on `\<NL>`), which incidentally tidies pre-existing shapes:
  `hello\ world` now parses as `[Literal("hello"), Literal(" world")]`
  instead of three parts, and `{foo}` (unmatched brace expansion)
  as `[Literal("{foo}")]` instead of two. Two parser snapshots
  (`backslash_escape_outside_quotes`, `brace_no_comma_is_literal`)
  were regenerated to reflect this; `Word::to_str()` output is
  unchanged in every case.

### Decision 2: Apply inside double quotes, not only outside quotes

POSIX 2.2.3 lists `\<newline>` as one of the few sequences that retain
their escape meaning inside double quotes. Real shells (bash, dash,
zsh) all elide it. The `read_double_quoted_parts` reader at
`crates/shell-parser/src/lexer/word_parts.rs:161` already has its own
backslash handling; the same `('\\' followed by '\n') ⇒ consume both`
rule is added there.

### Decision 3: No new diagnostic kind

A `\<newline>` inside single quotes or a heredoc body remains literal
— the parser already handles these contexts correctly because their
readers do not have the offending backslash arm. No new
`ParseDiagnostic` kind is needed; line continuation is silent in POSIX
shells and should be silent here.

### Decision 4: Spec home — `shell-command-security-model`

The behaviour is user-observable (controls which command name the
authorisation rules see). `shell-command-security-model` already owns
analogous lexer-level requirements such as `#` only starting a comment
at a token boundary (`openspec/specs/shell-command-security-model/spec.md:179`).
Adding the requirement there keeps the user-facing parsing contract
in one place. The contributor spec `parser-engine-invariants` is
unaffected — its span / inviolability requirements continue to hold,
since per-reader handling does not introduce new spans.

## Risks / Trade-offs

- **Risk:** A `\<newline>` that today is being relied upon (by user
  rules or tests) as a literal `\n` in the first word might change
  behaviour. → Mitigation: this was never intentional; the parser
  emits `\n` only because the lexer is wrong, and no shell behaves
  this way. Search the test suite for tests that assert a leading
  `\n` in a parsed Word and treat any such test as encoding the bug.
- **Risk:** Span calculations drift. → Mitigation: per-reader
  handling advances the byte cursor identically to today; only the
  emitted `WordPart` vector differs. Add a proptest covering
  `parser-engine-invariants` bounds for inputs containing `\<NL>`.
- **Risk:** Heredoc body reader silently shares the offending
  backslash arm. → Mitigation: confirm by reading
  `read_heredoc_delimiter` at `mod.rs:384` and the heredoc body reader
  before editing; if the body reader does not use
  `read_word_parts`/`read_double_quoted_parts`, no change is needed
  there.
