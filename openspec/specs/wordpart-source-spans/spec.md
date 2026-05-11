# wordpart-source-spans Specification

## Purpose

Contributor-only. Dynamic `WordPart` variants (`CommandSubstitution`, `Backtick`, `Arithmetic`, `ProcessSubstitution`) carry both the extracted body string and a `Span` with inner-span semantics (sigils excluded). Span/source equality across sibling parts and monotonic span ordering let downstream consumers (trace, evaluator) re-locate every dynamic span in the original input without re-tokenising.

## Requirements

### Requirement: Dynamic WordPart variants SHALL carry source-byte spans

The parser SHALL emit each dynamic `WordPart` (`CommandSubstitution`,
`Backtick`, `Arithmetic`, `ProcessSubstitution`) as a struct-form variant
carrying both the extracted body string (`source` for the first three;
`command` for `ProcessSubstitution`) and a `Span` whose `(start, end)` byte
offsets locate the body within the original input. Spans use *inner-span*
semantics — they exclude the opening and closing sigil bytes (`$(` / `)`,
`` ` `` / `` ` ``, `$((` / `))`, `<(` / `)`, `>(` / `)`).

#### Scenario: CommandSubstitution carries an inner span
- **WHEN** the input is `echo $(uname)`
- **THEN** the parsed `WordPart::CommandSubstitution` SHALL have `source ==
  "uname"` and `span` covering bytes 7..12 (inclusive of `u`, exclusive of
  the closing `)`)

#### Scenario: Backtick carries an inner span
- **WHEN** the input is `` echo `date` ``
- **THEN** the parsed `WordPart::Backtick` SHALL have `source == "date"` and
  `span` covering the four `date` bytes between the backticks

#### Scenario: Arithmetic carries an inner span
- **WHEN** the input is `echo $((1+2))`
- **THEN** the parsed `WordPart::Arithmetic` SHALL have `source == "1+2"`
  and `span` covering the three bytes of `1+2`

#### Scenario: ProcessSubstitution carries an inner span
- **WHEN** the input is `diff <(echo a) <(echo b)`
- **THEN** each parsed `WordPart::ProcessSubstitution` SHALL have its `span`
  cover the inner `echo a` / `echo b` bytes, excluding the `<(` opener and
  the matching `)` closer

### Requirement: WordPart span SHALL equal its source verbatim

The byte sequence `&input[span.start..span.end]` SHALL equal `source` exactly
for every dynamic `WordPart` carrying a `(source, span)` pair. No
normalisation, trimming, or escape processing is applied; the inner-span
convention removes the sigil bytes by construction.

#### Scenario: Span/source equality holds across arbitrary inputs
- **WHEN** an arbitrary shell-like input string of up to 80 bytes is parsed
- **THEN** every dynamic `WordPart`'s `span` slice equals its `source` field

#### Scenario: Unclosed substitution still satisfies the invariant
- **WHEN** the input is `"$( ` (an unclosed `$(` inside a double quote at
  EOF)
- **THEN** the resulting `WordPart::CommandSubstitution` SHALL have `source`
  equal to `&input[span.start..span.end]`

### Requirement: WordPart spans SHALL lie within their containing Word's source range

Every spanned dynamic `WordPart` SHALL satisfy
`w_start ≤ span.start ≤ span.end ≤ w_end`, where `[w_start, w_end]` is the
aggregate byte range of any spanned parts in its containing `Word`. (In the
absence of spanned parts the requirement is trivially satisfied.)

#### Scenario: Nested substitution in a quoted word lies inside the word
- **WHEN** the input is `echo "prefix-$(uname)-suffix"`
- **THEN** the inner `WordPart::CommandSubstitution`'s span SHALL lie within
  the outer double-quoted word's byte range

### Requirement: Sibling WordParts SHALL have non-overlapping monotonic spans

Spanned dynamic `WordPart` siblings within a single `Word` SHALL appear in
document order with non-overlapping spans. For any two spanned siblings at
positions `i < j`, `parts[i].span.end ≤ parts[j].span.start` SHALL hold.

#### Scenario: Two adjacent substitutions in one word
- **WHEN** the input is `echo $(a)$(b)`
- **THEN** the two parsed `WordPart::CommandSubstitution` parts SHALL have
  spans where the first's `end` is less than or equal to the second's `start`

### Requirement: Engine SHALL read spans from AST instead of re-scanning source

The engine's `decompose` pass SHALL emit `EvalUnit::EmbeddedCommand { source,
span }` by reading the `(source, span)` pair directly from the AST's dynamic
`WordPart`. The engine SHALL NOT reconstruct substitution spans by
re-scanning a `SimpleCommand`'s source slice.

#### Scenario: EmbeddedCommand span equals the AST span
- **WHEN** the input is `echo "cmd $(inner) end"`
- **THEN** the `EvalUnit::EmbeddedCommand` for `inner` SHALL have a span
  identical to the AST's `WordPart::CommandSubstitution.span`

#### Scenario: Recursive evaluation translates spans correctly
- **WHEN** the input contains a nested `$(outer-$(inner))` and is evaluated
- **THEN** every `SegmentDecision` produced by the recursive call lies within
  the parent `EmbeddedCommand`'s span, with `outer_offset` translation applied

### Requirement: Substitution body length SHALL equal span length

`source.len() == span.end - span.start` SHALL hold for every dynamic
`WordPart { source, span }` produced by the parser. This invariant
guarantees that recursive engine evaluation cannot produce a child segment
whose translated end exceeds the parent's span end.

#### Scenario: Body length matches span length on arbitrary input
- **WHEN** an arbitrary input is parsed
- **THEN** every dynamic `WordPart`'s `source.len()` equals
  `span.end - span.start`

### Requirement: Re-parsing source bytes SHALL yield equivalent AST

Parsing `source` and parsing `&input[span.start..span.end]` SHALL yield ASTs
whose stringified form is identical for every
`WordPart::CommandSubstitution { source, span }` produced from an input
`input` (i.e. the source extracted by the lexer is the same as the bytes the
span points at, modulo parser idempotency).

#### Scenario: Round-trip parse equality
- **WHEN** an arbitrary input produces a `WordPart::CommandSubstitution`
- **THEN** `parse(source).to_string() == parse(&input[span.start..span.end]).to_string()`

### Requirement: Adjacent ignore spans SHALL be coalesced
When the eval command generates the spans array for JSON output, consecutive spans with `"ignore"` permission SHALL be merged into a single span containing the concatenated text.

#### Scenario: Multiple operators with whitespace
- **WHEN** the command `true && curl || ls` is evaluated with `--json`
- **THEN** the spans array SHALL contain coalesced ignore spans
- **AND** concatenating all span texts SHALL reproduce the original command exactly

#### Scenario: Preserved command boundaries
- **WHEN** the command `cmd1 && cmd2` is evaluated
- **THEN** spans with `allow`/`ask`/`deny` permissions SHALL remain separate
- **AND** only `ignore` permission spans SHALL be coalesced

#### Scenario: No consecutive ignore spans
- **WHEN** the command `ls` (single command) is evaluated
- **THEN** the spans array SHALL contain a single span
- **AND** no coalescing SHALL be performed

#### Scenario: Empty command
- **WHEN** an empty command is evaluated
- **THEN** the spans array SHALL be empty
- **AND** no coalescing errors SHALL occur

