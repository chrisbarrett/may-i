## Context

`decompose` turns a parsed command into `EvalUnit`s. Embedded command
substitutions (`$( … )`, `` `…` ``, `<( … )` / `>( … )`) become
`EvalUnit::EmbeddedCommand`, which the engine evaluates recursively so the inner
command is gated like any other. Those units are produced by
`push_embedded_units_from_word`, which is called from exactly two places:

- `decompose_simple_command` — over a `Command::Simple`'s words and its
  assignment-prefix values;
- `push_embedded_units_from_redirect_targets` — over redirect-target words
  across the whole tree.

Every other word position the grammar exposes is never handed to that function,
so a substitution there is invisible. Confirmed bypasses (each `:allow`s an
ungated `rm -rf /`):

- a bare `Command::Assignment` value — `z=$(rm -rf /)` parses as `Assignment`,
  which `extract_simple_commands` skips entirely, so neither the prefix nor its
  value is ever scanned;
- `Command::For { words }` — `for x in $(rm -rf /)`;
- `Command::Case { word, arms.patterns }` — `case $(rm -rf /) in …`.

The test-only helpers `collect_all_words` / `find_structural_dynamic_parts`
already enumerate For/Case words, but they are `#[cfg(test)]` and not on the
production path — evidence the positions are known, just not wired into gating.

## Goals / Non-Goals

**Goals:**

- An embedded command substitution is evaluated wherever it appears, so it can
  never resolve to `:allow` unreviewed.
- A coverage invariant that fails if a future word position is added without
  wiring it into extraction.
- No change to span/coordinate handling — nested-segment colouring and
  bubbled-reason annotations stay identical to the existing simple-command and
  redirect-target paths.

**Non-Goals:**

- Opaque-string commands (`eval`/`trap`/`source`/`bash -c`). These carry their
  payload as a literal string the parser cannot decompose; they gate by their
  own command name and ask by default. Intentional recursion into a wrapper
  payload remains the `(authorise …)` mechanism's job — out of scope here.
- Arithmetic `$(( … ))` — runs no command, so it is correctly excluded.
- Re-architecting `decompose`; this extends the existing walk, it does not
  replace it.

## Decisions

### D1 — Extend the tree walk to all word positions

Generalise the redirect-target walk into a single whole-tree pass that hands
**every** word the AST exposes to `push_embedded_units_from_word`. Per node:

- `Command::Simple` — already covered by `decompose_simple_command` (words +
  assignment-prefix values); the new walk skips its words to avoid duplicate
  units, but the existing redirect-target handling stays.
- `Command::Assignment(a)` — scan `a.value` (the bare-assignment case the simple
  path never sees).
- `Command::For { words, .. }` — scan each iteration word.
- `Command::Case { word, arms, .. }` — scan the subject word and every arm
  pattern.

Reuse `push_embedded_units_from_word`, so the parser-provided inner-span flows
through unchanged and unterminated substitutions stay suppressed exactly as
today (the diagnostic floor owns those).

### D3 — Capture parameter-expansion operand substitutions in the lexer

A `$( … )` / backtick inside a parameter-expansion operator operand
(`${x:-$(rm)}`, `${x#$(rm)}`, `${x/$(rm)/y}`) runs a command, but the lexer read
those operands with `read_until_char` and stored them as opaque `String`s, so no
`WordPart` — and therefore no extraction pass — ever saw the substitution. This
is the *same* bypass class as the word positions above, in the one remaining
sub-position, and the coverage proptest (D2) would not have caught it because
the operand text never became structured parts.

Fix it where the bytes are still positioned: the lexer. A new operand reader
captures `$( … )` (not arithmetic `$((` — runs no command) and backtick
substitutions as real `WordPart`s with absolute source-byte spans, via the same
`read_dollar` / backtick readers every other path uses, while still returning
the verbatim operand string for resolution and display. They are stored in a new
`embedded: Vec<WordPart>` field on `WordPart::ParameterExpansionOp`.

`collect_embedded_commands` / `collect_embedded_with_spans` (the parser's single
source of truth for "what is an embedded command") recurse into that field, so
`Word::extract_embedded` surfaces operand substitutions exactly like any other —
**the engine needs no change**: every word position already routes through
`push_embedded_units_from_word`, which now sees the operand substitutions too.
This generalises the existing mechanism rather than special-casing param
expansion in the engine.

- *Why a parser field over an engine re-scan:* the engine deleted its flat
  input re-scan (`find_substitution_spans`); the WordPart span is the one source
  of truth for span↔source coherence. Only the lexer, mid-scan, knows the
  operand's absolute byte positions, so it is the only place that can mint a
  coherent span.
- *Why keep the operand `String` too:* `resolve_param_op` does string operations
  (default/strip/replace) on the operand value and `to_str`/`display_source`
  flatten it; both still want the verbatim text. The `embedded` field is purely
  additive — extraction reads it, resolution/display ignore it.

- *Why a dedicated word source over re-running `extract_simple_commands`-style
  recursion:* the units must carry the substitution's own inner-span for segment
  colouring; the existing helper already does this and is the one source of
  truth for "what is an embedded command."
- *Duplicate avoidance:* a `Command::Simple`'s own words are emitted by
  `decompose_simple_command`; the new pass must not re-emit them, or the inner
  range would appear twice. Only the not-yet-covered positions (assignment
  values, For/Case words) are scanned by the new pass.

### D2 — A coverage invariant, not just per-position tests

Add a property test over arbitrary shell inputs: for every command/backtick/
process substitution the parser finds in the input, `decompose` produces a
matching `EmbeddedCommand` unit. Point fixes to three positions are necessary
but not sufficient — the invariant is what stops a fourth position from silently
reintroducing the gap. The generator must exercise assignment/For/Case contexts,
not only simple commands.

## Risks / Trade-offs

- **Double-counting** a substitution that is reachable from two walks (e.g. a
  redirect target that is also a For word) would duplicate a unit. Mitigated by
  partitioning: the new pass owns assignment/For/Case words; redirect targets and
  simple-command words keep their existing owners, and the passes do not overlap.
- **Span correctness** for nested substitutions in the new positions must match
  the simple-command path so top-level-segment-disjointness properties still
  hold. Mitigated by reusing `push_embedded_units_from_word` verbatim and
  asserting the existing span-bounds proptests still pass.
- **Performance** — one extra whole-tree word walk per evaluation. Negligible
  against parsing; the redirect-target walk already does the same shape.
