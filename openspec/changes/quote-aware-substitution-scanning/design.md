# Design: Quote-aware substitution scanning

## Context

Every substitution construct in the lexer locates its end with a hand-rolled
delimiter scan, and none of them tracks quote state:

| Scan | Site | Failure with quoted delimiter |
| --- | --- | --- |
| `$(…)` / `<(…)` / `>(…)`, word context | `string_readers.rs:158` `read_balanced_parens_checked` | Quoted `(`/`)` corrupts paren depth; substitution swallows the rest of the command |
| `$(…)` inside heredoc body | `lexer/mod.rs:128` `find_balanced_paren_close` | Same, byte-level duplicate |
| `$((…))`, word context | `string_readers.rs:139` `read_until_double_paren_checked` | Stops at first `))`; no paren counting |
| `$((…))` inside heredoc body | `lexer/mod.rs:150` `find_double_paren_close` | Same, byte-level duplicate |
| `$[…]` deprecated arithmetic | `word_parts.rs:381-392` | Stops at first `]`; no bracket counting |
| `${…}` operator operands | `param_expansion.rs:411` `read_operand` | Quoted/escaped `}`, `/`, `:` terminates the operand |
| `${arr[…]}` subscript | `param_expansion.rs:456-490` `read_subscript` | Quoted `]` closes the subscript |
| `` `…` `` body, word + double-quote context | `word_parts.rs:286`, `word_parts.rs:245` | Escaped `` \` `` closes the body (the heredoc variant, `lexer/mod.rs:91`, already skips `\` — the implementations have drifted) |

The incident that surfaced this: a hook command
`for f in tests/*.rs; do n=$(grep -c 'may_i(' "$f"); echo "$n $f"; done | sort -rn`
parsed with the substitution swallowing everything after `'may_i(``, the loop
body collapsing to a bare assignment, and the engine returning
`ask` / `empty command` (`engine/src/eval/command.rs:316-320`).

All scenario expectations in the delta spec were verified empirically against
system bash (5.x): `$(echo "a)b")` → `a)b`; `$(( $(echo '))' >/dev/null; echo
5) + 0 ))` → `5`; `${FOO:-"a}b"}` and `${x:-a\}b}` → `a}b`; `${arr["a]b"]}`
scans the quoted `]` as subscript text (bash arithmetic-evaluates it later);
`$[a[1]]` scans past the nested `]`. The backtick case
`` `echo a\`b` `` errors in bash, but the error comes from bash's *re-parse* of
the captured body — the outer scan does honour `` \` ``; may-i evaluates the
captured body instead of re-parsing it, so no diagnostic is correct there.

## Goals / Non-Goals

**Goals:**

- One quote-aware scanning core shared by every construct scan, so the
  word-lexer and heredoc scanners cannot drift again.
- Scan semantics faithful to bash's delimiter location: quoting state,
  backslash escapes, nested paren/bracket depth, backtick-body skipping.
- Preserve the existing invariants the rest of the system relies on:
  captured text stays byte-identical to the source (`param_expansion.rs:405`
  doc), spans stay verbatim (`wordpart-source-spans` spec), and an
  unterminated construct still yields the Error-severity diagnostic path
  ("Unterminated substitutions are not recursed into").

**Non-Goals:**

- Gating commands nested inside arithmetic (`echo $(( $(rm -rf /) + 0 ))`
  runs in bash but is excluded from evaluation today —
  `engine/src/eval/decompose.rs:1010`, asserted in
  `engine/src/eval/tests/properties.rs:1076`). Real gap, different failure
  class; recommend a follow-up change.
- Bash's `$((expr))`-vs-`$( (cmd))` disambiguation — keep the existing
  lookahead rule (`word_parts.rs:314`).
- Brace expansion with quoted commas (`{a,"b,c"}`) — display-only divergence.
- Zsh glob qualifier `(…)` scanning — qualifier text is pattern data, not
  commands; quote-blindness there is harmless.
- Runtime expansion semantics (quote removal, arithmetic evaluation) — this
  change is about locating construct boundaries only.

## Decisions

### D1: One shared byte-slice scanner, not per-site fixes

Add `crates/shell-parser/src/lexer/scan.rs` exporting:

- `find_paren_close(bytes, from, end) -> Option<usize>` — index of the `)`
  closing a `$(…)`-opened region, quote-aware, depth-counting.
- `find_double_paren_close(bytes, from, end) -> Option<usize>` — index of the
  `))` closing a `$((…))` region, quote-aware, depth-counting (close at the
  first unquoted `))` while paren depth is 0).
- `find_bracket_close(bytes, from, end) -> Option<usize>` — index of the `]`
  closing a `$[…]` region, quote-aware, depth-counting.
- `skip_backtick_body(bytes, from, end) -> Option<usize>` — index of the
  closing backtick, backslash-aware (quote-blind inside the body, matching
  bash's outer scan).

*Alternatives considered:* fixing each loop in place (rejected — the
word-lexer/heredoc drift that produced two divergent backtick scanners shows
duplication is the root maintenance problem); a char-level method on `Lexer`
(rejected — the heredoc scanner operates on byte slices and the char vector
adds nothing: UTF-8 continuation bytes are ≥ 0x80 and cannot match ASCII
sigils, the argument already made at `lexer/mod.rs:29-33`).

### D2: Quote state machine (bash-faithful)

Scan state: `Unquoted | Single | Double`.

- `Unquoted`: `'` → `Single`; `"` → `Double`; `\` consumes the next byte
  (escape); construct delimiters (`(`/`)`/`]`/backtick) act only here.
- `Single`: only `'` exits; backslash is literal (so `'a\'` closes after
  `a\` — bash agrees: backslash has no special meaning inside single
  quotes).
- `Double`: `"` exits; `\` consumes the next byte. Bash only escapes
  `` $ ` " \ `` and newline inside double quotes, but for *delimiter
  location* consuming any backslashed byte is equivalent — the escaped byte
  is never a live delimiter in either semantics, and text is copied raw so
  no quote-removal decision is embedded here.
- Backtick body skipping (inside `Unquoted` in D1's paren scanner): jump to
  the matching backtick via `skip_backtick_body` so `` $(echo `x)y`) `` does
  not count the backtick body's parens.

### D3: Char-based readers delegate to the byte scanners

`read_balanced_parens_checked` and `read_until_double_paren_checked` become
thin wrappers: slice `self.input_str.as_bytes()` from `self.byte_pos`, call
the D1 scanner, advance `pos`/`byte_pos` past the closing delimiter, and
return the raw slice text (byte-identical invariant preserved — a verbatim
copy of the input, which the old char-by-char accumulation also produced).
`found = scanner returned Some`. The `$[…]` scan in `read_dollar` and
`read_subscript`'s `]` matching switch to the same pattern
(`find_bracket_close`). `input_str` is already accessible to the lexer's
child modules.

### D4: `read_operand` quote-awareness without changing its contract

Track the D2 state across the loop; `stops` terminate only in `Unquoted`
state; `\` consumes the next char *into the text* (raw preservation). The
existing `$(`-lifting and backtick-lifting branches keep firing wherever they
do today — a delegation consumes a complete, balanced inner construct so the
outer quote state remains consistent — but the inner scan is now quote-aware,
which is what fixes `${x:-$(echo "a}b")}`-shaped operands. If quotes are left
unbalanced inside an operand the scan runs to EOF, the caller's unconditional
`} skip` becomes a no-op, and the existing unterminated-`${
… }` detection (`word_parts.rs:418-430`) floors the parse — the same outcome
bash reaches.

### D5: Heredoc scanners adopt the shared core

`find_balanced_paren_close` / `find_double_paren_close` in
`lexer/mod.rs` are replaced by calls into `scan.rs`. The heredoc *body* scan
itself stays quote-blind (bash does not honour quoting in heredoc bodies —
`lexer/mod.rs:10-16`); only the `$(…)`/`` `…` ``/`$((…))` regions embedded in
the body become quote-aware.

### D6: Where a scan cannot find its delimiter

Unchanged: run to the end of the region, emit the existing
`Unterminated*` Error-severity diagnostic, and let the parse-error floor own
the decision. Quote-awareness changes *where* constructs end, never what
happens when they do not end.

## Risks / Trade-offs

- [Decisions change for previously mis-parsed commands] → Un-truncating a
  substitution can only *surface* commands the old parse hid; evaluation is
  strictest-wins and every malformed-input path still floors at `ask`
  ("Match and parse imprecision never widens toward allow"). The observable
  risk is a command that used to get `ask`/`empty command` now getting the
  decision its real structure warrants — that is the fix, but it is a
  behavior change worth a CHANGELOG entry.
- [State machine diverges from bash on an exotic input] → Mitigate with a
  proptest asserting quoted delimiters never move a construct boundary:
  for generated bodies, wrapping a delimiter in quotes inside `$(…)` must
  leave the captured body verbatim; plus the scenario unit tests as
  regression pins.
- [`read_operand` raw text now includes escaped stop chars (`a\}b`)] →
  Downstream consumers treat unresolved operands as opaque display text
  (unresolved forms floor `:allow`-satisfying words anyway); resolution
  paths that fold constants only handle previously-parseable forms, which
  never contained these sequences. Add unit pins for display output.

## Migration Plan

No config, DSL, or output changes; nothing to migrate. Rollback is a revert
of the implementation commit.

## Open Questions

- Should a nested `$(…)` inside `$((…))` become its own evaluation unit
  (bash runs it)? Deferred as a follow-up change (see Non-Goals); does not
  affect scanning tasks.
