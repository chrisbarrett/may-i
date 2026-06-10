## Context

`may-i` evaluates a command by parsing the bash source into an AST
(`crates/shell-parser`), decomposing it into evaluation units, and running
rules over each (`crates/engine/src/eval/command.rs`). Two parse-fidelity gaps
were found by running real harness commands through hook mode:

- **Leading `!`.** The lexer recognises `if/while/until/do/done/…` as keywords
  but not `!`. So `! kill -0 %1` falls through to a `Word`, the parser takes
  word[0] as the command name, and evaluation resolves a command literally
  named `!` — no rule matches and the real inner command (`kill`) escapes
  coverage. POSIX grammar is `pipeline ::= ["!"] pipe_sequence`; `!` is a
  reserved word that negates a pipeline's exit status, not a program.
- **Unterminated substitution.** `decompose` extracts an `EmbeddedCommand` for
  every `$(…)` / `` `…` `` node, including one left unterminated by a missing
  `)`. It then recurses into the swallowed tail (`\||\|deciding…rs | head -40`),
  finds no rule, and sets the aggregate to `:ask` with reason
  `No rule for command `|deciding|…` ($(...) substitution in `grep`)`. The
  spec's "Error-severity diagnostics floor decision at ask" requirement mandates
  a `parse error: <kind> at line L, column C: …` reason, but the floor only
  rewrites the reason `if aggregate_decision < Ask` — the fabricated `:ask`
  defeats that guard, so the misleading reason survives. This is a
  spec-conformance violation, not just a cosmetic issue.

Both were confirmed by reproduction: the escaped form `\$(` evaluates correctly
(`$(` literal → `allow`); only the bare unterminated `$(` triggers the bug.

## Goals / Non-Goals

**Goals:**

- Recognise leading `!` as transparent pipeline negation so the inner pipeline
  is evaluated under its real command name.
- Make the unterminated-substitution path conform to the existing floor-reason
  requirement, without disturbing well-formed substitution recursion.
- Cover both with regression tests.

**Non-Goals:**

- Tracking or acting on exit-status semantics. Negation does not change what
  runs; `may-i` decides on structure, so it is authorisation-transparent.
- The general position-blind reserved-word lexing gap (`find . -name done`
  mis-lexing `done`) — a separate latent issue, out of scope here.
- Recovering the original pre-transmission byte form of a command (the escaping
  ambiguity that motivated this). That is the audit-log change's job.

## Decisions

### D1 — Handle `!` at parse level, not in the lexer

`parse_pipeline` consumes a leading bare-`!` word as a negation prefix, then
parses the pipeline as normal. The lexer is left unchanged.

- *Why not a lexer `Token::Bang`:* existing keyword recognition is position-
  blind, so a `Bang` token would also fire for `find . ! -name x` and
  `[ ! -f x ]`, where `!` is a legitimate argument. `parse_pipeline` is only
  entered at pipeline-start position, so checking for a leading `!` there is
  position-correct for free and leaves argument-`!` untouched.
- *Why not a Prelude Carrier* (`(parser "!" (rest #cmd))`): wrong layer. `!` is
  bash grammar, not a program; CONTEXT.md separates the shell parser from
  per-program `(parser …)` tokenisation. The Carrier route also (a) needs a
  user-authored `(rule "!" (authorise #cmd))` since the Prelude ships no rules —
  absent it the ask-prompt bug returns; (b) pollutes the `:via` fact with `"!"`;
  (c) exposes `!` to trust/migration as if it were a tool; and (d) only works by
  exploiting the current mis-parse, coupling correctness to a bug.

### D2 — Negation is a transparent passthrough; no `Negate` AST node

`parse_pipeline` drops the `!` and returns the inner pipeline `Command`
unchanged. No wrapper node is introduced.

- Negation does not affect the decision, so an AST node would carry no
  evaluation signal and would ripple needlessly through `decompose` and the
  fold.
- Display fidelity is preserved regardless: `segment.rs` colours by byte ranges
  over the original input, so the `!` still appears in rendered output.
- A single leading `!` is consumed. Double negation (`! ! cmd`) is rare; the
  second `!` falls back to the existing behaviour. Documented as an edge, not
  handled specially.

### D3 — Suppress recursion engine-side, not by changing the AST

In `decompose`, when building units, skip emitting an `EmbeddedCommand` for a
substitution whose span coincides with an Error-severity diagnostic
(`UnterminatedCommandSubstitution`, `UnterminatedBacktick`). The AST itself is
untouched.

- *Why not have the parser omit the substitution `WordPart` when unterminated:*
  the spec requires "The AST output for any given input SHALL be identical to
  the current parser output", and other consumers (`wordpart-source-spans`)
  depend on the node existing. Keeping the AST stable and deciding not to
  recurse keeps the change local to evaluation.
- Correlation: match the substitution `WordPart`'s span against the spans of
  Error-severity diagnostics already present in `ParseResult.diagnostics`. The
  diagnostic span points at the opening construct, which lies within the
  substitution's span.

### D4 — Let the existing floor own the reason

Once D3 removes the fabricated `EmbeddedCommand`, the well-formed segments
(`grep`, `head`) keep the aggregate at `:allow`, so the existing
`if aggregate_decision < Ask` floor fires and applies the spec'd
`parse error: …` reason. The floor guard itself is unchanged — this preserves
the "Denied command with parse error" scenario, where a real `:deny` from a
well-formed segment still outranks the `:ask` floor and keeps its own reason.

## Risks / Trade-offs

- **`!foo` / `!=` misread as negation** → Only a token that is *exactly* the
  single character `!` is consumed; `!foo` stays a command word (history
  expansion is off in non-interactive bash).
- **Span correlation mis-fires on nested substitutions** → Restrict suppression
  to the substitution whose span contains an Error diagnostic's start offset;
  well-formed nested subs carry no Error diagnostic and are unaffected. The
  "Well-formed substitution still recurses" scenario fences this.
- **Over-suppression hides a real embedded command** → Only substitutions with
  an Error-severity diagnostic are suppressed; well-formed ones recurse exactly
  as before.

## Open Questions

- Should suppression extend to unterminated `${…}` / `$((…))`? They do not yield
  embedded *commands* today, so the change is likely a no-op for them — confirm
  during implementation and add a guard test if relevant.
