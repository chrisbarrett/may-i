## Context

Empirically characterising the defect (all via `may-i parse` / `eval` on the
inputs as data):

| input | parsed words | symptom |
|---|---|---|
| `cat <(rm -rf /danger)` | `cat` | inner command dropped (arg position) |
| `while … done < <(rm -rf /danger)` (top-level) | no `rm` | inner command dropped (redirect) |
| `f() { while … done < <(find .); rm -rf /danger; }` | `f read x : }` | inner **and** trailing `rm` dropped; Warning `MissingClosingKeyword "}"` |
| `( while … done < <(find .); rm x )` | `read x : )` | trailing `rm` dropped |
| `f() { while … done < "$(echo f)"; rm x; }` | includes `rm x` | **no bug** — command substitution target is fine |

So the fault is specific to process substitution. Two failure modes:

- **Inner command never captured.** The `<(…)` body (`rm -rf /danger`, `find .`)
  does not become a `WordPart`/embedded unit, so it is invisible to the engine —
  even at top level, even in plain argument position.
- **Parser desync after a `done` redirect.** When `<(…)` is the target of a
  loop's input redirect inside a compound, parsing consumes past the matching
  `)` and eats the rest of the enclosing group, surfacing only a Warning. Because
  the floor only triggers on Error-severity diagnostics, the dropped commands are
  silent.

The existing engine already evaluates `$(…)` / backtick inner commands
(`EmbeddedCommand` units); process substitution is simply not wired in
(`decompose` only pulls embedded units from word parts, and the procsub word
part is absent / mis-parsed).

## Goals / Non-Goals

**Goals:**

- A command inside `<(…)` / `>(…)` is evaluated, in argument and redirect-target
  position.
- Process-substitution parsing is self-contained: it stops at its `)` and never
  drops following commands.
- No silent token loss; residual unparseable input floors to `:ask`.

**Non-Goals:**

- Dataflow from the substituted file descriptor to its consumer.
- Naming the process substitution in bubbled `:ask` reasons — the existing spec
  deliberately leaves process substitutions unannotated; keep that.

## Decisions

### D1 — Parse `<(…)` / `>(…)` as a first-class process substitution

Lex/parse a process substitution as a single unit that captures its inner
command source and span and terminates at the matching `)`, in both positions:

- **Argument position** (`cat <(…)`, `diff <(a) <(b)`): a `WordPart::Process
  Substitution` in the command's word, as the AST already models.
- **Redirect-target position** (`… < <(…)`): the redirect operator `<` followed
  by a process-substitution target. Disambiguate from `< (subshell)` — the
  `<(` opening (no space) is the process substitution; `< (` is a redirect of a
  subshell (rare/invalid as a target). The redirect target carries the procsub.

The matching `)` is found by balanced-paren scanning over the inner command, so
parsing resumes cleanly at the token after `)`.

### D2 — Evaluate the inner command as an embedded unit

In `decompose`, emit an embedded unit for a process substitution's inner command
wherever it appears (word part or redirect target), reusing the
`EmbeddedCommand` path that `$(…)` uses. The procsub keeps `EmbeddedKind`/reason
form `None` (no origin annotation), consistent with the current
`SubstitutionForm::Process => None` mapping — it is evaluated, just not named in
the reason.

### D3 — No silent token loss (shared principle)

The correct parse (D1) removes the desync, so following commands are retained
without special handling. As a backstop, any input the parser still cannot place
SHALL produce an Error-severity diagnostic, not a dropped token — the same
principle stated in `command-position-reserved-words`. This guarantees that even
an unforeseen procsub edge floors to `:ask` rather than hiding a command.

## Risks / Trade-offs

- **`< <(…)` vs `< (subshell)` disambiguation** → key on the adjacency of `<(`
  (process substitution) versus `<` then whitespace/`(`; cover both with parse
  tests.
- **Nested process substitutions / substitutions inside the body**
  (`<(grep $(date) f)`) → balanced-paren scanning must handle nesting; add a
  nested case.
- **Interaction with the redirect parser** → the loop-redirect path
  (`maybe_wrap_redirections`) must accept a procsub target without consuming the
  compound terminator; regression-test brace group, subshell, and function body.

## Open Questions

- Should `>(…)` output process substitutions be evaluated identically? They run a
  command too (`tee >(rm x)`), so the same extraction should apply — confirm a
  scenario covers the `>` form.
