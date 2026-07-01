## Context

`may-i-shell-parser` is a hand-written recursive-descent parser (`parse.rs` +
`lexer/`) that judges every input against the bash grammar. `parse(input) ->
ParseResult` is the sole entry; the engine calls it at three points
(`check.rs`, `eval/command.rs` top-level, and recursively when re-parsing the
source of an embedded command substitution). Diagnostics floor the decision:
`Error` severity forces at least `:ask`; `Warning` does not.

zsh has **no published formal grammar** — its parser is hand-written recursive
descent in the zsh source (`Src/parse.c`, `Src/lex.c`) with no BNF or yacc
artifact, and its syntax is partly runtime-`setopt`-dependent. So "the zsh
grammar" can only be defined operationally. Measured against `zsh -n` over a
corpus of common constructs, the two highest-frequency false parses are:

- **Glob qualifiers** (`ls **/*(.)`): `Error` (`UnexpectedToken`) → floors a
  correct command to `:ask`. The real defect.
- **No-semicolon brace terminator** (`foo() { echo hi }`): `Warning`
  (`MissingClosingKeyword "}"`). The `}` is swallowed as an argument; the
  group boundary is lost. Fail-safe (trailing commands still evaluate) but the
  AST is wrong.

## Goals / Non-Goals

**Goals:**

- A per-invocation shell **dialect** (`Bash` default, `Zsh`), resolved from the
  executing shell (`$SHELL` basename), overridable on `eval`, hermetic-`Bash`
  on `check`.
- Under `Zsh`, accept the two constructs above without emitting their
  diagnostics, with an AST faithful enough that evaluation is unchanged in
  strictness.
- Bash behaviour byte-identical to today.
- Every zsh production is **strictness-preserving**: it can only remove a
  diagnostic or make a word parse; it can never widen a decision. A qualified
  glob stays unresolved (expansion-bearing, floors an `:allow`) exactly as a
  plain glob does.

**Non-Goals:**

- Byte-exact zsh fidelity. We match the common shapes, not every corner.
- Runtime-`setopt`-dependent semantics (`SH_WORD_SPLIT`, `KSH_ARRAYS`, unquoted
  `$var` word-splitting divergence). Not statically decidable; out of scope.
- The long tail: anonymous functions `() { … }`, `foreach … end`, `repeat`
  loops, `always { }`. Deferred to a follow-up change.
- A `Posix` dialect. The enum is designed to admit one later, but none ships now.

## Decisions

### Dialect lives in the parser crate; `parse` stays Bash-default

Add `pub enum Dialect { Bash, Zsh }` (with `impl Default = Bash`) to
`may-i-shell-parser`. `Parser` carries a `dialect` field. Keep `parse(input)`
as the Bash-default convenience (so the many Bash test call sites and the
`check` path are untouched) and add `parse_with_dialect(input, Dialect)`. The
divergence points consult `self.dialect`.

*Alternative considered:* change `parse`'s signature to take a dialect
everywhere. Rejected — churns dozens of Bash-only call sites for no benefit;
`check` and most tests genuinely want Bash, so a default entry is the honest
API.

### Dialect is resolved at the invocation boundary and threaded inward

The binary (`src/main.rs`) owns resolution: `hook` and `eval` derive the
dialect from the executing shell path's basename (`zsh` → `Zsh`, else `Bash`);
`eval` gets an explicit `--dialect` override that wins; `check` passes `Bash`.
The resolved dialect enters the engine and is stored on the evaluation context
so that **recursive re-parses of embedded command sources inherit it** — a
`$(…)` body inside a zsh command is still zsh.

The executing shell is **observed ground truth**, analogous to the entry
environment — not a Fact. It is never reachable through `(fact? …)`; there is
no `:dialect` fact. This keeps the rule language unaware of the shell, matching
how the entry environment is consulted structurally rather than as policy.

*Alternative considered:* a harness-supplied `--fact :zsh`. Rejected — dialect
governs tokenisation (layer 3), not policy (layers 1–2); modelling it as a Fact
would let rules branch on it and blur the layer boundary.

### No-semicolon brace terminator: scoped, whitespace-delimited `}`

Under `Zsh`, a **whitespace-delimited** `}` (a `}` that forms its own token)
terminates a command list **within brace-group / function-body context**. At
top level `}` remains a literal argument in both dialects (`echo }` is
unchanged). Concretely: the simple-command argument loop, when
`dialect == Zsh` and inside a brace/function context, stops at a `}` token
instead of absorbing it as a literal word, letting `parse_list` /
`parse_brace_group` see the terminator.

zsh actually also terminates on a *glued* `}` (`echo hi}` → `hi`) while keeping
a *mid-word* `}` literal (`a}b` → `a}b`). We implement only the
whitespace-delimited case in this pass; glued `}` falls back to today's
`Warning` (fail-safe — trailing commands still evaluate). This covers the
dominant agent output (`foo() { …; }`, `foo() { … }`) and is documented as a
known limitation.

*Alternative considered:* full zsh `}`-tokenisation (glued + mid-word
disambiguation). Rejected for first pass — materially more lexer surface for
the rare glued case, and the fallback is already safe.

### Glob qualifiers: trailing `(…)` folded into the glob word

Under `Zsh`, a `(` **immediately adjacent** to a preceding word that contains
an unquoted glob metacharacter (`*`, `?`, `[`) is lexed as a glob qualifier and
its balanced `(…)` is folded into that word as unresolved glob text, rather
than opening a subshell or erroring. The word stays expansion-bearing, so it
floors an `:allow` just like a plain glob — recognition removes only the
`Error` diagnostic.

The adjacency + glob-metachar guard is what disambiguates from a subshell
(`cmd (subshell)` has a space and no leading glob word) and from a function
definition (`name()` has no glob metachar). This keeps the qualifier rule from
mis-claiming ordinary parenthesised constructs.

*Alternative considered:* resolve the qualifier's meaning (`(.)` = plain files,
`(/)` = dirs). Rejected — needs a filesystem and runtime semantics; the
security model already treats globs as unresolved, so no resolution is owed.

### No new spec bucket

`shell-dialect` is a new user-facing capability in the existing `parsing`
bucket; the delta to `shell-command-security-model` stays in `parsing`. No
`openspec/config.yaml` bucket amendment is needed.

## Risks / Trade-offs

- **Glued `}` not handled** (`echo hi}`) → residual `Warning` on rare inputs.
  → Fail-safe (no decision change); documented; follow-up if it surfaces.
- **Glob-qualifier `(` disambiguation** could mis-tokenise a genuine adjacent
  construct. → Gated on adjacency *and* a glob metachar in the preceding word;
  proptest against `zsh -n` as oracle to catch regressions.
- **`$SHELL` may not be the shell the harness actually `exec`s** (a harness
  could run `bash -c` regardless of login shell). → Bash default is the safe
  fallback; the `--dialect` override and, later, a harness-supplied signal can
  correct it. Choosing the wrong dialect only ever changes which *diagnostics*
  fire, never strictness, because zsh productions are strictness-preserving.
- **Dialect not threaded into a recursive re-parse** would judge an embedded
  zsh body as bash. → The dialect rides the evaluation context through every
  `authorise`/embedded recursion; covered by a property test that a zsh
  construct inside `$(…)` is not diagnosed.
- **Scope creep toward full zsh.** → The enumerated two-construct list is the
  contract; the long tail is explicitly a separate change.

## Migration Plan

No user-config format change, so no `may-i migrate` step. Rollout is internal:
the parser gains an entry point and the binary gains resolution + a flag.
Rollback is removing the `Zsh` arm — Bash paths are untouched by construction.

## Open Questions

- Exact spelling of the `eval` override flag (`--dialect zsh` vs
  `--shell zsh`). Leaning `--dialect` to match the internal term.
- Should the hook eventually accept an explicit dialect signal from the harness
  (more reliable than `$SHELL`) rather than deriving it? Out of scope now;
  the resolution seam is designed to admit it.
