## Context

`may-i` decides on command structure without running the shell. Every matcher in
a rule body tests a Pattern against a token's source text. For a literal token
the source text *is* the runtime value, so the test is sound. For a token
carrying a shell expansion, the source text is a template the shell rewrites
before execution — the runtime value is unknown to `may-i`. Today the engine
tests the template text as if it were the value, so an allow guard written as a
prefix/shape constraint is satisfied by a template whose expansion escapes the
constraint. Confirmed bypasses (built binary, `^/tmp/` guard): `/tmp/$HOME`,
`/tmp/*`, `/tmp/{a,../etc}` all return `:allow`.

The engine already has the structural signal: dynamic `WordPart` variants
(`CommandSubstitution`, `Backtick`, `Arithmetic`, `ProcessSubstitution`) carry
source + span (see `wordpart-source-spans`). Parameter expansion is likewise a
distinct part. The missing pieces are (1) glob/brace/tilde detection over
literal parts, and (2) the matcher-seam policy that suppresses an allow-
contributing match against any such word.

## Goals / Non-Goals

**Goals.** Make an `:allow` decision rest only on constraints proven for the
runtime value. Keep `:ask`/`:deny` matching under uncertainty (the safe
direction). Floor — never silently no-match — so the user sees *why* (a silent
no-match would read as "no rule matched", indistinguishable from a typo, the
exact failure mode `binding-shapes` already calls out).

**Non-Goals.** Expanding values (we never run the shell). Handling pure-literal
path traversal (`/tmp/../etc` — the author's regex semantics). Touching the
parser's AST shape. Any trust-hash or migration impact.

## Decisions

### D1 — Asymmetry is the invariant, floor is the mechanism

The rule is not "expansions don't match" but "expansions don't match *toward
allow*". A `(forbidden …)`/`(not (flag …))`/`unless`-test that fires on an
expansion-bearing word tightens the decision, which is safe and often what the
author wants (`(forbidden (regex "secret"))` should still trip on `secret$X`).
So the suppression is scoped to matches whose contribution is allow-ward. The
floor reuses the existing "raise decision to at least `:ask`" combinator that the
Error-severity parse floor already uses; we do **not** synthesize a fake
`ParseDiagnostic` (that would pollute `parse_diagnostics` and the audit record's
parse-status field). The floor carries its own reason string.

**Rejected:** treating an expansion-bearing word as an unconditional no-match.
That silently drops the segment to the default `:ask` fallback with the generic
"no patterns matched" reason, hiding the real cause and breaking `(forbidden …)`
in the safe direction.

### D2 — Where the suppression lives

At the single matcher seam where a single-token expression is tested against a
token value (the `Expr<T>` evaluation entry, plus the per-element call inside
`every?`/`some?`). The seam receives the token's `Word` (or the binding value's
originating word) so it can ask "is this word expansion-bearing?" and "is this
expression non-wildcard?". When both hold and the call site is allow-ward, return
a sentinel that the segment aggregator converts to an ask-floor. This keeps the
policy in one place rather than scattered across each `ArgPattern` arm.

**Open sub-question for review:** binding values (`#var`) are stored as strings,
having lost their `Word` provenance. To honour the rule for `(matches? #var …)`
and `(every? #var …)`, the binding environment must retain an "expansion-bearing"
flag per captured token (a bit alongside the string), set when the parser
captured a dynamic word. This is a small struct change to the binding value type.
The alternative — re-detecting expansion from the stored string — is unsound
(`$` survives as a literal byte and we can't tell a captured `\$` from a live
`$`). Recommend the flag.

### D3 — What counts as expansion-bearing

Dynamic `WordPart`s: yes (parameter, command, arithmetic, process substitution).
Over literal parts, an **unquoted** glob char (`*` `?` `[`), brace group
(`{…,…}`), or leading `~`: yes. Quoted occurrences (inside `'…'` or `"…"`) are
literal in bash and SHALL NOT count — e.g. `rm '/tmp/*'` deletes a file literally
named `*`, so matching it as the literal `/tmp/*` is sound. This requires the
detector to respect the quoting context the lexer already tracks per part.

## Risks

- **Over-flooring annoyance.** Commands legitimately using `$HOME`/globs under an
  allow rule now ask. This is the intended trade (correctness over convenience);
  the wildcard escape hatch (`*`) lets an author opt a position out explicitly.
  Mitigated by a clear reason so the user understands the ask.
- **Binding-value struct change (D2)** touches the engine's binding environment
  and its `Arbitrary`/proptest generators. Contained to one crate.

## Migration

None. No surface, canonical-form, or trust-hash change.
