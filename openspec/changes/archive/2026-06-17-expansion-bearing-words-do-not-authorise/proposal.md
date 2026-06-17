## Why

`may-i` matches the **surface bytes** of a command, but a rule's author reasons
about the command's **runtime effect**. When a matched word carries a shell
expansion, those two diverge, and an allow rule built as a guard is bypassed by
the divergence. Confirmed against the built binary with a `^/tmp/` allow guard:

```
(parser "rm" (style gnu) (flags posix) (positional #paths (regex "^/tmp/") *))
(rule   "rm" (when (every? #paths (regex "^/tmp/")) (allow "tmp only")))
```

| input | decision | why it is wrong |
| --- | --- | --- |
| `rm /tmp/x` | allow | correct |
| `rm /tmp/$HOME` | **allow** | `$HOME` unexpanded; the runtime path is `/root`, not under `/tmp` |
| `rm /tmp/*` | **allow** | glob; the runtime targets are whatever the glob expands to |
| `rm /tmp/{a,../etc}` | **allow** | brace expansion reaches `../etc` |

In every bypass the matcher saw a string starting `^/tmp/` and authorised it,
while the value bash will actually operate on is provably *not* known at
authorisation time. The guard reads as sound to its author and is not. This is
the load-bearing failure mode for a tool whose job is to authorise before
execution: a matched constraint that contributes to `:allow` must constrain the
value that will run, not a literal that the shell will rewrite.

The same divergence is harmless — even desirable — when the decision is `:ask`
or `:deny`: floors and denials erring toward caution is the safe direction. The
fix is therefore **asymmetric**, and that asymmetry is the security invariant
this change makes normative.

## What Changes

- Add the **asymmetric-soundness invariant** to the security model: a parse or
  match imprecision SHALL never move a decision *toward* `:allow`; it may only
  move it toward `:ask`/`:deny`. This frames the whole security model and is
  referenced by sibling changes (redirect/env-prefix visibility, embedded-
  command extraction).
- Define an **expansion-bearing word**: a word any of whose parts is a parameter
  expansion (`$x`, `${…}`), command substitution (`$(…)`, `` `…` ``), arithmetic
  expansion (`$((…))`), process substitution, an unquoted glob metacharacter
  (`*`, `?`, `[`), an unquoted brace expansion (`{a,b}`), or an unquoted leading
  tilde (`~`) — i.e. a word whose runtime value is not provable from its source
  bytes.
- A matcher that inspects an expansion-bearing word (`(positional …)`,
  `(exact …)`, `(anywhere …)`, `(parameter X FORM)` value, `(flag X)` value,
  `(every?/some? #var …)` element, `(matches? #var …)`) against a non-wildcard
  expression SHALL NOT report a match that contributes to `:allow`. The segment
  SHALL floor to at least `:ask` with a reason naming the unresolved word.
- The wildcard `*` (the Pattern atom) and bare presence checks SHALL be
  unaffected: matching "any value" is sound regardless of expansion. `(bound?
  #var)` is unaffected. Pure-literal words (no expansion) are unaffected — a
  literal `/tmp/../etc` matching `^/tmp/` is the author's regex semantics, out of
  scope here and documented as such.

## Capabilities

### New Capabilities

<!-- none -->

### Modified Capabilities

- `shell-command-security-model` (bucket: parsing; trust-relevant): add the
  asymmetric-soundness invariant, and the requirement that an expansion-bearing
  word cannot satisfy a non-wildcard matcher toward `:allow` (floors to `:ask`).

## Impact

- `crates/shell-parser` — expose, per `Word`, whether it is expansion-bearing
  (any dynamic `WordPart`, or an unquoted glob/brace/tilde metacharacter). The
  dynamic `WordPart` variants already carry this; glob/brace/tilde detection over
  literal parts is new.
- `crates/engine/src/eval` — at the matcher seam, when a non-wildcard expression
  is tested against an expansion-bearing word in a position that could
  contribute to `:allow`, suppress the match and floor the segment to `:ask`
  with an unresolved-word reason. The floor reuses the existing
  Error-severity-floor plumbing's "raise to at least ask" combinator; it does
  not fabricate a parse diagnostic.
- Trace: the suppressed match renders with its evidence and an "unresolved
  expansion" annotation rather than a silent no-match.
- No DSL or config surface change. Trust-hash unaffected (no canonical-form
  change). No migration. Out of scope: expanding the values (we never run the
  shell), pure-literal path traversal, and `:ask`/`:deny` matches (the asymmetry
  intentionally leaves those alone).
