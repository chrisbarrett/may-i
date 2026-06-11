## ADDED Requirements

### Requirement: Match and parse imprecision never widens toward allow

The evaluator SHALL treat every imprecision in parsing a command or matching a
Pattern as moving the decision only toward `:ask`/`:deny`, never toward
`:allow`. Formally: for any command `cmd` and config `C`, if the engine is
uncertain whether a matcher's constraint holds for the value that will run
(because the source under-determines that value), the matcher SHALL NOT report
the match as contributing to `:allow`. An uncertain matcher that could only have
tightened the decision (a `(forbidden …)`, a `(not (flag …))`, the test arm of
an `unless`) MAY still fire, because firing it errs toward caution.

This is the security model's load-bearing invariant: `may-i` authorises before
execution, so an authorisation (`:allow`) MUST rest on a constraint that holds
for the runtime value, while a refusal (`:ask`/`:deny`) is sound under
uncertainty. The Error-severity parse floor (see "Error-severity diagnostics
floor decision at ask") and the expansion-bearing-word rule below are both
instances of this invariant.

#### Scenario: Uncertainty floors an otherwise-allow segment to ask

- **WHEN** a segment would evaluate to `:allow` only because a matcher reported a
  match it could not prove for the runtime value
- **THEN** the segment's decision SHALL be at least `:ask`

#### Scenario: Uncertainty does not relax a deny

- **WHEN** a segment evaluates to `:deny`
- **AND** some matcher in the same segment was uncertain
- **THEN** the decision SHALL remain `:deny` (uncertainty never relaxes)

### Requirement: Expansion-bearing words do not satisfy an allow constraint

A non-wildcard matcher tested against an expansion-bearing word SHALL NOT report
a match that contributes to `:allow`; the enclosing segment SHALL floor to at
least `:ask`.

A word is **expansion-bearing** when any of its parts is a parameter expansion
(`$x`, `${…}`), a command substitution (`$(…)`, `` `…` ``), an arithmetic
expansion (`$((…))`), a process substitution (`<(…)`, `>(…)`), an unquoted glob
metacharacter (`*`, `?`, `[`), an unquoted brace expansion (`{a,b}`), or an
unquoted leading tilde (`~`) — i.e. a word whose runtime value is not provable
from its source bytes.

When a rule-body matcher tests a **non-wildcard** expression against an
expansion-bearing word, the matcher SHALL NOT report a match that contributes to
`:allow`. The enclosing segment's decision SHALL floor to at least `:ask`, with a
reason naming the unresolved word. The matchers in scope are `(positional …)`,
`(exact …)`, `(anywhere …)`, the value form of `(parameter X FORM)`, the value
form of `(flag X)`, each element tested by `(every? #var …)` / `(some? #var …)`,
and `(matches? #var PAT)`.

A **non-wildcard** expression is any single-token Pattern other than the
wildcard atom `*`: a string literal, `(regex …)`, or an `(or …)`/`(and …)`/`(not
…)` composed of such. The wildcard atom `*` matches "any value" and SHALL remain
sound against an expansion-bearing word (it constrains nothing). `(bound? #var)`
SHALL be unaffected (it tests presence, not value). A word with no expansion
part SHALL be unaffected: a pure literal is matched as written, and a literal
that defeats the author's regex (e.g. `/tmp/../etc` against `^/tmp/`) is the
regex's own semantics, outside this requirement.

#### Scenario: Parameter expansion in a positional defeats an allow guard

- **GIVEN** `(parser "rm" (style gnu) (flags posix) (positional #paths (regex "^/tmp/") *))` and `(rule "rm" (when (every? #paths (regex "^/tmp/")) (allow "tmp only")))`
- **WHEN** evaluating `rm /tmp/$HOME`
- **THEN** the `(regex "^/tmp/")` element test against `/tmp/$HOME` SHALL NOT
  contribute to `:allow`
- **AND** the decision SHALL be at least `:ask`
- **AND** the reason SHALL name the unresolved word `/tmp/$HOME`

#### Scenario: Glob in a matched positional floors to ask

- **GIVEN** the configuration above
- **WHEN** evaluating `rm /tmp/*`
- **THEN** the decision SHALL be at least `:ask` (the glob's runtime targets are
  not provable from the source)

#### Scenario: Brace expansion in a matched positional floors to ask

- **GIVEN** the configuration above
- **WHEN** evaluating `rm /tmp/{a,../etc}`
- **THEN** the decision SHALL be at least `:ask`

#### Scenario: Wildcard matcher is unaffected by expansion

- **GIVEN** `(rule "rm" (when (positional *) (allow "any single arg")))`
- **WHEN** evaluating `rm $HOME`
- **THEN** the wildcard `*` SHALL match `$HOME` and the decision SHALL be
  `:allow` (matching "any value" is sound regardless of expansion)

#### Scenario: Pure-literal word is matched as written

- **GIVEN** `(rule "rm" (when (positional "/tmp/x") (allow)))`
- **WHEN** evaluating `rm /tmp/x`
- **THEN** the decision SHALL be `:allow` (no expansion part; literal match)

#### Scenario: Expansion in a deny matcher still fires

- **GIVEN** `(rule "rm" (when (anywhere (regex "secret")) (deny "no secrets")))`
- **WHEN** evaluating `rm secret$X`
- **THEN** `(anywhere (regex "secret"))` MAY match and the decision SHALL be
  `:deny` (firing a deny under expansion errs toward caution)

#### Scenario: Expansion in a flag value floors an allow

- **GIVEN** `(rule "kubectl" (when (parameter ["n" "namespace"] (regex "^dev-")) (allow "dev namespaces")))`
- **WHEN** evaluating `kubectl -n dev-$ENV get pods`
- **THEN** the `(regex "^dev-")` test against the expansion-bearing value
  `dev-$ENV` SHALL NOT contribute to `:allow`
- **AND** the decision SHALL be at least `:ask`
