## MODIFIED Requirements

### Requirement: Argv Patterns scope to the outer slice

The Patterns `(flag …)`, `(parameter …)`, `(positional …)`, `(exact …)`, `(anywhere …)`, `(forbidden …)` SHALL operate exclusively on the outer slice produced by tokenisation. Tokens past the outer slice (claimed by the parser's `(rest …)` binding) SHALL NOT be visible to these Patterns.

The outer/rest split SHALL be determined by the parser's `(flags MODE)`:

- Under `(flags posix)` the outer slice ends at the first non-flag token; everything from that point on is rest.
- Under `(flags (until STR…))` the outer slice ends immediately before the first matching boundary token; the boundary token is consumed and dropped, and the remainder is rest.
- Under `(flags permute)` (the default for undeclared programs) the outer slice is the whole argv and there is no rest unless a positional declaration leaves a residual.

Tokens claimed by a parser's `(positional …)` declaration SHALL remain visible to
these Patterns. A positional declaration names a token; it does not hide it. This
SHALL hold under every `(flags MODE)`:

- Under `(flags posix)` the outer slice visible to Patterns SHALL comprise exactly the tokens claimed by positional declarations. Tokens claimed by `(rest …)` SHALL remain hidden.
- Under `(flags (until STR…))` it SHALL comprise the pre-boundary positional residual.
- Under `(flags permute)` it SHALL comprise the whole positional residual, whether or not a declaration claimed each token.

The rest slice SHALL be addressable only via `(authorise #var)` where `#var` is the parser's `(rest …)` binding (typically `#cmd`).

#### Scenario: Flag Pattern does not see rest tokens under posix

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))` and `(rule "sudo" (and (flag "r") (deny "outer flag")))`
- **WHEN** evaluating `sudo rm -rf /tmp/x`
- **THEN** `(flag "r")` SHALL NOT match (the `-r` is in the rest slice).

#### Scenario: Forbidden Pattern does not see rest tokens under posix

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))` and `(rule "sudo" (and (forbidden "secret") (allow)))`
- **WHEN** evaluating `sudo echo secret`
- **THEN** `(forbidden "secret")` SHALL succeed (the `secret` token is in the rest slice, not visible).

#### Scenario: Outer slice ends at boundary token under until

- **GIVEN** `(parser "nix" (style gnu) (flags (until "--command" "-c")) (rest #cmd))` and `(rule "nix" (and (flag "i") (deny "no impure")))`
- **WHEN** evaluating `nix --command bash -i`
- **THEN** `(flag "i")` SHALL NOT match (the `-i` is past the `--command` boundary, in the rest slice).

#### Scenario: Declared positional token stays visible to Patterns

- **GIVEN** the Prelude `ssh` parser (`(flags posix)`, `(positional #host (regex "^[^-].*"))`, `(rest #cmd)`) and `(rule "ssh" (when (anywhere "media-server") (ask "remote host")))`
- **WHEN** evaluating `ssh media-server sudo -n true`
- **THEN** `(anywhere "media-server")` SHALL match.

#### Scenario: Declared positional does not expose the rest slice

- **GIVEN** the Prelude `ssh` parser and `(rule "ssh" (when (anywhere "sudo") (deny "no sudo")))`
- **WHEN** evaluating `ssh media-server sudo -n true`
- **THEN** `(anywhere "sudo")` SHALL NOT match (the `sudo` token belongs to `#cmd`).

## REMOVED Requirements

### Requirement: Bind is valid in positional, exact, and anywhere but not forbidden

**Reason**: The `[:k …]` bind Pattern is removed from the Pattern sublanguage.
It was accepted in six positions and produced a Fact in exactly one (inside a
Quantifier); in `(positional …)`, `(exact …)` and `(anywhere …)` the captured
value was matched, reported in the Trace, and then silently discarded. Writing a
Fact is now the job of a rule-body form, not a side effect of matching.

**Migration**: Declare the token as a parser `(positional #var …)` and bind it
with `(let-facts [[:k #var]] BODY)`. A bind Pattern remaining in any of these
positions is a load-time error naming the replacement.

### Requirement: Fact-binding capture under quantifiers

**Reason**: Capture inside `(every? …)` and `(some? …)` made a test also a write,
which required re-walking a matched expression to recover which branch matched.
Facts are now written only by `(let-facts …)`, and `(filter #var PAT)` expresses
the subset selection `(some? …)` capture provided.

**Migration**: `(when (every? #v (and PAT [:k *])) BODY)` becomes
`(when (every? #v PAT) (let-facts [[:k #v]] BODY))`. `(some? #v (and PAT [:k *]))`
becomes a `(some? #v PAT)` guard with `(let-facts [[:k (filter #v PAT)]] BODY)`.
Note that the resulting Fact replaces any enclosing value for `:k` rather than
accumulating onto it. Both rewrites are applied automatically by `may-i migrate`.
