## MODIFIED Requirements

### Requirement: Rule-body operators have declared shape signatures

Each rule-body form that consumes a `#var` SHALL declare the shape(s) it
accepts. The type checker SHALL reject a use whose argument shape does
not match.

The signatures SHALL be:

- `(authorise #v)` — `#v : Command`. Other shapes SHALL fail at load.
- `(bound?    #v)` — `#v : ∀τ. τ` (any shape). Always permitted.
- `(matches?  #v PAT)` — `#v : Token | Command`. Collection and Count
  shapes SHALL fail at load.
- `(every?    #v PRED)` — `#v : Collection Token`. Other shapes SHALL
  fail at load.
- `(some?     #v PRED)` — `#v : Collection Token`. Other shapes SHALL
  fail at load.
- `(let-facts [[:k #v]] BODY)` — `#v : Token | Command | Collection
  Token`. `Count` SHALL fail at load.
- `(filter #v PAT)` — `#v : Collection Token`. Other shapes SHALL fail
  at load, since a single value is filtered by a conditional rather
  than by selection.

`(filter …)` SHALL appear only as the value position of a `(let-facts …)`
pair, never as a rule-body form or as a test.

`PRED` in `(every? …)` and `(some? …)` SHALL be a single-token Pattern
expression (literal, regex, wildcard `*`, `(or …)`, `(and …)`, `(not
…)`); shapes carried by sub-expressions are unconstrained because the
predicate operates on individual tokens, not on a `#var` directly.

#### Scenario: `(authorise …)` on Collection rejects

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)))` and `(rule "ssh" (authorise #opts))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with a shape-mismatch diagnostic
- **AND** the diagnostic SHALL name `#opts` as `Collection Token` and
  `(authorise …)` as requiring `Command`.

#### Scenario: `(every? …)` on Token rejects

- **GIVEN** `(parser "xargs" (style gnu) (flags posix) (parameter "n" #procs) (rest #cmd))` and `(rule "xargs" (when (every? #procs (regex "^[0-9]+$")) (allow)))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with a shape-mismatch diagnostic
- **AND** the diagnostic SHALL name `#procs` as `Token` and `(every?
  …)` as requiring `Collection Token`.

#### Scenario: `(matches? …)` on Collection rejects

- **GIVEN** `(parser "find" (style single-dash-long) (flags permute) (parameter "exec" (many-till ";") #args))` evaluated under a hypothetical rule `(rule "find" (when (matches? #args (regex "rm")) (ask)))`
- **WHEN** the config is loaded
- **THEN** the loader SHALL accept the rule because the `(many-till …)`
  capture has shape `Command` (string-joined), not `Collection Token`
- **AND** the existing `(matches? …)` semantics over a `Command`-shaped
  binding SHALL apply.

#### Scenario: `(let-facts …)` on a Count binding rejects

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (flag "v" (count #verbosity)) (rest #cmd))` and `(rule "ssh" (let-facts [[:ssh/verbosity #verbosity]] (authorise #cmd)))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with a shape-mismatch diagnostic
- **AND** the diagnostic SHALL name `#verbosity` as `Count` and
  `(let-facts …)` as requiring `Token`, `Command` or `Collection Token`.

#### Scenario: `(filter …)` on a Token binding rejects

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (positional #host *) (rest #cmd))` and `(rule "ssh" (let-facts [[:ssh/host (filter #host (regex "^prod"))]] (authorise #cmd)))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with a shape-mismatch diagnostic
- **AND** the diagnostic SHALL name `#host` as `Token` and `(filter …)`
  as requiring `Collection Token`.
