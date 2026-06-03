## ADDED Requirements

### Requirement: `(every? #var PRED)` folds a predicate over a collection binding

The rule-body form `(every? #var PRED)` SHALL evaluate `PRED` against
every element of the collection bound to `#var` and SHALL match iff
every element matches. `#var` SHALL be a parser-bound name whose
declared shape is `Collection Token` (see `binding-shapes`). Using
`(every? …)` on any other shape SHALL be a config-load error.

`PRED` SHALL be a single-token Pattern expression: a literal string,
the wildcard `*`, a `(regex …)`, an `(or …)`/`(and …)`/`(not …)` of
such expressions, or a fact-binding `[:k *]`.

The fold SHALL be vacuously true on the empty collection (zero
elements). Fact-binding patterns inside `PRED` SHALL contribute their
captured values to facts as if the matching pattern had been written
without a quantifier — see "Fact-binding capture under quantifiers"
below.

`(every? …)` SHALL be evaluable wherever a Pattern is expected: inside
`(and …)`, `(or …)`, `(not …)`, `(when …)`, `(unless …)`, `(if …)`,
and as a `(cond …)` test arm.

#### Scenario: All positionals match — every? is true

- **GIVEN** `(parser "rm" (style gnu) (flags posix) (positional #paths (regex "^/tmp/") *))` and `(rule "rm" (when (and (flag ["r" "recursive"]) (every? #paths (regex "^/tmp/"))) (allow "tmp paths")))`
- **WHEN** evaluating `rm -rf /tmp/a /tmp/b`
- **THEN** `(every? #paths (regex "^/tmp/"))` SHALL match
- **AND** the rule SHALL return `:allow "tmp paths"`.

#### Scenario: One positional fails — every? is no-match

- **GIVEN** the configuration above
- **WHEN** evaluating `rm -rf /tmp/a /etc/passwd`
- **THEN** `(every? #paths (regex "^/tmp/"))` SHALL NOT match (because
  `/etc/passwd` does not match the regex)
- **AND** the rule SHALL return no decision from this branch.

#### Scenario: Empty collection — every? is vacuously true

- **GIVEN** `(parser "rm" (style gnu) (flags posix) (positional #paths * *))` and `(rule "rm" (when (every? #paths (regex "^/tmp/")) (allow "vacuous")))`
- **WHEN** evaluating `rm` (no positionals)
- **THEN** `#paths` SHALL bind to the empty collection
- **AND** `(every? #paths (regex "^/tmp/"))` SHALL match
- **AND** the rule SHALL return `:allow "vacuous"`.

#### Scenario: Wrong shape fails at load

- **GIVEN** `(parser "xargs" (style gnu) (flags posix) (parameter "n" #procs) (rest #cmd))` and `(rule "xargs" (when (every? #procs (regex "^[0-9]+$")) (allow)))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with a shape-mismatch diagnostic naming
  `#procs` as `Token` and `(every? …)` as requiring `Collection Token`.

### Requirement: `(some? #var PRED)` matches when any element satisfies the predicate

The rule-body form `(some? #var PRED)` SHALL evaluate `PRED` against
every element of the collection bound to `#var` and SHALL match iff at
least one element matches. The shape requirement, predicate
sublanguage, and composition contexts SHALL be the same as for
`(every? …)`.

The fold SHALL be false on the empty collection (zero elements).

#### Scenario: One positional matches — some? is true

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)) (rest #cmd))` and `(rule "ssh" (when (some? #opts (regex "^ProxyCommand=")) (ask "review ProxyCommand")))`
- **WHEN** evaluating `ssh -o BatchMode=yes -o ProxyCommand="nc host port" target`
- **THEN** `(some? #opts (regex "^ProxyCommand="))` SHALL match
- **AND** the rule SHALL return `:ask "review ProxyCommand"`.

#### Scenario: No positional matches — some? is no-match

- **GIVEN** the configuration above
- **WHEN** evaluating `ssh -o BatchMode=yes target`
- **THEN** `(some? #opts (regex "^ProxyCommand="))` SHALL NOT match.

#### Scenario: Empty collection — some? is false

- **GIVEN** the configuration above
- **WHEN** evaluating `ssh target` (no `-o` flags)
- **THEN** `#opts` SHALL bind to the empty collection
- **AND** `(some? #opts (regex "^ProxyCommand="))` SHALL NOT match.

#### Scenario: Wrong shape fails at load

- **GIVEN** `(parser "bash" (style gnu) (flags posix) (parameter "c" (command #cmd)))` and `(rule "bash" (when (some? #cmd (regex "rm")) (deny)))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with a shape-mismatch diagnostic naming
  `#cmd` as `Command` and `(some? …)` as requiring `Collection Token`.

### Requirement: Fact-binding capture under quantifiers

Fact-binding patterns inside `(every? …)` and `(some? …)` SHALL
accumulate matched element values into facts in the enclosing rule's
fact environment.

When `PRED` inside `(every? …)` or `(some? …)` contains a fact-binding
`[:k *]`, every element that matches SHALL contribute its value to the
fact named `:k` in iteration order. The fact's accumulated values
SHALL be a set (consistent with existing fact-storage semantics) —
duplicates SHALL deduplicate.

For `(every? …)`, the fact SHALL accumulate exactly when the overall
fold matches (i.e. every element matches); when even one element
fails, no fact contribution SHALL be retained.

For `(some? …)`, the fact SHALL accumulate the values of every element
that matched (potentially more than one), regardless of whether other
elements failed.

#### Scenario: `(every? …)` with fact-binding accumulates all values

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)))` and `(rule "ssh" (when (every? #opts [:ssh/opt *]) (allow)))`
- **WHEN** evaluating `ssh -o BatchMode=yes -o ConnectTimeout=10 host`
- **THEN** the rule's fact environment SHALL include `:ssh/opt`
  containing both `"BatchMode=yes"` and `"ConnectTimeout=10"`.

#### Scenario: `(some? …)` with fact-binding accumulates matching values only

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)))` and `(rule "ssh" (when (some? #opts (and (regex "^ProxyCommand=") [:ssh/proxy *])) (ask "review proxy")))`
- **WHEN** evaluating `ssh -o BatchMode=yes -o ProxyCommand="nc h p" -o ProxyCommand="other" host`
- **THEN** the fact `:ssh/proxy` SHALL accumulate both ProxyCommand values
- **AND** SHALL NOT accumulate `BatchMode=yes`.
