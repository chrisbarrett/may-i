## ADDED Requirements

### Requirement: `(let-facts [[:k VALUE] …] BODY)` binds Facts for a body

The rule-body form `(let-facts BINDINGS BODY)` SHALL accept a vector of
`[:k VALUE]` pairs and evaluate `BODY` with each `:k` Fact bound to `VALUE`.

The binding SHALL apply to `BODY` and to every evaluation `BODY` reaches through
`(authorise …)`, and SHALL NOT apply outside `BODY`.

Binding SHALL replace, not accumulate. When `:k` already holds a value from an
enclosing scope, `BODY` SHALL observe only the value given here. The enclosing
value SHALL NOT be observable inside `BODY` through any query.

`VALUE` SHALL be one of:

- `#var` — the value of the named Binding.
- `(filter #var PAT)` — those values of the named Binding matching `PAT`.
- A literal string.
- Omitted — `[:k]` binds `:k` as a presence Fact.

When `VALUE` names a Binding that is unbound for this invocation, or a
`(filter …)` that selects nothing, `:k` SHALL be absent inside `BODY` — neither
present-with-no-values nor inherited from an enclosing scope. `BODY` SHALL still
be evaluated.

`(let-facts …)` SHALL be usable wherever a rule-body form is accepted, and MAY
nest.

#### Scenario: Binding is visible to the authorised command

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (positional #host *) (rest #cmd))` and `(rule "ssh" (let-facts [[:ssh/host #host]] (authorise #cmd)))` and `(rule "rm" (when (fact? [:ssh/host *]) (ask "rm on remote host")))`
- **WHEN** evaluating `ssh prod.example.com rm /tmp/x`
- **THEN** the inner evaluation's Facts SHALL include `:ssh/host "prod.example.com"`
- **AND** the rule for `rm` SHALL reach its `(ask …)`.

#### Scenario: Innermost binding wins over an enclosing one

- **GIVEN** the configuration above plus `(rule "sudo" (when (fact? [:ssh/host "media-server"]) (allow "elevated on media-server")))`
- **WHEN** evaluating `ssh jump-host ssh media-server sudo -n reboot`
- **THEN** the evaluation of `sudo` SHALL observe `:ssh/host` = `{"media-server"}`
- **AND** SHALL NOT observe `"jump-host"`.

#### Scenario: Unbound value removes the key rather than inheriting it

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (positional #host ? *) (rest #cmd))` and `(rule "ssh" (let-facts [[:ssh/host #host]] (authorise #cmd)))` and `(rule "rm" (if (fact? [:ssh/host *]) (deny "host leaked") (allow "no host")))`
- **WHEN** evaluating a nested invocation in which the outer `ssh` binds `#host` and the inner `ssh` leaves it unbound
- **THEN** the innermost evaluation SHALL NOT have a `:ssh/host` Fact
- **AND** the rule for `rm` SHALL reach its `(allow …)`.

#### Scenario: Presence Fact and literal value

- **GIVEN** `(rule "ssh" (let-facts [[:reviewed] [:tier "production"]] (authorise #cmd)))`
- **WHEN** evaluating `ssh host ls`
- **THEN** the inner evaluation SHALL satisfy `(fact? :reviewed)`
- **AND** SHALL satisfy `(fact? [:tier "production"])`.

#### Scenario: `(filter …)` selects a subset of a collection Binding

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)) (rest #cmd))` and `(rule "ssh" (let-facts [[:ssh/proxy (filter #opts (regex "^ProxyCommand="))]] (authorise #cmd)))`
- **WHEN** evaluating `ssh -o BatchMode=yes -o ProxyCommand="nc h p" host ls`
- **THEN** the inner evaluation's `:ssh/proxy` SHALL contain `"ProxyCommand=nc h p"`
- **AND** SHALL NOT contain `"BatchMode=yes"`.

## MODIFIED Requirements

### Requirement: Bindings live within parser evaluation and inner recurse

A parser-bound name SHALL be visible in:

- The rule body matched against the current command (read-only access via `(authorise #var)`, `(bound? #var)`, `(matches? #var …)`, `(let-facts [[:k #var]] …)`).
- The inner recurse triggered by `(authorise #var)` — but only if explicitly bound to a Fact via `(let-facts …)`. Parser-bound names SHALL NOT automatically propagate to inner recurses.

Parser-bound names SHALL NOT escape their parser's evaluation scope. A rule body for command A SHALL NOT reference bindings declared by the parser for command B.

#### Scenario: Bindings do not auto-propagate to inner recurse

- **GIVEN** `(parser "timeout" (style gnu) (flags posix) (positional #duration *) (rest #cmd))` and `(rule "timeout" (authorise #cmd))` and `(rule "rm" (when (bound? #duration) (ask "should not match")))`
- **WHEN** evaluating `timeout 30 rm /tmp/x`
- **THEN** the inner rule for `rm` SHALL NOT have `#duration` in scope
- **AND** `(bound? #duration)` in the inner rule SHALL fail at load (binding not declared by `rm`'s parser).

#### Scenario: Promoted fact is visible in inner recurse

- **GIVEN** `(parser "timeout" (style gnu) (flags posix) (positional #duration *) (rest #cmd))` and `(rule "timeout" (let-facts [[:timeout/duration #duration]] (authorise #cmd)))`
- **WHEN** evaluating `timeout 30 rm /tmp/x`
- **THEN** the inner evaluation's Facts SHALL include `:timeout/duration "30"`.

## REMOVED Requirements

### Requirement: `(with-facts [[:k #var]] BODY)` promotes binding to a fact

**Reason**: Never implemented, and its semantics conflict with the write model
this change establishes. It specified that an unbound `#var` leaves the Fact "at
its parent-scope value, or absent", which makes an enclosing value observable in
exactly the case an author is trying to override. Its name also collides with the
Check-block `(with-facts …)` form, where `with-` denotes merging — the opposite
of the replacement semantics intended here.

**Migration**: Use `(let-facts [[:k #var]] BODY)`, which replaces rather than
merges and removes the key when `#var` is unbound. The Check-block
`(with-facts …)` form is unchanged and keeps its merging semantics.
