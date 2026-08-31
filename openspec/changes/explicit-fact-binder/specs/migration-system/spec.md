## ADDED Requirements

### Requirement: Migration rule `bind_pattern_to_let_facts`

The migration rule SHALL rewrite Quantifier Fact-binding capture into an explicit
`(let-facts …)` form, and SHALL leave bind Patterns it cannot rewrite for the
loader to reject.

**Trigger:** a `[:k PAT]` bind Pattern anywhere in a rule body.

**Rewrites:**

- `(when (every? #v BIND) BODY)` where `BIND` contains `[:k *]` SHALL become
  `(when (every? #v PAT) (let-facts [[:k #v]] BODY))`, where `PAT` is `BIND` with
  the bind Pattern removed. When removing the bind leaves no constraint, `PAT`
  SHALL be `*`.
- `(when (some? #v BIND) BODY)` SHALL become
  `(when (some? #v PAT) (let-facts [[:k (filter #v PAT)]] BODY))`.
- A bind Pattern in `(positional …)`, `(exact …)` or `(anywhere …)` SHALL be
  left in place. The loader reports it with a diagnostic naming `(let-facts …)`
  as the replacement, because the rewrite requires a parser declaration the
  migration cannot infer.

The rewrite SHALL preserve comments and formatting per the existing CST
roundtrip requirement.

Where a rewritten Fact previously accumulated onto an enclosing value and now
replaces it, the rewrite SHALL still be applied; the behaviour change is
reported in the migration diff rather than avoided.

#### Scenario: `every?` capture rewrites to a body-level binding

- **GIVEN** `(rule "ssh" (when (every? #opts (and (regex "=") [:ssh/opt *])) (allow)))`
- **WHEN** the migration rule `bind_pattern_to_let_facts` runs
- **THEN** the form rewrites to `(rule "ssh" (when (every? #opts (regex "=")) (let-facts [[:ssh/opt #opts]] (allow))))`

#### Scenario: `some?` capture rewrites to a filtered value

- **GIVEN** `(rule "ssh" (when (some? #opts (and (regex "^ProxyCommand=") [:ssh/proxy *])) (ask "review proxy")))`
- **WHEN** the migration rule `bind_pattern_to_let_facts` runs
- **THEN** the form rewrites to `(rule "ssh" (when (some? #opts (regex "^ProxyCommand=")) (let-facts [[:ssh/proxy (filter #opts (regex "^ProxyCommand="))]] (ask "review proxy"))))`

#### Scenario: Bare wildcard capture leaves an unconstrained quantifier

- **GIVEN** `(rule "ssh" (when (every? #opts [:ssh/opt *]) (allow)))`
- **WHEN** the migration rule `bind_pattern_to_let_facts` runs
- **THEN** the form rewrites to `(rule "ssh" (when (every? #opts *) (let-facts [[:ssh/opt #opts]] (allow))))`

#### Scenario: Bind in an argv Pattern is left for the loader

- **GIVEN** `(rule "ssh" (when (anywhere [:ssh/host *]) (allow)))`
- **WHEN** the migration rule `bind_pattern_to_let_facts` runs
- **THEN** the form is left unchanged
- **AND** loading the migrated config SHALL fail with a diagnostic naming `(let-facts …)` and the parser declaration needed to supply the binding.
