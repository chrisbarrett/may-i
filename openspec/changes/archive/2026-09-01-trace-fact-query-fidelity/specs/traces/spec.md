## MODIFIED Requirements

### Requirement: Human trace renders compact evidence for context fact queries
The human-readable evaluation trace SHALL preserve the written `fact?` query on the left and summarize context-fact evidence on the right using a single compact annotation. The rendered query SHALL use the spelling the DSL currently accepts; retired spellings SHALL NOT appear. Presence queries MUST render only `yes` or `no`. Exact scalar queries MUST render `yes` on success, the observed scalar value on mismatch, and `no` when no scalar value is available. Pattern-based scalar queries MUST render the observed scalar value with the final verdict whenever a scalar value is available, and `no` otherwise.

A fact key holds a set of values. A *scalar value* is available only when that set has exactly one member, matching `ContextFacts::get_scalar`.

When the set holds more than one member:

- On a match, the annotation MUST name the member that satisfied the query — the *witness* — with the verdict. It MUST NOT name a member that did not satisfy it.
- On a mismatch, the annotation MUST render `no`, since no single member accounts for the verdict.
- Exact queries MUST continue to render `yes` on success without echoing the value, which the query already states.

#### Scenario: Presence query renders only the verdict
- **WHEN** a rendered trace includes `(fact? :via/ssh)` and the context contains `:via/ssh`
- **THEN** the right column for that query is `yes`

#### Scenario: Exact scalar mismatch renders the observed value
- **WHEN** a rendered trace includes `(fact? [:opencode/agent "build"])` and the context contains `:opencode/agent` = `{"plan"}`
- **THEN** the right column for that query is `"plan" -> no`

#### Scenario: Pattern-based scalar query renders the observed value on success
- **WHEN** a rendered trace includes `(fact? [:ssh/host (regex "^prod-")])` and the context contains `:ssh/host` = `{"prod-1"}`
- **THEN** the right column for that query is `"prod-1" -> yes`

#### Scenario: Missing scalar value renders plain no
- **WHEN** a rendered trace includes `(fact? [:ssh/host (regex "^prod-")])` and the context does not include `:ssh/host`
- **THEN** the right column for that query is `no`

#### Scenario: Query renders with the accepted spelling
- **WHEN** a config contains `(rule "echo" (if (fact? [:via "ssh"]) (deny "remote") (allow)))` and a trace is rendered for it
- **THEN** the left column shows `(fact? [:via "ssh"])`
- **AND** the left column does not contain `has`

#### Scenario: Multi-member match names the satisfying value
- **WHEN** a rendered trace includes `(fact? [:o/all "a=1"])` and the context contains `:o/all` = `{"BAD", "a=1"}`
- **THEN** the right column for that query is `yes`
- **AND** the right column does not contain `BAD`

#### Scenario: Multi-member pattern match names the witness
- **WHEN** a rendered trace includes `(fact? [:via (regex "^ss")])` and the context contains `:via` = `{"ssh", "sudo"}`
- **THEN** the right column for that query is `"ssh" -> yes`

#### Scenario: Multi-member mismatch renders plain no
- **WHEN** a rendered trace includes `(fact? [:via "docker"])` and the context contains `:via` = `{"ssh", "sudo"}`
- **THEN** the right column for that query is `no`
- **AND** the right column names neither `ssh` nor `sudo`
