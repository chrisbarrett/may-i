## ADDED Requirements

### Requirement: Trace producer records structural data, not display strings
`TracingFold` and the `Ann` / `TraceEntry` types it populates SHALL carry
structural data only. Display-only formatting — parser flag-mode
rendering, observed-value summarisation prose, regex literal quoting,
fact-failure prose, and any other transformation whose output exists to
satisfy the two-column text renderer's layout — SHALL live in the
renderer, not the producer.

Concretely, a field on `Ann` or `TraceEntry` MUST NOT be populated by
calling a display-format helper. Enum / struct field types MUST match
the structural shape of the recorded value (sets, integers, enums,
literal-source strings such as a regex pattern or a binding name), not
a pre-rendered display string.

#### Scenario: Parser entry records flag mode structurally
- **WHEN** `TracingFold` records a `TraceEntry::Parser` for a parser
  declared with `(flags until "--")`
- **THEN** the recorded flag-mode field carries the structural until-list
  (e.g. `Until(["--"])`), not the pre-rendered string `"until \"--\""`

#### Scenario: FactQuery records observed values structurally
- **WHEN** `TracingFold` records an `Ann::FactQuery` for a query against
  facts where the key has values `{"prod", "staging"}`
- **THEN** the recorded observed-values field carries the set
  `{"prod", "staging"}`, not a pre-rendered comma-joined string

#### Scenario: FactQuery records failure mode structurally
- **WHEN** a fact query fails because the key is absent
- **THEN** the recorded failure-mode field carries a structural variant
  (e.g. `FactFailure::KeyAbsent`), not the prose string the renderer
  emits

#### Scenario: Text renderer formats from structural data
- **WHEN** `trace_to_layout` (or its successor) renders a
  `TraceEntry::Parser` with the structural flag-mode field
- **THEN** it produces the same byte sequence the previous implementation
  produced from the pre-rendered string

#### Scenario: JSON renderer formats from structural data
- **WHEN** `trace_to_json` serialises a `TraceEntry` carrying structural
  fields
- **THEN** the JSON output bytes are unchanged from the previous
  implementation; field names and values match the previous shape
  byte-for-byte
