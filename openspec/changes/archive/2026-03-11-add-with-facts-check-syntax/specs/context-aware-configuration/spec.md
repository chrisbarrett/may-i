## ADDED Requirements

### Requirement: Checks can scope context facts with explicit fact blocks
The configuration DSL SHALL allow `(check ...)` forms to contain `(with-facts FACTS ...BODY...)` scopes that apply namespaced context facts to nested check assertions. `FACTS` SHALL be a vector of fact-entry vectors, where a one-element entry declares a presence fact and a two-element entry declares a scalar fact. The body of `with-facts` SHALL allow plain decision-and-command assertions plus nested `with-facts` scopes.

#### Scenario: Scoped facts apply to multiple assertions
- **WHEN** a check contains `(with-facts [[:client/opencode] [:opencode/agent "build"]] :allow "git add ." :allow "git checkout main")`
- **THEN** both assertions are evaluated with `:client/opencode` present and `:opencode/agent = "build"`

#### Scenario: Nested scopes refine outer facts
- **WHEN** a check contains an outer `(with-facts [[:client/opencode]])` scope and an inner `(with-facts [[:opencode/agent "plan"]] :ask "git add .")`
- **THEN** the inner assertion is evaluated with both the outer `:client/opencode` fact and the inner `:opencode/agent = "plan"` fact

#### Scenario: Inner scopes override matching outer keys
- **WHEN** an outer `with-facts` scope binds `[:opencode/agent "build"]` and a nested scope binds `[:opencode/agent "plan"]`
- **THEN** assertions in the nested scope are evaluated with `:opencode/agent = "plan"`

### Requirement: Check fact literals reject duplicate keys and preserve simple fact semantics
The evaluator MUST treat each `with-facts` literal as a coherent fact set. Repeating the same fact key more than once inside a single fact vector MUST be a configuration error. Multiple distinct `:via/*` facts MAY appear together in one fact literal, but their order SHALL NOT carry provenance semantics.

#### Scenario: Duplicate scalar key is rejected
- **WHEN** a `with-facts` literal contains both `[:opencode/agent "build"]` and `[:opencode/agent "plan"]`
- **THEN** configuration loading fails with an error describing the duplicate fact key

#### Scenario: Duplicate presence key is rejected
- **WHEN** a `with-facts` literal contains `[:client/opencode]` more than once
- **THEN** configuration loading fails with an error describing the duplicate fact key

#### Scenario: Multiple via facts are allowed together
- **WHEN** a `with-facts` literal contains `[:via/sudo]` and `[:via/ssh]`
- **THEN** both provenance facts are present during evaluation
- **AND** evaluation does not infer any ordering semantics from their position in the vector

### Requirement: Suspicious empty with-facts forms remain recoverable
The configuration loader SHALL emit warnings when a `with-facts` literal contains no fact entries or when a `with-facts` body contains no assertions. Empty `with-facts` forms SHALL remain parseable so users receive recoverable diagnostics instead of a hard parse failure.

#### Scenario: Empty fact vector warns
- **WHEN** a check contains `(with-facts [] :allow "git add .")`
- **THEN** configuration loading succeeds
- **AND** a warning reports that the fact literal binds no facts

#### Scenario: Empty with-facts body warns
- **WHEN** a check contains `(with-facts [[:client/opencode]])` with no nested assertions
- **THEN** configuration loading succeeds
- **AND** a warning reports that the scope contains no assertions

## REMOVED Requirements

### Requirement: Inline check facts use the `(facts ...)` form
**Reason**: Inline fact payloads broke the plist-style readability of `(check ...)` forms and made shared context across assertions noisy.
**Migration**: Rewrite context-sensitive checks to use `(with-facts [[:key] [:key "value"]] ...assertions...)` blocks.
