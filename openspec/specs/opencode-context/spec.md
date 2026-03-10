### Requirement: Eval ingests explicit OpenCode agent context
When `may-i eval` is invoked with explicit OpenCode runtime metadata, the evaluator SHALL expose that metadata as namespaced context facts during rule matching.

#### Scenario: OpenCode agent is exposed as context facts
- **WHEN** `may-i eval` runs with `MAYI_OPENCODE_AGENT=plan`
- **THEN** the evaluation context includes `:client/opencode`
- **AND** the evaluation context includes `:opencode/agent = "plan"`

#### Scenario: Missing OpenCode metadata produces no OpenCode facts
- **WHEN** `may-i eval` runs without `MAYI_OPENCODE_AGENT`
- **THEN** the evaluation context does not include `:client/opencode`
- **AND** the evaluation context does not include `:opencode/agent`

### Requirement: OpenCode context can gate rule evaluation
Rules SHALL be able to use existing `(context ...)` expressions to match against OpenCode runtime facts supplied on the `eval` path.

#### Scenario: Rule matches a specific OpenCode agent
- **WHEN** a rule includes `(context (= :opencode/agent "plan"))` and `may-i eval` runs with `MAYI_OPENCODE_AGENT=plan`
- **THEN** that rule's context clause matches

#### Scenario: Rule does not match a different OpenCode agent
- **WHEN** a rule includes `(context (= :opencode/agent "plan"))` and `may-i eval` runs with `MAYI_OPENCODE_AGENT=build`
- **THEN** that rule is skipped as though its context clause did not match

### Requirement: OpenCode context remains inspectable in eval output
`may-i eval` SHALL preserve traceability for OpenCode-gated decisions so users can understand when OpenCode runtime facts affected the result.

#### Scenario: JSON eval includes context-aware trace details
- **WHEN** `may-i --json eval` matches or skips a rule because of `:opencode/agent`
- **THEN** the JSON response includes trace data that reflects the context-based evaluation

#### Scenario: Human-readable eval reflects the same decision
- **WHEN** `may-i eval` is run with OpenCode context that changes which rule matches
- **THEN** the reported decision and trace output reflect the same OpenCode-aware evaluation as JSON mode
