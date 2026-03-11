## MODIFIED Requirements

### Requirement: OpenCode context can gate rule evaluation
Rules SHALL be able to use existing `(context ...)` expressions to match against OpenCode runtime facts supplied explicitly on the `eval` path.

#### Scenario: Rule matches a specific OpenCode agent
- **WHEN** a rule includes `(context (has [:opencode/agent "plan"]))` and `may-i eval` runs with `--fact :client/opencode --fact :opencode/agent=plan`
- **THEN** that rule's context clause matches

#### Scenario: Rule does not match a different OpenCode agent
- **WHEN** a rule includes `(context (has [:opencode/agent "plan"]))` and `may-i eval` runs with `--fact :client/opencode --fact :opencode/agent=build`
- **THEN** that rule is skipped as though its context clause did not match
