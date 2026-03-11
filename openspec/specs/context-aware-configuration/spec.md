### Requirement: Rules can query namespaced context facts
The configuration DSL SHALL allow a rule to include a `(context EXPR)` clause whose expression is evaluated against a namespaced context fact set alongside command and argument matching. Context expressions SHALL support alias references plus explicit boolean composition with `(and ...)`, `(or ...)`, and `(not ...)`, and primitive predicates `(has :key)`, `(= :key "value")`, and `(matches :key "regex")`.

#### Scenario: Presence fact gates a rule
- **WHEN** a rule includes `(context (has :via/ssh))` and the evaluated command context contains `:via/ssh`
- **THEN** the rule's context clause matches

#### Scenario: Absent fact skips a rule
- **WHEN** a rule includes `(context (has :via/ssh))` and the evaluated command context does not contain `:via/ssh`
- **THEN** the rule is skipped as though its context clause did not match

#### Scenario: Scalar fact matches by exact value
- **WHEN** a rule includes `(context (= :claude-code/permission-mode "acceptEdits"))` and the evaluated context contains that exact scalar fact value
- **THEN** the rule's context clause matches

#### Scenario: Scalar fact matches by regex
- **WHEN** a rule includes `(context (matches :ssh/host "^prod-"))` and the evaluated context contains `:ssh/host = "prod-1"`
- **THEN** the rule's context clause matches

### Requirement: Context aliases can be defined and composed
The configuration DSL SHALL allow top-level `(defcontext NAME EXPR)` forms that define reusable context expressions. A defined alias SHALL be usable anywhere another context expression can appear, including inside boolean compositions. Unknown aliases and cyclic alias definitions MUST cause configuration errors.

#### Scenario: Alias used directly in a rule
- **WHEN** the config defines `(defcontext remote-prod (and (has :via/ssh) (matches :ssh/host "^prod-")))` and a rule includes `(context remote-prod)`
- **THEN** the rule evaluates the aliased context expression

#### Scenario: Alias composes inside a boolean expression
- **WHEN** the config defines `my-ctx-a` and `my-ctx-b` and a rule includes `(context (or my-ctx-a my-ctx-b))`
- **THEN** the rule matches when either aliased context expression matches

#### Scenario: Cyclic aliases are rejected
- **WHEN** context aliases reference each other recursively
- **THEN** configuration loading fails with an error describing the cycle

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

### Requirement: Wrappers derive context facts during unwrapping
Wrapper evaluation SHALL derive context facts before evaluating the inner command. A matched wrapper MUST add an inferred `:via/<wrapper-command>` presence fact by default. Wrapper patterns SHALL support direct scalar fact extraction using bracket binding syntax `[:key pattern]`, which matches a single scalar argument and stores its statically known value in the named fact key.

#### Scenario: Matched wrapper adds inferred via fact
- **WHEN** a wrapper named `ssh` matches an outer command
- **THEN** the inner command context contains `:via/ssh`

#### Scenario: Wrapper extracts a scalar fact from a matched argument
- **WHEN** a wrapper pattern includes `(positional [:ssh/host *] :command+args)` and the command is `ssh prod-1 journalctl -u nginx`
- **THEN** the inner command context contains `:ssh/host = "prod-1"`

#### Scenario: Nested wrappers accumulate facts
- **WHEN** nested wrappers such as `sudo ssh prod-1 ls` are matched during unwrapping
- **THEN** the final inner command context contains facts from each matched wrapper, including `:via/sudo`, `:via/ssh`, and `:ssh/host = "prod-1"`

### Requirement: Context facts remain conservative when values are missing or dynamic
The evaluator MUST treat missing context facts as absent rather than synthesizing defaults. Wrapper-derived scalar facts MUST only be attached when the matched value is statically known as a single scalar. If a wrapper match is known but the extracted value is dynamic or opaque, the evaluator MUST keep the inferred `:via/...` fact and omit the derived scalar fact.

#### Scenario: Dynamic wrapper value omits scalar fact
- **WHEN** an `ssh` wrapper matches but the host value cannot be statically resolved
- **THEN** the evaluated context includes `:via/ssh` and does not include `:ssh/host`

#### Scenario: Missing runtime metadata does not fabricate facts
- **WHEN** a runtime integration does not provide a field such as `permission_mode`
- **THEN** the evaluated context does not include a corresponding namespaced fact for that field

#### Scenario: Context-sensitive rule falls back conservatively
- **WHEN** a rule depends on `(= :ssh/host "prod-1")` and the command context lacks `:ssh/host`
- **THEN** that rule does not match and evaluation continues using the remaining rules
