## ADDED Requirements

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
