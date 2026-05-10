## ADDED Requirements

### Requirement: Top-level rule combination is most-strict-wins

When a command is evaluated against a config, the engine SHALL combine
the effects of **all** matching rules under the `Decision` lattice
(`Allow < Ask < Deny`). The resulting decision SHALL be the maximum
under this ordering. The combine SHALL be order-independent: shuffling
the rule list within or across source files MUST NOT change the
resulting `Decision`.

#### Scenario: Allow and Deny on same command — Deny wins
- **GIVEN** rules `(rule "rm" (effect :allow))` and
  `(rule "rm" (effect :deny "danger"))` in any order
- **WHEN** evaluating the command `rm file`
- **THEN** the result SHALL be `Decision::Deny`

#### Scenario: Allow and Ask on same command — Ask wins
- **GIVEN** rules `(rule "git" (effect :allow))` and
  `(rule "git" (positional "push") (effect :ask))` in any order
- **WHEN** evaluating the command `git push`
- **THEN** the result SHALL be `Decision::Ask`

#### Scenario: Ask and Deny on same command — Deny wins
- **GIVEN** rules `(rule "rm" (effect :ask))` and
  `(rule "rm" (positional "-rf") (effect :deny "danger"))` in any
  order
- **WHEN** evaluating the command `rm -rf /tmp`
- **THEN** the result SHALL be `Decision::Deny`

#### Scenario: Multiple rules at same effect collapse
- **GIVEN** three rules all matching `echo` and all yielding
  `Decision::Allow`
- **WHEN** evaluating `echo hi`
- **THEN** the result SHALL be `Decision::Allow`

#### Scenario: No rule matches — Ask
- **GIVEN** a config with no rule whose predicate matches the command
- **WHEN** evaluating that command
- **THEN** the result SHALL be `Decision::Ask`

### Requirement: Tie-breaking on `reason` is earliest source order

The engine SHALL break ties on the `reason` string by selecting the earliest rule in source order when multiple matching rules share the most-strict effect. Source order is defined as: rules from the primary config in file order, then rules from each loaded file in load order, then within each loaded file in file order.

#### Scenario: Two Deny rules with different reasons — earliest wins
- **GIVEN** primary config `(rule "rm" (effect :deny "primary"))`
  and loaded file `(rule "rm" (effect :deny "loaded"))`
- **WHEN** evaluating `rm file`
- **THEN** the result decision SHALL be `Decision::Deny`
- **AND** the result reason SHALL be `"primary"`

#### Scenario: Loaded rule strictest, no primary match
- **GIVEN** primary config `(rule "git" (effect :allow))`
  and loaded file `(rule "git" (positional "push") (effect :deny "no push"))`
- **WHEN** evaluating `git push`
- **THEN** the result SHALL be `Decision::Deny` with reason
  `"no push"` (the only rule contributing the strictest effect)

### Requirement: Trace surfaces all tied entries

The engine SHALL include every rule that contributed the most-strict effect in the trace output for an evaluation. The rule whose `reason` survived the earliest-in-source-order tie-breaker SHALL be marked as the reason source; the remaining tied rules SHALL be presented as also-matched siblings at the same effect.

#### Scenario: Two rules tied at Deny — both appear in trace
- **GIVEN** two rules both matching `rm` and both yielding
  `Decision::Deny`, the first with reason `"primary"` and the second
  with reason `"loaded"`
- **WHEN** the command `rm file` is evaluated with trace output
  enabled
- **THEN** the trace SHALL list both rules as evaluated entries
- **AND** the rule with reason `"primary"` SHALL be marked as the
  reason source
- **AND** the rule with reason `"loaded"` SHALL appear as a tied
  sibling at the same effect

#### Scenario: Single most-strict rule — no sibling annotation
- **GIVEN** a single matching rule yielding `Decision::Deny` and
  other matching rules yielding `Decision::Allow`
- **WHEN** trace output is rendered
- **THEN** the `Deny` rule SHALL appear as the reason source with no
  tied-sibling annotation

### Requirement: Adding a rule cannot relax the decision

The engine SHALL NOT produce a less-strict decision when a rule is added to a config in which at least one rule already matches the command. Formally, for any config `C`, command `cmd`, and additional rule `r`, if `C` contains at least one rule whose command pattern matches `cmd`, then `evaluate(C ++ [r], cmd).decision >= evaluate(C, cmd).decision` under the `Decision` lattice. This is the load-bearing security property: loaded rules — including those discovered via repo-local resolution — MUST NOT widen the policy established by an existing matching primary rule.

The no-match fallback (`Ask`) is excluded from this property: when no rule in `C` matches, appending the first matching rule replaces the fallback with that rule's decision, which may be `Allow`. Configs that wish to deny by default must encode that as an explicit catch-all rule.

#### Scenario: Adding an Allow rule to an Allow result is a no-op
- **GIVEN** a config that yields `Decision::Allow` for a command
- **WHEN** any rule yielding `Decision::Allow` is appended
- **THEN** the result SHALL still be `Decision::Allow`

#### Scenario: Adding an Allow rule to a Deny result does not widen
- **GIVEN** a config that yields `Decision::Deny` for a command
- **WHEN** a rule yielding `Decision::Allow` is appended
- **THEN** the result SHALL remain `Decision::Deny`

#### Scenario: Adding a Deny rule can tighten an Allow result
- **GIVEN** a config that yields `Decision::Allow` for a command
- **WHEN** a matching rule yielding `Decision::Deny` is appended
- **THEN** the result SHALL become `Decision::Deny`
