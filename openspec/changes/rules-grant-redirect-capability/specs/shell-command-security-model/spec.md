> [!NOTE]
> Draft delta — sketches the intended requirement so the proposal can be
> reviewed; the exact form name and value enum are open design questions.

## ADDED Requirements

### Requirement: A rule may grant redirect carriage

A rule SHALL be able to declare that the command it matches may carry
redirections to file targets, e.g. `(rule "tee" (redirects :allow) (allow))`
(exact form name and values to be settled in design). When a matching rule
grants the capability, the redirect floor defined by "Redirect targets are
not silently ignored" SHALL NOT apply to that command's redirections. The
capability SHALL NOT widen past the rule's own decision: it removes the
floor, it does not add an allow. Rules without the capability SHALL keep the
floor. The capability SHALL participate in rule hashing for trust purposes
(it changes what a rule authorises).

#### Scenario: Capability-bearing rule passes redirects through

- **GIVEN** `(rule "tee" (redirects :allow) (allow))`
- **WHEN** evaluating `tee out.txt < in.txt`
- **THEN** the decision SHALL be `:allow` (no redirect floor)

#### Scenario: Rule without the capability keeps the floor

- **GIVEN** `(rule "echo" (allow))` and the `tee` rule above
- **WHEN** evaluating `echo x > f.txt`
- **THEN** the decision SHALL be at least `:ask` with a reason naming the
  redirect target
