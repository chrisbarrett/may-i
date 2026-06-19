## ADDED Requirements

### Requirement: Script-local function recognition crosses substitution boundaries

The evaluator SHALL recognise a call to a script-local function appearing inside
a command substitution (`$(…)`, backticks, or process substitution) as an
internal call under the same conditions it recognises a bare call — using the
functions **live at the substitution's site**. The governing invariant is:

> A function call inside a substitution SHALL receive the same
> internal/external classification it would receive as a bare call at the
> substitution's site.

Recognition SHALL remain **liveness-aware and position-aware**: the inherited
set is the functions provably live at the substitution's location (the Tier-1
top-level establishment for a substitution on the spine, the Tier-2 activation
set for one inside a function body or conditionally-reached region), never the
whole-command set of defined names. A function not yet established at the
substitution's site SHALL NOT be recognised.

Recognition SHALL propagate through **nested substitutions**: a substitution
nested inside another inherits its parent substitution's live set unioned with
any function established within the parent's own source.

This requirement preserves soundness: the inherited set never contains a name
not provably live at the site, so the rule can only remove a spurious ask, never
suppress a gate. Function bodies continue to be authorised at their definition
site, so a dangerous operation inside a recognised function still produces its
own decision.

#### Scenario: Call to a live local function inside `$(…)` does not ask

- **WHEN** the input is `resolve() { echo hi; }; dest=$(resolve)`
- **AND** no rule matches `resolve`
- **THEN** the decision SHALL be `:allow`
- **AND** the reason SHALL NOT be `No rule for command `resolve``

#### Scenario: Forward-referenced function inside `$(…)` still asks

- **WHEN** the input is `dest=$(resolve); resolve() { echo hi; }`
- **AND** no rule matches `resolve`
- **THEN** the decision SHALL be `:ask`
- **AND** the reason SHALL be `No rule for command `resolve`` (the substitution
  runs before `resolve` is defined, so it is not live at the site)

#### Scenario: Non-defined unknown command inside `$(…)` still asks

- **WHEN** the input is `resolve() { echo hi; }; dest=$(kubectl get pods)`
- **AND** no rule matches `kubectl`
- **THEN** the decision SHALL be `:ask`
- **AND** the reason SHALL be `No rule for command `kubectl``

#### Scenario: Recognition reaches a substitution inside a function body

- **WHEN** the input is `resolve() { echo hi; }; main() { dest=$(resolve); }; main`
- **AND** no rule matches `resolve`
- **THEN** the call to `resolve` inside the substitution SHALL be treated as an
  internal call, not an unknown command (`resolve` is established before `main`
  is first invoked)

#### Scenario: Recognition propagates through nested substitutions

- **WHEN** the input is `g() { echo x; }; f() { echo y; }; out=$(f $(g))`
- **AND** no rule matches `f` or `g`
- **THEN** both `f` and `g` SHALL be treated as internal calls, not unknown
  commands

#### Scenario: A dangerous body of a substitution-recognised function still asks

- **WHEN** the input is `wipe() { rm -rf "$d"; }; x=$(wipe)`
- **AND** a rule asks about recursive `rm`
- **THEN** the decision SHALL be at least `:ask` from the body's `rm`
- **AND** the `wipe` call inside the substitution SHALL NOT add a `No rule for
  command …` reason
