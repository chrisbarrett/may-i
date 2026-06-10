## ADDED Requirements

### Requirement: Calls to script-local functions are internal

The evaluator SHALL treat a call to a function the same command defines as an
internal call that resolves to `:allow` and is never reported as `No rule for
command …`. A command may define shell functions (`name() { … }` or `function
name { … }`); the evaluator SHALL collect the set of function names defined
anywhere in the parsed command and classify a simple command whose first word is
one of those names as an internal call. The bodies of defined functions SHALL continue to be
authorised as ordinary commands, so a dangerous operation inside a body still
produces its own decision.

Recognition SHALL be set-based across the whole command: a name defined as a
function anywhere in the command makes every call to it internal, regardless of
whether the definition precedes or follows the call. The evaluator SHALL NOT
attempt control-flow analysis of definition order.

#### Scenario: Call to a defined function does not ask

- **WHEN** the input is `materialise() { echo hi; }; materialise foo`
- **AND** no rule matches `materialise`
- **THEN** the decision SHALL be `:allow`
- **AND** the reason SHALL NOT be `No rule for command `materialise``

#### Scenario: Function body is still authorised

- **WHEN** the input is `cleanup() { rm -rf "$wt"; }; cleanup`
- **AND** a rule asks about recursive `rm`
- **THEN** the decision SHALL be at least `:ask` from the body's `rm`
- **AND** the `cleanup` call itself SHALL NOT add a `No rule for command …` reason

#### Scenario: Forward reference between functions is internal

- **WHEN** the input defines `outer() { inner; }` before `inner() { echo hi; }`
  and then calls `outer`
- **THEN** the call to `inner` inside `outer`'s body SHALL be treated as an
  internal call, not an unknown command

#### Scenario: A non-defined unknown command still asks

- **WHEN** the input is `materialise() { echo hi; }; kubectl get pods`
- **AND** no rule matches `kubectl`
- **THEN** the decision SHALL be `:ask`
- **AND** the reason SHALL be `No rule for command `kubectl``
