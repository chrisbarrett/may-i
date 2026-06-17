## ADDED Requirements

### Requirement: Calls to script-local functions are internal

The evaluator SHALL treat a call to a function the same command defines, **when
that function is live at the call site**, as an internal call that resolves to
`:allow` and is never reported as `No rule for command …`. A command may define
shell functions (`name() { … }` or `function name { … }`). The bodies of defined
functions SHALL continue to be authorised as ordinary commands, so a dangerous
operation inside a body still produces its own decision.

Recognition SHALL be **liveness-aware**, never classifying a call internal
unless the named function is provably live there (a false-internal would allow
an ungated external program to run). Specifically:

- A call in the **top-level command sequence** SHALL be internal only if a
  definition of that name precedes it in execution order and no intervening
  `unset -f` removed it.
- A call **inside a function body** SHALL be internal only if the function is
  defined unconditionally at top level before the first top-level invocation of
  any defined function (the activation point) and is never unset. This preserves
  mutual recursion and helper-defined-below.

When liveness cannot be proven — a definition reachable only through a
conditional, a dynamic `unset -f`, or a call that may precede its definition —
the evaluator SHALL treat the call as an ordinary (external) command rather than
internal.

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

#### Scenario: A top-level call before its definition is external

- **WHEN** the input is `rm -rf /tmp/x; rm() { true; }`
- **AND** no rule matches `rm`
- **THEN** the call to `rm` SHALL be treated as an external command (the
  definition follows it in execution order, so `rm` is not yet live)
- **AND** the reason SHALL be `No rule for command `rm``

#### Scenario: A call after `unset -f` is external

- **WHEN** the input is `rm() { true; }; unset -f rm; rm -rf /tmp/x`
- **AND** `true` and `unset` are allowed, and no rule matches `rm`
- **THEN** the call to `rm` SHALL be treated as an external command (the
  `unset -f` removed the function before the call)
- **AND** the reason SHALL be `No rule for command `rm``

#### Scenario: A body forward-reference invoked before its definition is external

- **WHEN** the input is `g() { f; }; g; f() { true; }`
- **AND** `true` is allowed, and no rule matches `f`
- **THEN** the call to `f` inside `g`'s body SHALL be treated as an external
  command (the first invocation of `g` runs before `f` is defined, so `f` is not
  established at the activation point)
- **AND** the reason SHALL be `No rule for command `f```
