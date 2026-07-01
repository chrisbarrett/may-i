## ADDED Requirements

### Requirement: Entry-environment contribution is attributed in traces

The trace SHALL render an entry-environment contribution whenever the entry
environment (see `facts`) tips a decision — a bare reassignment floored because
its name is present in the entry environment, or a `(scope …)` predicate that
consulted it — identifying the variable name and that it was present in the
entry environment.

The trace SHALL render the name and its presence only; it SHALL NOT render any
entry-environment value, consistent with the names-only invariant in `facts`.
This keeps a decision such as `PATH=/evil → :ask` explainable without exposing
environment contents.

#### Scenario: Bare reassignment trace names the entry-environment variable

- **GIVEN** an entry environment in which `PATH` is present and no
  `(env "PATH" …)` capability
- **WHEN** a trace is produced for `PATH=/evil:$PATH; ls`
- **THEN** the trace SHALL show that `PATH` being present in the entry
  environment made the write reach a child and floor the segment
- **AND** the trace SHALL NOT render any environment value

#### Scenario: A purely shell-local write needs no entry-environment annotation

- **GIVEN** an entry environment in which `MY_TMP` is absent
- **WHEN** a trace is produced for `MY_TMP=/x ls`
- **THEN** the trace SHALL NOT attribute any entry-environment contribution (the
  write is shell-local and the snapshot did not affect the decision)
