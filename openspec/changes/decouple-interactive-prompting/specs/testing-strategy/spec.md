## ADDED Requirements

### Requirement: Interactive prompting flows are unit-tested through a fake prompt

Interactive prompting flows (the per-rule trust review loop, the integrity-repair loop, and any future loop following the same shape) SHALL be exercised by unit tests that drive the loop through a fake prompting impl, not solely by end-to-end TTY-driven integration tests. The fake SHALL record output and replay a scripted sequence of user answers, so loop branches (per-entry decisions, quit short-circuit, non-interactive skip) can be asserted on without a real terminal or subprocess.

#### Scenario: Per-rule review loop has a unit test over a fake prompt

- **WHEN** the test suite runs
- **THEN** at least one unit test SHALL exist that exercises the per-rule review loop against a fake prompt impl, scripting a multi-rule scenario and asserting on the resulting trust-store mutations and review summary

#### Scenario: Integrity-repair loop has a unit test over a fake prompt

- **WHEN** the test suite runs
- **THEN** at least one unit test SHALL exist that exercises the integrity-repair loop against a fake prompt impl, covering both the interactive (re-approve / drop) branches and the non-interactive (advisory-only) branch

#### Scenario: Loop logic does not depend on TTY crates

- **WHEN** the module hosting the pure review or repair loop is scanned for direct imports
- **THEN** no direct dependency on `console`, `dialoguer`, or other TTY-driver crates SHALL appear in the loop module; those crates SHALL be confined to the terminal prompting impl
