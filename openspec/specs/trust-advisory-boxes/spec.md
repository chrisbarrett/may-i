---
audience: user
bucket: trust
trust-relevant: true
---
# Trust-Advisory-Boxes Specification

## Purpose

How `may-i` renders trust state into terminal traces: the Advisory warning
box surfaced around loaded but untrusted rules in user-facing subcommands,
and the block-context output rendered when the trust gate blocks `eval` in
non-JSON TTY mode (untrusted rules default to `:ask`). Output surfaces
excluded are hook mode, JSON, and help/reference.

See related trust specs: `trust-gate` for the gate decision the
block-context renders, `trust-store` for the stored approvals these
advisories refer the user to.

## Requirements
### Requirement: Untrusted rules render as Advisory warning box

When user-facing subcommands (eval, check, trust, migrate, parse) detect untrusted rules in non-JSON TTY mode, they SHALL render a `Layout::Note` warning box (NoteLevel::Warn) to stderr. Hook mode and help/reference are excluded.

#### Scenario: Single untrusted program names the program

- **WHEN** exactly one program (`git`) has untrusted rules from `~/rules/vcs.lisp`
- **THEN** the warning box heading is "Untrusted rules: git"
- **AND** the body names the source file and directs the user to `$ may-i trust "git"`

#### Scenario: Multiple untrusted programs lists names with cap

- **WHEN** 7 programs have untrusted rules
- **THEN** the warning box heading is "Untrusted rules"
- **AND** the body states the count, lists the first 5 program names comma-separated, and shows "(and 2 more)"
- **AND** the suggestion directs the user to `$ may-i trust` (no args)

#### Scenario: Five or fewer untrusted programs lists all names

- **WHEN** 3 programs (`git`, `cargo`, `npm`) have untrusted rules
- **THEN** all 3 names appear in the body, no "(and N more)" suffix
- **AND** the suggestion directs the user to `$ may-i trust` (no args)

#### Scenario: JSON mode does not render the box

- **WHEN** `--json` is set and untrusted rules exist
- **THEN** no advisory box is rendered (JSON output is unchanged)

#### Scenario: Non-TTY mode does not render the box

- **WHEN** stdout/stderr is not a TTY (piped) and untrusted rules exist
- **THEN** no advisory box is rendered

### Requirement: Trust store integrity failures render as Advisory error box

When the trust store has integrity issues, user-facing subcommands SHALL render a `Layout::Note` error box (NoteLevel::Error) to stderr. The box includes the trust store file path.

#### Scenario: Specific entries have mismatched hashes

- **WHEN** 3 entries in `~/.local/share/may-i/trust.json` fail integrity verification
- **THEN** the error box heading is "Trust store integrity failure"
- **AND** the body names the store path, states the count, lists affected entry names (take 5, comma-separated)
- **AND** the suggestion directs the user to `$ may-i trust`

#### Scenario: More than 5 tampered entries truncates with count

- **WHEN** 12 entries fail integrity verification
- **THEN** the body lists the first 5 names and shows "(and 7 more)"

#### Scenario: Whole file corrupt or unloadable

- **WHEN** the trust store file cannot be parsed (corrupt JSON, unrecognized format)
- **THEN** the error box heading is "Trust store corrupted"
- **AND** the body names the store path and states the file could not be loaded
- **AND** the body notes all programs will require re-approval
- **AND** no suggestion command is shown (re-approval happens automatically)

### Requirement: Eval proceeds with warning instead of blocking

When `cmd_eval` detects untrusted rules in non-JSON mode, it SHALL show the advisory warning box and then proceed with evaluation, treating untrusted rules as defaulting to `:ask`. Previously, eval returned early without evaluating.

#### Scenario: Eval shows trace alongside trust warning

- **WHEN** `may-i eval "git push"` is run and `git` has untrusted rules
- **THEN** the warning box is rendered to stderr
- **AND** the evaluation proceeds, producing trace and result output
- **AND** the result reflects `:ask` for the untrusted rules

#### Scenario: Eval JSON mode still blocks

- **WHEN** `may-i eval --json "git push"` is run and `git` has untrusted rules
- **THEN** the JSON response returns `"decision": "ask"` with the trust reason (unchanged behavior)

#### Scenario: Hook mode still blocks

- **WHEN** the hook receives a command for an untrusted program
- **THEN** the hook returns the JSON `:ask` block response (unchanged behavior)

### Requirement: Check subcommand gains trust awareness

`cmd_check` SHALL detect untrusted rules and render the advisory warning box. Checks still run so the user sees results, but the warning provides context that results may reflect unapproved rules.

#### Scenario: Check with untrusted rules shows warning then results

- **WHEN** `may-i check` is run and untrusted rules exist
- **THEN** the warning box is rendered to stderr before check results
- **AND** all checks execute and results are displayed normally

#### Scenario: Check JSON mode unaffected

- **WHEN** `may-i check --json` is run and untrusted rules exist
- **THEN** JSON output is unchanged (no advisory box)

### Requirement: Trust advisory builders are pure functions
The Trust advisory builders SHALL be pure functions returning `Option<Layout>` (warning box) or `Layout` (integrity box), performing no IO. They SHALL live in `src/trust_advisory.rs` (the module owning the data) rather than in `src/output/mod.rs`. Their input shapes SHALL NOT leak across module boundaries: callers pass the trust config or the trust-store result, not flattened internal data structures.

#### Scenario: Warning builder returns None when no untrusted rules
- **WHEN** `trust_advisory::build_warning_layout(&config)` is called and no
  loaded rules are untrusted
- **THEN** the function returns `None`
- **AND** no IO occurs

#### Scenario: Warning builder returns a Layout when untrusted rules exist
- **WHEN** the same call is made against a config with untrusted loaded
  rules
- **THEN** the function returns `Some(Layout)` whose rendered output
  matches the existing requirement scenarios in this spec (heading,
  body, suggestion)
- **AND** the function performs no IO

#### Scenario: Integrity builder returns a Layout
- **WHEN** `trust_advisory::build_integrity_layout(store_path, suspects)`
  is called
- **THEN** the function returns a `Layout` matching the existing integrity
  requirement scenarios
- **AND** the function performs no IO

#### Scenario: Output module no longer exports advisory builders
- **WHEN** the `src/output/mod.rs` public API is inspected
- **THEN** `migration_note`, `trust_warning_note`, and
  `trust_integrity_note` are no longer exported from `output`
- **AND** the trace-rendering functions (`print_trace`, `write_trace`,
  `trace_to_json`, `colorize_decision_keyword`) remain
- **AND** layout primitive re-exports (`Layout`, `Advisory`, `Note`,
  `Terminal`, `ColRow`, `ColAlign`, `write_layout`, `strip_ansi`,
  `HRuleLabel`, `NoteLevel`) remain

### Requirement: Migration note builder lives outside output
The migration advisory note builder SHALL live in the module that owns its data (the migration command or a sibling notes module), not in `src/output/mod.rs`. Its signature SHALL remain `(loaded, config_path) -> Option<Layout>` and its rendered text SHALL be byte-equal to today's output.

#### Scenario: Builder lives in cmd_migrate or a notes module
- **WHEN** `migration_note` is imported by `cmd_eval` or `cmd_check`
- **THEN** the import path is the migration / notes module, not `output`

#### Scenario: Rendered output is unchanged
- **WHEN** a config with pre-migration forms is loaded and the migration
  note is rendered to stderr
- **THEN** the produced text is byte-equal to today's output for the same
  config

### Requirement: Eval TTY mode shows advisory box instead of blocking
When eval detects untrusted rules in non-JSON TTY mode, it SHALL render an advisory warning box and proceed with evaluation (untrusted rules default to `:ask`). It no longer returns early.

#### Scenario: Single source file
- **WHEN** `echo` has untrusted rules from `~/rules/basics.lisp` and eval is run in TTY mode
- **THEN** a warning box is rendered naming the source file, with suggestion `$ may-i trust "echo"`
- **AND** evaluation proceeds with trace and result output

#### Scenario: Multiple source files
- **WHEN** `git` has untrusted rules from both `~/rules/vcs.lisp` and `~/rules/extras.lisp`
- **THEN** the warning box body names both file paths

#### Scenario: JSON mode blocks with files in response
- **WHEN** eval runs with `--json` and blocks due to untrusted rules
- **THEN** the JSON response includes `"decision": "ask"`, reason string with file paths, and a `"files"` array

### Requirement: Hook block response includes source files
When the Claude Code hook blocks due to untrusted rules, the reason string SHALL include source file paths.

#### Scenario: Hook block reason mentions file
- **WHEN** the hook blocks `echo` with rules from `~/rules/basics.lisp`
- **THEN** `permissionDecisionReason` includes the file path

#### Scenario: Hook response structure unchanged
- **WHEN** the hook blocks due to untrusted rules
- **THEN** the response shape (`hookSpecificOutput.permissionDecision`, `hookSpecificOutput.permissionDecisionReason`) is unchanged; file info is embedded in the reason string
