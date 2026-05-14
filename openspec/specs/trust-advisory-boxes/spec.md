---
audience: user
bucket: trust
trust-relevant: true
---
# Trust-Advisory-Boxes Specification

## Purpose

How `may-i` renders trust state into terminal traces: the advisory warning box surfaced around loaded but untrusted rules in user-facing subcommands (`eval`, `check`, `trust`, `migrate`, `parse`), the error advisory box rendered on trust-store integrity failure, and the runtime fall-through behaviour when untrusted rules are detected in non-JSON TTY mode (evaluation proceeds with the warning; untrusted rules default to `:ask`). Output surfaces excluded are hook mode, JSON, and help/reference.

See related specs: `trust-gate` for the runtime decision the advisories reflect; `trust-store` for the stored approvals these advisories refer the user to; `code-quality` for the module-ownership invariants on the advisory builders.

## Requirements

### Requirement: Untrusted rules render as advisory warning box

When user-facing subcommands (`eval`, `check`, `trust`, `migrate`, `parse`) detect untrusted rules in non-JSON TTY mode, they SHALL render a warning advisory box to stderr. Hook mode and help/reference are excluded.

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

### Requirement: Trust store integrity failures render as advisory error box

When the trust store has integrity issues, user-facing subcommands SHALL render an error advisory box to stderr. The box includes the trust store file path.

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

When `may-i eval` detects untrusted rules in non-JSON TTY mode, it SHALL render the advisory warning box to stderr and then proceed with evaluation, treating untrusted rules as defaulting to `:ask`. Previously, eval returned early without evaluating. JSON mode and hook mode still block with an `:ask` response.

#### Scenario: Eval shows trace alongside trust warning (single file)

- **WHEN** `may-i eval "echo hi"` is run in TTY mode and `echo` has untrusted rules from `~/rules/basics.lisp`
- **THEN** the warning box is rendered to stderr naming the source file with suggestion `$ may-i trust "echo"`
- **AND** the evaluation proceeds, producing trace and result output
- **AND** the result reflects `:ask` for the untrusted rules

#### Scenario: Eval names multiple source files

- **WHEN** `git` has untrusted rules from both `~/rules/vcs.lisp` and `~/rules/extras.lisp`
- **THEN** the warning box body names both file paths

#### Scenario: Eval JSON mode still blocks

- **WHEN** `may-i eval --json "git push"` is run and `git` has untrusted rules
- **THEN** the JSON response returns `"decision": "ask"` with the trust reason and a `"files"` array of source paths

#### Scenario: Hook mode still blocks

- **WHEN** the Claude Code hook receives a command for an untrusted program
- **THEN** the hook returns the JSON `:ask` block response (unchanged behavior)

### Requirement: Check subcommand gains trust awareness

`may-i check` SHALL detect untrusted rules and render the advisory warning box. Checks still run so the user sees results, but the warning provides context that results may reflect unapproved rules.

#### Scenario: Check with untrusted rules shows warning then results

- **WHEN** `may-i check` is run and untrusted rules exist
- **THEN** the warning box is rendered to stderr before check results
- **AND** all checks execute and results are displayed normally

#### Scenario: Check JSON mode unaffected

- **WHEN** `may-i check --json` is run and untrusted rules exist
- **THEN** JSON output is unchanged (no advisory box)

### Requirement: Hook block response includes source files

When the Claude Code hook blocks due to untrusted rules, the reason string SHALL include source file paths.

#### Scenario: Hook block reason mentions file

- **WHEN** the hook blocks `echo` with rules from `~/rules/basics.lisp`
- **THEN** the hook response's `permissionDecisionReason` includes the file path

#### Scenario: Hook response shape unchanged

- **WHEN** the hook blocks due to untrusted rules
- **THEN** the hook response shape is unchanged; file information is embedded in the reason string
