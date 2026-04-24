## ADDED Requirements

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
