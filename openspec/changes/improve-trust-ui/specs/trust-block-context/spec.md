## ADDED Requirements

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
