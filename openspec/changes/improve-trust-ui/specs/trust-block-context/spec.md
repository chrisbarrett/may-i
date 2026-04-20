## ADDED Requirements

### Requirement: Eval block message includes source files
When eval blocks due to untrusted rules, the message SHALL name the source file(s) contributing untrusted rules for that program.

#### Scenario: Single source file
- **WHEN** `echo` is blocked and its rules come from `~/rules/basics.lisp`
- **THEN** the block message includes the file path, e.g.: `Untrusted rules for 'echo' (from ~/rules/basics.lisp). Run: may-i trust "echo"`

#### Scenario: Multiple source files
- **WHEN** `git` is blocked and its rules come from both `~/rules/vcs.lisp` and `~/rules/extras.lisp`
- **THEN** the block message lists both file paths

#### Scenario: JSON mode includes files
- **WHEN** eval runs with `--json` and blocks due to untrusted rules
- **THEN** the JSON response includes a `"files"` array with the source file paths

### Requirement: Hook block response includes source files
When the Claude Code hook blocks due to untrusted rules, the reason string SHALL include source file paths.

#### Scenario: Hook block reason mentions file
- **WHEN** the hook blocks `echo` with rules from `~/rules/basics.lisp`
- **THEN** `permissionDecisionReason` includes the file path

#### Scenario: Hook response structure unchanged
- **WHEN** the hook blocks due to untrusted rules
- **THEN** the response shape (`hookSpecificOutput.permissionDecision`, `hookSpecificOutput.permissionDecisionReason`) is unchanged; file info is embedded in the reason string
