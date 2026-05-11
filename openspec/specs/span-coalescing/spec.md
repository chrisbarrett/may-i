# span-coalescing Specification

## Purpose

Contributor-only. How `may-i eval --json` emits the `spans` array: consecutive `ignore`-permission spans are coalesced into a single span (whitespace and operator text combined), while `allow`/`ask`/`deny` spans remain distinct so command boundaries are preserved.

## Requirements

### Requirement: Adjacent ignore spans SHALL be coalesced
When the eval command generates the spans array for JSON output, consecutive spans with `"ignore"` permission SHALL be merged into a single span containing the concatenated text.

#### Scenario: Multiple operators with whitespace
- **WHEN** the command `true && curl || ls` is evaluated with `--json`
- **THEN** the spans array SHALL contain coalesced ignore spans
- **AND** concatenating all span texts SHALL reproduce the original command exactly

#### Scenario: Preserved command boundaries
- **WHEN** the command `cmd1 && cmd2` is evaluated
- **THEN** spans with `allow`/`ask`/`deny` permissions SHALL remain separate
- **AND** only `ignore` permission spans SHALL be coalesced

#### Scenario: No consecutive ignore spans
- **WHEN** the command `ls` (single command) is evaluated
- **THEN** the spans array SHALL contain a single span
- **AND** no coalescing SHALL be performed

#### Scenario: Empty command
- **WHEN** an empty command is evaluated
- **THEN** the spans array SHALL be empty
- **AND** no coalescing errors SHALL occur
