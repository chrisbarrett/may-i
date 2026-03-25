# Migration Form-Wise Diff

## Problem Statement

The current `may-i migrate` command has several usability issues:

1. **Line-based diff instead of form-based**: The `--diff` flag shows a line-by-line diff, which is hard to read for Lisp code where forms span multiple lines and comments are interspersed.

2. **False positives in warnings**: The unhandled case detection incorrectly flags comment lines as legacy wrapper forms, producing overwhelming and unhelpful output.

3. **No interactive confirmation**: Running `migrate` without flags immediately overwrites the config file without showing what will change or asking for confirmation.

4. **Poor error handling**: Parse errors cause immediate failure without showing context or allowing partial migrations.

## Proposed Solution

Implement a form-wise diff for the migration command that:

- Shows only forms that will actually change (not the entire file)
- Displays original and transformed forms side-by-side with context
- Includes 2 lines of preceding/trailing trivia (comments, whitespace)
- Detects terminal width and adapts layout (side-by-side or vertical)
- Prompts for confirmation when running interactively
- Shows error spans with context instead of failing immediately

## Success Criteria

1. `may-i migrate --diff` shows only changed forms with surrounding context
2. Side-by-side layout for terminals ≥80 columns, vertical layout below
3. Interactive prompt "Apply migration? [Y/n]" when connected to TTY
4. Non-TTY execution errors with message to use `--yes` flag
5. Parse errors show 2-line context around error span
6. All changes covered by tests

## Out of Scope

- GUI or web-based migration interface
- Automatic backups (user should use version control)
- Migration of configs with syntax errors
- Support for migrating partial files

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Terminal width detection fails on exotic terminals | Medium | Fall back to 80 columns, provide `--width` flag |
| Complex forms overflow narrow terminals | Low | Switch to vertical layout below threshold |
| User accidentally confirms destructive migration | Medium | Show clear diff before prompt, require explicit Y |

## Alternatives Considered

1. **Keep current line-based diff**: Rejected - too hard to read for Lisp code
2. **Generate unified diff (patch format)**: Rejected - doesn't handle Lisp structure well
3. **JSON output for external diff tools**: Rejected - overkill for this use case
