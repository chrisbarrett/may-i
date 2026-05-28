## MODIFIED Requirements

### Requirement: Trust listing groups by file when all trusted

When all loaded programs are trusted, `may-i trust` SHALL display a sectioned layout: one section per source file, with the file path as a dimmed heading and the program names wrapped underneath at the available terminal width.

The layout SHALL NOT use a two-column divider; horizontal overflow on long file paths or long program lists is unacceptable.

#### Scenario: All programs trusted from two files

- **WHEN** `echo` and `cat` come from `~/rules/basics.lisp`, `git` comes from `~/rules/vcs.lisp`, and all are trusted
- **THEN** output shows:
  ```
    ~/rules/basics.lisp
      echo, cat

    ~/rules/vcs.lisp
      git

    All trusted.
  ```

#### Scenario: Single file with many programs

- **WHEN** one file contributes enough program names that their comma-joined form exceeds the terminal width
- **THEN** the program names wrap across multiple lines beneath the file heading without producing horizontal overflow

#### Scenario: Long file path does not break layout

- **WHEN** a source file's `~`-shortened path is longer than half the terminal width
- **THEN** the path renders in full on its own heading line and the program section below remains aligned
