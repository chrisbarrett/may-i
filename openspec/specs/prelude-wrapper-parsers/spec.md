# prelude-wrapper-parsers Specification

## Purpose

TBD — established by the dsl-coherence change. This capability defines the set of parsers shipped in the prelude for common wrapper tools (sudo, xargs, env, find, etc.) and their parser-side declarations.

## Requirements

### Requirement: Prelude ships parsers for common wrapper tools

The prelude SHALL define parsers for the following wrapper tools before any user config is loaded. Each declaration SHALL include a `(style …)`, the relevant `(flag …)` and `(parameter …)` declarations, and a `(tail …)` declaration for the wrapper boundary.

The prelude SHALL declare:

- `sudo`     — `(style gnu) (tail (after :flags))`
- `xargs`    — `(style gnu) (parameter ["n" "I" "L" "P" "d"]) (flag ["0" "r"]) (tail (after :flags))`
- `env`      — `(style gnu) (tail (after :flags))`
- `timeout`  — `(style gnu) (tail (after :flags))`
- `nice`     — `(style gnu) (parameter ["n"]) (tail (after :flags))`
- `time`     — `(style gnu) (tail (after :flags))`
- `watch`    — `(style gnu) (parameter ["n" "interval"]) (tail (after :flags))`
- `su`       — `(style gnu) (tail (after :flags))`
- `ionice`   — `(style gnu) (tail (after :flags))`
- `chrt`     — `(style gnu) (tail (after :flags))`
- `mise`     — `(style gnu) (tail (after "--"))`

User parsers MAY shadow or use `(overrides …)` for any prelude parser.

#### Scenario: Prelude sudo parser closes silent bypass

- **GIVEN** prelude parsers loaded and user config `(rule "sudo" (tail (authorise)))` and `(rule "rm" (and (flag "r") (deny "no rm -r")))`
- **WHEN** evaluating `sudo rm -rf /tmp/x`
- **THEN** the inner evaluation SHALL see argv `[-rf, /tmp/x]` for `rm`
- **AND** the rule SHALL return `:deny`.

#### Scenario: Prelude xargs parser handles flagged invocation

- **GIVEN** prelude parsers and `(rule "xargs" (tail (authorise)))` and `(rule "rm" (allow))`
- **WHEN** evaluating `xargs -n 1 rm -rf`
- **THEN** the outer slice SHALL be `[xargs, -n, 1]` and the tail SHALL be `[rm, -rf]`
- **AND** the inner evaluation SHALL recurse with command `rm` and argv `[-rf]`.

#### Scenario: Prelude mise parser uses `--` boundary

- **GIVEN** prelude parsers and `(rule "mise" (and (positional "exec") (tail (authorise))))` and `(rule "rm" (deny "no rm"))`
- **WHEN** evaluating `mise exec -- rm /tmp/x`
- **THEN** the outer slice SHALL be `[mise, exec]` and the tail SHALL be `[rm, /tmp/x]`
- **AND** the rule SHALL return `:deny`.

#### Scenario: User parser shadows prelude

- **GIVEN** prelude `sudo` parser and user `(parser "sudo" (style gnu) (flag "E"))` (no tail)
- **WHEN** the config is loaded
- **THEN** the user parser SHALL win
- **AND** the resolved parser for `sudo` SHALL NOT split argv (no tail declared).

### Requirement: Prelude ships `find` parser with `(many-till …)` for action clauses

The prelude SHALL declare a parser for `find`:

```
(parser "find"
  (style single-dash-long)
  (parameter "exec"    (many-till (or ";" "+")))
  (parameter "execdir" (many-till (or ";" "+")))
  (parameter "ok"      (many-till (or ";" "+")))
  (parameter ["name" "iname" "type" "mtime" "size" "regex" "path"]))
```

#### Scenario: Prelude find parser captures `-exec`

- **GIVEN** prelude parsers and `(rule "find" (parameter "exec" (authorise)))` and `(rule "rm" (and (flag "r") (deny "no rm -r")))`
- **WHEN** evaluating `find . -exec rm -rf / \;`
- **THEN** the captured value for parameter `exec` SHALL be `[rm, -rf, /]`
- **AND** the rule SHALL return `:deny` after recursion into `rm`.

#### Scenario: Prelude find parser recognises `+` terminator

- **GIVEN** the configuration above
- **WHEN** evaluating `find . -name '*.bak' -exec rm {} +`
- **THEN** the captured value for parameter `exec` SHALL be `[rm, {}]`
- **AND** the recursion SHALL run with command `rm` and argv `[{}]`.
