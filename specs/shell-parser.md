# Shell Parser

Production-grade recursive descent parser producing a typed AST for shell
commands. Used by the rule engine to decompose compound commands and extract
simple commands for evaluation.

---

## R5: Grammar coverage

Must handle:

**Commands:** simple commands, pipelines (`|`), and/or lists (`&&`/`||`),
sequential lists (`;`/`&`), subshells `()`, brace groups `{}`, if/elif/else/fi,
for/while/until, case (including `;;`/`;&`/`;;&`), function definitions,
variable assignments (`VAR=val cmd`, `export VAR=val`)

**Quoting/expansion** (recognized, not evaluated): single quotes, double quotes,
ANSI-C `$'...'`, parameter expansion (`$var`, `${var:-default}`, `${var##pat}`,
etc.), command substitution (`$(cmd)`, `` `cmd` ``), arithmetic `$((expr))`,
brace expansion `{a,b}`, globs `*?[...]`, process substitution `<(cmd)`/`>(cmd)`

**Redirections:** `<`, `>`, `>>`, `>|`, `2>&1`, heredocs (`<<`/`<<-`),
herestrings `<<<`

**Verify:** unit tests per construct; `cargo test -- parser`

## R6: Robustness on malformed input

**Given** syntactically invalid shell input **Then** return a partial AST;
evaluation falls through to default `ask`

Never panic on untrusted input.

**Verify:** `cargo-fuzz`; `proptest`

## R7: `parse` subcommand

`may-i parse` prints the Debug representation of the AST for a given shell
command. Useful for debugging rules and inspecting how the parser decomposes
input.

```
may-i parse '<command>'     # parse a string argument
may-i parse -f <file>       # parse the contents of a file
may-i parse -f -            # parse from stdin
```

**Given** a valid shell command **Then** print the full AST to stdout using
Rust's `{:#?}` formatter

**Given** malformed input **Then** print the partial AST (same graceful
degradation as R6)

**Verify:** `cargo run -- parse 'echo hello && ls'`
