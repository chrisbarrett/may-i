## Why

The shell parser does not model bash arrays, and one half is actively lossy:

- `arr=(a b c); echo …` emits an Error diagnostic at `(` and **discards the rest
  of the command** — it parses to just `Assignment { name: "arr", value: "" }`.
  The trailing `; echo …` is dropped from evaluation, in tension with the
  existing requirement *"The parser never silently discards tokens"*.
- `${arr[@]}` / `${arr[0]}` parse as a parameter literally **named** `arr[@]` /
  `arr[0]` — the subscript is swallowed into the name string, so it can never be
  recognised as an array reference.

Arrays of literals are a common ops idiom (`regions=(us-east-1 eu-west-1)`,
`for r in "${regions[@]}"`). Today every such command floors — via a parse error
for the literal, via an unresolvable parameter for the expansion — and the
literal case silently truncates whatever follows. This change makes the parser
**model** arrays faithfully; it does not yet resolve them (that is the follow-up
`resolve-constant-array-arguments`).

## What Changes

- Parse an array-literal assignment `name=(word…)` (and `declare`/`local`/`export`
  `-a` forms) into a representation that preserves each element word, emits **no**
  error, and **continues parsing** the rest of the command.
- Represent a subscripted parameter expansion `${name[subscript]}`,
  `${name[@]}`, `${name[*]}`, `${#name[@]}` with the array name and subscript
  distinguished — not concatenated into the parameter name.
- Track each array's **kind** — indexed (`declare -a`, `name=(…)`) vs associative
  (`declare -A`) — in the AST. Associative element order is unspecified in bash,
  so a later resolver must be able to tell the two apart to stay sound; capturing
  the kind here unblocks that without modelling associative values yet.
- No resolution or value analysis yet: a subscripted expansion remains an
  unresolved expansion and floors an `:allow` exactly as an unknown scalar does.
  The behavioural win is fidelity — the trailing command is evaluated, and the
  expansion is now a recognisable array reference for the follow-up change.

## Capabilities

Bucket: `parsing` (argv tokenisation and the shell AST the evaluator sees).

### New Capabilities

<!-- none -->

### Modified Capabilities

- `shell-command-security-model`: require array-literal assignments and
  subscripted parameter expansions to be parsed into a faithful representation
  (including the array's indexed-vs-associative kind) without emitting an error or
  discarding following commands, so no portion of a command containing an array is
  dropped from evaluation.

## Impact

- `crates/shell-parser` — lexer/parser: recognise `(` after `name=` as an
  array-literal assignment and lex its element words; recognise `[subscript]`
  inside `${…}` as a subscript rather than part of the name. New/extended AST:
  the assignment value gains an array form, and `WordPart` gains a subscripted
  parameter reference. The `name=()` parse-error-and-truncate path is removed.
- `crates/engine` — the evaluator must accept the new AST nodes; a subscripted
  expansion is treated as expansion-bearing (unresolved) so decisions are
  unchanged except that the previously-discarded trailing command is now
  evaluated.
- Tests: `crates/shell-parser` — array literal parses with no diagnostic and the
  following command survives; subscript forms parse with name and subscript
  separated; `arr+=(x)`, `arr[i]=x`, sparse/associative forms parse without
  truncation (modelled or explicitly diagnosed, never silently dropped).
- No DSL, config, or trust-hash surface change; no migration. **Prerequisite for**
  `resolve-constant-array-arguments`. Independent of the scalar and loop changes.
