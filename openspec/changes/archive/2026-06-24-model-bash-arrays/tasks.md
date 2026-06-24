## 1. AST for arrays

- [x] 1.1 Add a failing parser test: `arr=(a b c); echo done` parses both the
      array assignment and `echo done`, with no Error diagnostic. Confirm red
      (today it errors and drops `echo done`).
- [x] 1.2 Introduce the array assignment value form (scalar-or-array enum on
      `Assignment`, or a sibling node) carrying array `kind`
      (`Indexed`/`Associative`), and a subscripted parameter `WordPart`
      (`name` + subscript `Index(Word)`/`All`/`Star`).
- [x] 1.4 Failing test: `declare -a idx=(a b c)` parses as indexed and
      `declare -A assoc=([k]=v)` as associative; a bare `arr=(a b c)` is indexed.
      Confirm the kind is recorded and red first.
- [x] 1.3 Update every consumer of `Assignment.value` to match the scalar arm;
      handle the new array arm where assignment values are walked.

## 2. Lexing / parsing

- [x] 2.1 Lex `name=(…)` / `name+=(…)` as an array literal: element words until
      the matching `)`, honouring quoting and nested expansions, then resume
      command parsing. Remove the error-at-`(` truncation path.
- [x] 2.2 Lex `[subscript]` after a name inside `${…}` as a distinguished
      subscript; `${arr[@]}`, `${arr[*]}`, `${arr[0]}`, `${#arr[@]}` parse with
      name and subscript separated.
- [x] 2.3 Parse `arr[i]=v` indexed element assignment and `declare -a`/`local -a`/
      `export -a` forms without truncating; `declare -A` and sparse/`+=`/`unset
      'arr[i]'` parse (modelled or coarsely diagnosed) without silently dropping
      tokens.

## 3. Evaluator acceptance (behaviour-preserving)

- [x] 3.1 Failing engine test: a subscripted expansion is expansion-bearing and
      floors an `:allow` as an unknown scalar does; the trailing command after an
      array literal is evaluated. Confirm red.
- [x] 3.2 Handle the new AST nodes in `crates/engine` decompose/eval: array
      element words contribute embedded-command and taint scan sites like a scalar
      value; subscripted expansions are unresolved.
- [x] 3.3 Proptest: for inputs containing no array syntax, decisions are
      byte-for-byte unchanged from before this change (refactor-safety).

## 4. Verification

- [x] 4.1 `cargo fmt`; full `cargo test` across `shell-parser` and `engine`.
- [x] 4.2 Fuzz/proptest: the parser and evaluator do not panic on arbitrary
      array-ish input (unterminated `(`, nested `(`, malformed subscripts).
- [x] 4.3 `cargo tarpaulin`; inspect `lcov.info` for uncovered branches in the
      array lexer/parser; add unit tests a proptest cannot reach.
- [x] 4.4 Confirm no DSL/config/trust-hash surface changed; no migration. Verify
      this unblocks `resolve-constant-array-arguments` (array AST + separated
      subscript are available).
- [x] 4.5 Review `REFERENCE.md`: document array-literal and subscript parsing /
      the removed truncation, or record "verified, no surface change".
      → Verified, no surface change: `REFERENCE.md` documents the user-facing
        DSL (rules, parsers, capabilities); this change is internal parser/AST
        modelling with no new DSL form, config key, or trust-hash input.
