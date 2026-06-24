## 1. Constant-array analysis

- [x] 1.1 Add a failing test in `crates/shell-parser`: `arr=(a b c)` yields a
      constant array `[a,b,c]`; `arr+=(d)`, `arr[1]=x`, `unset 'arr[0]'`, a
      dynamic index, or a non-literal element each disqualify it. Confirm red.
- [x] 1.2 Generalise `constant_env` to a per-name value kind
      (`Scalar(String)` | `Array(Vec<String>)`); scalars stay the singleton case.
      Extend the use-order / no-reassignment discipline to arrays plus the
      array-specific disqualifiers.
- [x] 1.3 Update scalar consumers (command-name and scalar-argument resolution)
      for the new value kind; proptest that scalar behaviour is unchanged.

## 2. Subscript resolution in `decompose`

- [x] 2.1 Failing engine test: `parts=(s3://bkt/a s3://bkt/b); aws s3 cp "${parts[@]}" /tmp/x`
      with an allow matching both sources resolves to `:allow`, no floor, and
      matchers see `s3://bkt/a`, `s3://bkt/b`, `/tmp/x`. Confirm red.
- [x] 2.2 Resolve `${arr[i]}` (literal index) → single element via the scalar
      `Word::resolve` path; `${#arr[@]}` → element count.
- [x] 2.3 Implement the quoted `"${arr[@]}"` argv splice: replace one slot with N
      element slots, each with a cleared `arg_expansions` entry; preserve
      `args.len() == arg_expansions.len()`. Mixed-splice (`pre"${arr[@]}"post`)
      left unresolved in v1 (`quoted_array_splice` restricts to a lone-word
      splice; documented there).
- [x] 2.4 Leave `${arr[*]}`, unquoted `${arr[@]}`, dynamic index, and any mutated
      or non-literal array expansion-bearing (unresolved).
- [x] 2.5 Gate resolution on the array kind from `model-bash-arrays`: resolve
      indexed arrays only; leave associative `${m[key]}`, `"${m[@]}"`, `${m[*]}`,
      `${#m[@]}` unresolved (unspecified element order → unsound to resolve).

## 3. Boundary and matcher scenarios

- [x] 3.1 Test: a `(positional …)` pattern after an `[@]` splice matches the right
      argument index (splice does not misalign positions).
- [x] 3.2 Test: literal index single resolution; out-of-range and dynamic index
      stay unresolved.
- [x] 3.3 Test: `${#arr[@]}` resolves to the count.
- [x] 3.4 Test: `[*]`, unquoted `[@]`, mutated array, and non-literal element all
      stay flagged and floor an `:allow`.
- [x] 3.6 Test: an associative `declare -A m=([a]=1 [b]=2); cmd "${m[@]}"` stays
      unresolved (kind-gated, unspecified order).
- [x] 3.5 Metamorphic proptest: a resolved `"${arr[@]}"` classifies identically to
      its element literals written inline in the command.

## 4. Verification

- [x] 4.1 `cargo fmt`; full `cargo test` across `shell-parser` and `engine`.
- [x] 4.2 `cargo tarpaulin`; inspect `lcov.info` for uncovered branches in the
      array resolution / splice path; add unit tests a proptest cannot reach.
      Splice + `resolve_argument_words` fully covered; added targeted tests for
      `${#arr[i]}` char-length, dynamic/non-numeric index, star-length, and the
      operator-poison path. Only residual gaps are trivial safe-direction stubs.
- [x] 4.3 Confirm dependence on `model-bash-arrays` (array AST + separated
      subscripts) and `resolve-constant-argument-expansions` (single-literal
      resolution); no DSL/config/trust-hash surface changed; no migration.
- [x] 4.4 Review `REFERENCE.md`: documents user-facing DSL surface only; constant
      scalar/loop resolution from the prior changes added nothing there, and this
      change adds no DSL/config/trust surface — verified, no surface change.
