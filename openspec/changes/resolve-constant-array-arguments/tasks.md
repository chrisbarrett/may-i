## 1. Constant-array analysis

- [ ] 1.1 Add a failing test in `crates/shell-parser`: `arr=(a b c)` yields a
      constant array `[a,b,c]`; `arr+=(d)`, `arr[1]=x`, `unset 'arr[0]'`, a
      dynamic index, or a non-literal element each disqualify it. Confirm red.
- [ ] 1.2 Generalise `constant_env` to a per-name value kind
      (`Scalar(String)` | `Array(Vec<String>)`); scalars stay the singleton case.
      Extend the use-order / no-reassignment discipline to arrays plus the
      array-specific disqualifiers.
- [ ] 1.3 Update scalar consumers (command-name and scalar-argument resolution)
      for the new value kind; proptest that scalar behaviour is unchanged.

## 2. Subscript resolution in `decompose`

- [ ] 2.1 Failing engine test: `parts=(s3://bkt/a s3://bkt/b); aws s3 cp "${parts[@]}" /tmp/x`
      with an allow matching both sources resolves to `:allow`, no floor, and
      matchers see `s3://bkt/a`, `s3://bkt/b`, `/tmp/x`. Confirm red.
- [ ] 2.2 Resolve `${arr[i]}` (literal index) → single element via the scalar
      `Word::resolve` path; `${#arr[@]}` → element count.
- [ ] 2.3 Implement the quoted `"${arr[@]}"` argv splice: replace one slot with N
      element slots, each with a cleared `arg_expansions` entry; preserve
      `args.len() == arg_expansions.len()`. Decide and document the mixed-splice
      (`pre"${arr[@]}"post`) policy — resolve per bash join rules, or leave
      unresolved in v1.
- [ ] 2.4 Leave `${arr[*]}`, unquoted `${arr[@]}`, dynamic index, and any mutated
      or non-literal array expansion-bearing (unresolved).
- [ ] 2.5 Gate resolution on the array kind from `model-bash-arrays`: resolve
      indexed arrays only; leave associative `${m[key]}`, `"${m[@]}"`, `${m[*]}`,
      `${#m[@]}` unresolved (unspecified element order → unsound to resolve).

## 3. Boundary and matcher scenarios

- [ ] 3.1 Test: a `(positional …)` pattern after an `[@]` splice matches the right
      argument index (splice does not misalign positions).
- [ ] 3.2 Test: literal index single resolution; out-of-range and dynamic index
      stay unresolved.
- [ ] 3.3 Test: `${#arr[@]}` resolves to the count.
- [ ] 3.4 Test: `[*]`, unquoted `[@]`, mutated array, and non-literal element all
      stay flagged and floor an `:allow`.
- [ ] 3.6 Test: an associative `declare -A m=([a]=1 [b]=2); cmd "${m[@]}"` stays
      unresolved (kind-gated, unspecified order).
- [ ] 3.5 Metamorphic proptest: a resolved `"${arr[@]}"` classifies identically to
      its element literals written inline in the command.

## 4. Verification

- [ ] 4.1 `cargo fmt`; full `cargo test` across `shell-parser` and `engine`.
- [ ] 4.2 `cargo tarpaulin`; inspect `lcov.info` for uncovered branches in the
      array resolution / splice path; add unit tests a proptest cannot reach.
- [ ] 4.3 Confirm dependence on `model-bash-arrays` (array AST + separated
      subscripts) and `resolve-constant-argument-expansions` (single-literal
      resolution); no DSL/config/trust-hash surface changed; no migration.
- [ ] 4.4 Review `REFERENCE.md`: document constant-array argument resolution
      (`[i]`, quoted `[@]`, `${#arr[@]}`) and the unresolved `[*]`/unquoted cases,
      or record "verified, no surface change".
