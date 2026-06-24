## Why

Once `model-bash-arrays` makes arrays representable, a literal array is the same
provable primitive as a scalar constant or an enumerable `for` list — a
statically-known finite sequence of literals:

```sh
parts=(s3://bkt/a s3://bkt/b)
aws s3 cp "${parts[@]}" /tmp/x        # → aws s3 cp s3://bkt/a s3://bkt/b /tmp/x
region=${zones[0]}                     # → a single literal element
```

But arrays add a mechanism scalars and loops do not: `"${arr[@]}"` is
**word-count-changing** — one token expands to N argv words. This change resolves
constant-array expansions in arguments so they match rules on their real values.

## What Changes

- Track **provably-constant arrays**: an array with a single array-literal
  assignment whose elements are all static literals, never mutated by element
  assignment (`arr[i]=`), append (`arr+=`), `unset 'arr[i]'`, or a sparse/dynamic
  index. Such an array maps to a known ordered sequence of literals.
- Resolve subscripted argument expansions against that sequence:
  - `${arr[i]}` with a literal index → the single element literal (scalar-style
    resolution; reuses `resolve-constant-argument-expansions`);
  - quoted `"${arr[@]}"` → **one resolved argv word per element** (word-count
    expansion), each provable, so positional/`anywhere` matchers see the real
    arguments;
  - `${#arr[@]}` → the element count as a literal.
- `${arr[*]}` and **unquoted** `${arr[@]}` stay unresolved (their joining/splitting
  depends on `IFS` and globbing) — conservative, floors as today.
- All-or-nothing: if any element is not a provable literal, or the array is
  mutated, the whole expansion stays unresolved and floors an `:allow` as before.

## Capabilities

Bucket: `parsing` (how argv words resolve before rules see them).

### New Capabilities

<!-- none -->

### Modified Capabilities

- `shell-command-security-model`: extend provably-constant resolution to literal
  bash arrays — resolve `${arr[i]}`, quoted `"${arr[@]}"` (expanding to one argv
  word per element), and `${#arr[@]}`; keep `${arr[*]}`/unquoted `${arr[@]}` and
  any mutated or non-literal array unresolved.

## Impact

- `crates/shell-parser/src/const_env.rs` — generalise the provably-constant
  analysis to also yield constant **arrays** (a name → ordered literal sequence),
  disqualifying on any element/append/unset mutation, sparse or dynamic index, or
  non-literal element. Scalars are unchanged (a singleton case alongside).
- `crates/engine/src/eval/decompose.rs` — when building `args`/`arg_expansions`,
  resolve a subscripted expansion against the constant-array env: a single-element
  result substitutes one literal (clearing its expansion flag); a quoted `[@]`
  splices N literal args into the argv with N cleared flags, preserving
  `args.len() == arg_expansions.len()`; `${#arr[@]}` substitutes the count.
- Tests: `crates/engine` — `[@]` argv splice matches a positional/`anywhere`
  pattern over the elements; literal-index single resolution; `${#arr[@]}` count;
  `[*]`/unquoted/mutated/non-literal stay flagged. Metamorphic: a resolved
  `"${arr[@]}"` classifies identically to the elements written inline.
- No DSL, config, or trust-hash surface change; no migration. **Depends on**
  `model-bash-arrays` (array AST + separated subscripts) and reuses
  `resolve-constant-argument-expansions` (single-literal resolution).
