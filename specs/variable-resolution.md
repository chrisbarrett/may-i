# Variable Resolution

Tracks variable safety state through the AST to determine whether command
arguments can be statically analyzed. Three-state model: known literals are
matched against rules, opaque values match only wildcards, unsafe values
trigger `ask`.

---

## R16: Variable safety states

Variables have one of three states:

| State          | Meaning                                    | Rule matching          |
| :------------- | :----------------------------------------- | :--------------------- |
| `Known(value)` | Resolvable to a literal string             | Matched normally        |
| `Opaque`       | Safe but value unknown (e.g., loop var)    | Matches only wildcards  |
| `Unsafe`       | Assigned from untrusted/unresolvable source| Triggers `ask`          |

**Given** a variable assigned from a literal (`VAR=hello`) **Then** state is
`Known("hello")`.

**Given** a variable assigned from command substitution (`VAR=$(cmd)`) where the
substituted command evaluates to `allow` **Then** state is `Opaque`.

**Given** a variable assigned from an unresolvable source **Then** state is
`Unsafe`.

**Verify:** `cargo test -- var_env`

## R17: Conservative matching for opaque arguments

**Given** an `Opaque` resolved argument **When** matched against an `Expr`
**Then** it matches only `Wildcard` expressions — never literals or regexes.

This ensures the engine never assumes a safe match on values it cannot inspect.

**Verify:** property tests in `matcher`; `cargo test -- matcher`

## R18: Process environment seeding

**Given** the engine starts evaluation **Then** `VarEnv` is seeded from the
process environment (`std::env::vars()`), with all vars marked `Known`.

Additionally, vars listed in `(safe-env-vars ...)` config are always resolvable
even if not present in the process environment.

**Verify:** `cargo test -- var_env`

## R19: Control flow merging

**Given** branching control flow (if/elif/else, case arms) **Then** merge
branch environments conservatively:

- If a variable is `Known` with the same value in all branches → `Known`
- If a variable differs across branches or is `Opaque` in any → `Opaque`
- If a variable is `Unsafe` in any branch → `Unsafe`

**Given** a for-loop with literal values **Then** evaluate the body once per
value, threading the env through each iteration.

**Given** a for-loop with a dynamic iterator **Then** set the loop variable to
`Opaque` and evaluate the body once.

**Verify:** `cargo test -- engine`; tests for if/for/while/case variable
tracking

## R20: Subprocess isolation

**Given** a subshell `(...)`, pipeline `|`, or background job `&` **Then** the
child receives a copy of the parent env. Mutations inside the child do not
propagate back to the parent scope.

**Verify:** `cargo test -- engine`

## R21: Word resolution

**Given** a word containing `$VAR` or `${VAR}` references **When** `VAR` is
`Known(value)` **Then** replace the reference with the literal value.

**When** `VAR` is `Opaque` **Then** replace with an opaque marker (matches only
wildcards).

**When** `VAR` is `Unsafe` or not in env **Then** leave the reference
unresolved (triggers dynamic-parts detection → `ask`).

**Verify:** `cargo test -- var_env`

## Constraints

- Variable tracking must be zero-allocation for the common case (no variables)
- Merging must be conservative: safety never increases through branching
- All public resolution functions are pure (no side effects beyond VarEnv
  threading)
