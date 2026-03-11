## Why

Checks can now inject runtime context facts, but the current `(facts ...)` inline syntax breaks the plist-style readability that makes `(check ...)` forms easy to scan. As more rules use context-sensitive checks, that awkward shape makes configs harder to read, group, and maintain.

## What Changes

- Replace inline check fact injection with an explicit `(with-facts FACTS ...CHECKS...)` scope inside `(check ...)`.
- Introduce a uniform vector-based fact literal for check-scoped facts, where each fact entry is expressed as a vector.
- Allow nested `with-facts` scopes so outer fact bindings can be refined for smaller groups of assertions.
- Define validation and diagnostics for empty fact literals, empty `with-facts` bodies, and duplicate fact keys within a single fact literal.
- Update examples and documentation so context-aware checks use the new scoped syntax consistently.

## Capabilities

### New Capabilities
- None.

### Modified Capabilities
- `context-aware-configuration`: Revise check syntax for supplying context facts so fact-aware assertions use scoped `with-facts` blocks and vector fact literals.

## Impact

- Affects config parsing for `(check ...)` forms and the representation of inline check context.
- Affects config validation, warnings, and user-facing examples for context-sensitive checks.
- Requires updates to docs and tests covering nested scopes, duplicate fact handling, and warning cases.
