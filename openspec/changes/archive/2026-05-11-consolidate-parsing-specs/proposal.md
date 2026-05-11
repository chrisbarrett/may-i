## Why

The Parsing bucket holds 9 specs: `dsl-form-list-syntax`, `parser-bindings`,
`parser-engine-invariants`, `pattern-expressions`, `prelude-wrapper-parsers`,
`parameter-many-till`, `partial-pattern-matching`, `expr-combinator-matching`,
`v2-expr-fact-binding` (plus contributor-only `wordpart-source-spans` and
`span-coalescing`). Three of these are sub-1-requirement spec stubs
(`expr-combinator-matching`, `v2-expr-fact-binding`, `span-coalescing`) and
two more (`partial-pattern-matching`, `parameter-many-till`,
`prelude-wrapper-parsers`) restate behaviour their natural parent spec
already describes at a higher level.

This change folds the stubs and sub-spec restatements into their natural
parents (`pattern-expressions`, `parser-bindings`, `wordpart-source-spans`).
The rename `pattern-expressions` → `patterns` (vocab alignment per
`spec-conventions`) is deferred to the dedicated `rename-specs-to-vocab`
change.

Net 9 → 5 parsing specs (excluding contributor specs;
`parser-engine-invariants` stays as it is sized and distinct).

## What Changes

- **Fold `expr-combinator-matching` → `pattern-expressions`**: 1
  requirement (*Expr::Or matches if any sub-expression matches*).
- **Fold `partial-pattern-matching` → `pattern-expressions`**: 4
  requirements about positional quantifier semantics (`?`/`+`/`*`).
- **Fold `v2-expr-fact-binding` → `pattern-expressions`**: 1 requirement
  about where fact-binding `[:k *]` is and isn't valid inside argv-shaped
  patterns.
- **Fold `parameter-many-till` → `parser-bindings`**: 3 requirements
  about multi-token parameter capture and the rule-body access path.
- **Fold `prelude-wrapper-parsers` → `parser-bindings`**: 2 requirements
  enumerating the prelude's per-wrapper parser declarations and the
  prelude `find` parser.
- **Fold `span-coalescing` → `wordpart-source-spans`** (contributor): 1
  requirement about adjacent ignore-span coalescing in JSON output.

`parser-engine-invariants`, `dsl-form-list-syntax`, and
`shell-command-security-model` stay untouched.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `pattern-expressions` — ABSORBS `expr-combinator-matching`,
  `partial-pattern-matching`, and `v2-expr-fact-binding`. 6 requirements
  added to its existing 6.
- `parser-bindings` — ABSORBS `parameter-many-till` and
  `prelude-wrapper-parsers`. 5 requirements added to its existing 10.
- `wordpart-source-spans` — ABSORBS `span-coalescing`. 1 requirement
  added.

### Removed Capabilities

- `expr-combinator-matching` — folded into `pattern-expressions`.
  Directory removed at archive.
- `partial-pattern-matching` — folded into `pattern-expressions`.
  Directory removed.
- `v2-expr-fact-binding` — folded into `pattern-expressions`. Directory
  removed.
- `parameter-many-till` — folded into `parser-bindings`. Directory
  removed.
- `prelude-wrapper-parsers` — folded into `parser-bindings`. Directory
  removed.
- `span-coalescing` — folded into `wordpart-source-spans`. Directory
  removed.

## Spec-delta convention

Source-spec deltas list `## REMOVED Requirements` as `### Requirement:
NAME` blocks with **Reason** and **Migration** lines. Target-spec deltas
list `## ADDED Requirements` with full body and `#### Scenario:` children
copied verbatim from the source files.

## Impact

- `openspec/specs/pattern-expressions/spec.md` — receives 6 requirements
  (1 + 4 + 1).
- `openspec/specs/parser-bindings/spec.md` — receives 5 requirements
  (3 + 2). Purpose rewritten to cover the absorbed scope.
- `openspec/specs/wordpart-source-spans/spec.md` — receives 1
  requirement.
- 6 source spec directories removed at archive.
- No source-code, test, or runtime config changes.

## Compatibility

No requirement content changes. The rename
`pattern-expressions` → `patterns` (vocab alignment) is deferred to
`rename-specs-to-vocab`.
