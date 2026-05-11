## Why

`openspec/specs/via-fact-builtin/spec.md` documents how the automatic `:via`
fact is populated during recursive evaluation. The contract is current, but
the prose and scenarios still use vocabulary retired by the
`parser-named-bindings` change:

- `(may-i *)` — retired; replaced by `(authorise #var)` and friends.
- `:effect (effect :deny)` — retired; replaced by the bare decision verbs
  `(allow)`, `(ask)`, `(deny)` in rule-body position.
- `(positional [:ssh/host *] …)` — pre-binding fact-capture syntax; users
  now write the parser-side `(positional #host …)` declaration and
  reference `#host` from rule bodies.

This spec is the only live spec under `openspec/specs/` that still uses
these forms. The drift was missed by `spec-hygiene-pass` and the
normalisation passes. This change refreshes the language without
changing semantics — same requirement, same scenarios, current
vocabulary.

## What Changes

- **Refresh `via-fact-builtin` spec text to current vocabulary.** Replace
  `(may-i *)` with `(authorise #var)`-shaped examples grounded in the
  parser-bindings model. Replace `(effect :decision)` with bare
  decision verbs. Replace `[:ssh/host *]` fact captures with
  parser-side `#host` bindings.
- **No requirement changes.** The two existing requirements
  ("`:via` pushed on recurse" and "`:via` is the only automatic fact")
  remain. Only their text and scenarios are updated.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `via-fact-builtin`: vocabulary refresh; no behaviour change.

## Impact

- `openspec/specs/via-fact-builtin/spec.md` — Purpose paragraph,
  requirement bodies, and scenarios rewritten in current vocabulary.
- No code changes. No fixtures changed. Engine semantics unchanged.
