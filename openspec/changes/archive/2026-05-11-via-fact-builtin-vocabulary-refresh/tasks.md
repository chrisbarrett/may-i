## 1. Audit current spec

- [x] 1.1 Re-read `openspec/specs/via-fact-builtin/spec.md` and
      confirmed only vocabulary changes are needed; both requirements
      remain semantically identical.
- [x] 1.2 Cross-checked against `parser-bindings`, `parameter-many-till`,
      and `rule-evaluation`; refreshed examples are consistent.

## 2. Refresh spec text

- [x] 2.1 MODIFIED `openspec/specs/via-fact-builtin/spec.md`:
      Purpose rewritten in terms of `(authorise …)` recursion entries;
      scenarios use `(parser …  (rest #cmd))` + `(rule "sudo" (authorise #cmd))`
      shape; `:effect (effect :decision)` rewritten to bare decision
      verbs; `(positional [:ssh/host *] …)` rewritten to parser-side
      `(positional #host …)` + rule-side `(with-facts [[:ssh/host #host]] …)`.

## 3. Validate

- [x] 3.1 `openspec validate via-fact-builtin-vocabulary-refresh --strict`.
- [x] 3.2 `grep` confirms no `(may-i ` or `(effect :` left in the
      refreshed spec (the surviving `[:ssh/host …]` token is the
      legitimate `with-facts` fact-key syntax, not the old capture form).
