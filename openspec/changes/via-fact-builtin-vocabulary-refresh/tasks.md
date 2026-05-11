## 1. Audit current spec

- [ ] 1.1 Re-read `openspec/specs/via-fact-builtin/spec.md` and confirm
      the only changes needed are vocabulary, not semantics.
- [ ] 1.2 Cross-check against `parser-bindings`, `parameter-many-till`,
      and `rule-evaluation` to make sure the refreshed examples are
      consistent with how they use `(authorise …)` and decision verbs.

## 2. Refresh spec text

- [ ] 2.1 MODIFY `openspec/specs/via-fact-builtin/spec.md`:
      - Purpose: replace "wrapper recursion" / "each `(authorise)` recurse"
        wording so it reads naturally with current forms.
      - "`:via` push on recurse" requirement: rewrite scenarios to use
        `(parser …  (rest #cmd))` + `(rule "sudo" (authorise #cmd))`
        instead of `(rule "sudo" (positional . (may-i *)))`.
      - "`:via` is the only automatic fact" requirement: rewrite the
        bind-vs-automatic scenario to use parser-side
        `(positional #host …)` binding rather than rule-side
        `(positional [:ssh/host *] …)`.
      - Replace `:effect (effect :decision)` with bare `(decision)`
        verbs throughout.

## 3. Validate

- [ ] 3.1 `openspec validate via-fact-builtin-vocabulary-refresh --strict`.
- [ ] 3.2 `grep` confirms no `(may-i ` or `(effect :` left in the
      refreshed spec.
