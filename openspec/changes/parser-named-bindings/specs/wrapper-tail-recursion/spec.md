## REMOVED Requirements

### Requirement: Parser tail boundary accepts a single literal token

**Reason**: Subsumed by `(flags (until STR))` in the new parser-body grammar. Single-token boundary semantics (consume the boundary, neither slice contains it) are preserved in the new form.

**Migration**: `(tail (after "TOK"))` rewrites to `(flags (until "TOK")) (rest #cmd)` under `may-i migrate` (Class A, mechanical).

### Requirement: Parser tail boundary accepts an alias-set of literal tokens

**Reason**: Subsumed by `(flags (until STR…))` in the new parser-body grammar. The alias-set semantics (first occurrence of any listed token splits) are preserved.

**Migration**: `(tail (after [STR…]))` rewrites to `(flags (until STR…)) (rest #cmd)` under `may-i migrate`. The empty-alias-set error condition is preserved by the new form: `(flags (until))` is a config-load error.

### Requirement: `(tail (authorise))` returns no-match when boundary is absent and a tail is declared

**Reason**: Subsumed by the new `(authorise #var)` semantics. When `(flags (until STR…))` is declared and the argv lacks the boundary token, the `(rest #var)` binding is empty, and `(authorise #var)` returns no-match per the parser-bindings capability requirement "`(authorise #var)` recurses on a bound name".

**Migration**: Behaviour preserved. No-match semantics for absent-boundary inputs continue to apply through the new authorise-on-empty rule.

### Requirement: Prelude declares a `nix` parser with multi-token tail boundary

**Reason**: Replaced by the prelude declaration in the new form. See modified prelude-wrapper-parsers capability.

**Migration**: `(parser "nix" (style gnu) (tail (after ["--command" "-c"])))` rewrites to `(parser "nix" (style gnu) (flags (until "--command" "-c")) (rest #cmd))` in the prelude. User shadowing semantics are preserved.
