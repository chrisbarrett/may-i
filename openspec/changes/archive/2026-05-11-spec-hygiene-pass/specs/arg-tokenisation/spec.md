## REMOVED Requirements

The `arg-tokenisation` capability is removed in full. Its requirements describe a retired DSL surface (`:style` PLIST, `:long-prefix`, `:pun` keyword, `(may-i *)` recursion). The canonical parsing DSL spec is `dsl-form-list-syntax`. See proposal.md for the full contradiction list.

### Requirement: `(define NAME (PLIST))` declares a parsing style
**Reason:** PLIST-bodied style declarations retired by `dsl-form-list-syntax`; current form is `(define-arg-style NAME (overrides …) …)`.

### Requirement: Prelude ships standard styles
**Reason:** Subsumed by `dsl-form-list-syntax` and the prelude code itself; standard styles `gnu`, `single-dash-long`, `legacy-bundle`, `key-value` are documented in `CONTEXT.md`'s vocabulary table.

### Requirement: `(parser PROGRAM :style STYLE BODY…)` declares a parser
**Reason:** The `:style` PLIST key retired; `(style NAME)` is the body form per `dsl-form-list-syntax`.

### Requirement: Default fallback is the `gnu` style with no parameters
**Reason:** True but not specified anywhere it can drift; this fallback is part of how the parsing layer works and lives in the parser engine, not in a separate spec. Will be picked up by future parsing-spec consolidation if needed.

### Requirement: Pun policy controls bare parameter occurrence
**Reason:** Documented in `dsl-form-list-syntax`'s `(pun KEYWORD)` attribute form.

### Requirement: Parser applies to the command being evaluated
**Reason:** Behavioural rule of the engine; survives in `parser-engine-invariants` and the prelude wrapper parsers. The standalone restatement here added no enforcement.

### Requirement: Trace surfaces the resolved parser
**Reason:** Trace rendering is owned by `human-evaluation-trace` and `trace-system`; this requirement is a stray that those specs already cover.
