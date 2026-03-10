## 1. Context DSL and data model

- [ ] 1.1 Extend the config grammar and parser to accept top-level `defcontext` forms and rule-level `(context ...)` clauses with `and`, `or`, `not`, `has`, `=`, and `matches` predicates.
- [ ] 1.2 Add core data types for namespaced context facts, context expressions, and resolved context aliases, including validation for unknown and cyclic `defcontext` references.
- [ ] 1.3 Update configuration diagnostics, pretty-printing, and starter documentation to describe the new context syntax and reserved forms.

## 2. Wrapper-derived facts

- [ ] 2.1 Extend wrapper parsing and types to support single-scalar bracket fact bindings such as `[:ssh/host *]` in wrapper patterns.
- [ ] 2.2 Update wrapper unwrapping to infer `:via/<wrapper-command>` facts on match and attach extracted scalar facts only when the matched value is statically known.
- [ ] 2.3 Define and implement accumulation behavior for nested wrappers so derived facts are threaded into the inner command evaluation context.

## 3. Runtime fact ingestion and rule evaluation

- [ ] 3.1 Ingest namespaced context facts from hook/runtime inputs, including Claude Code metadata that is already present in the incoming payload.
- [ ] 3.2 Thread the context fact set through engine evaluation so rule matching considers command, args, and `(context ...)` together.
- [ ] 3.3 Extend evaluation traces and JSON output so context-based matches and skips remain inspectable in `eval` and `check`.

## 4. Verification and examples

- [ ] 4.1 Add parser and config tests covering `defcontext`, context predicates, alias composition, and cycle/unknown-name errors.
- [ ] 4.2 Add engine tests covering runtime facts, wrapper-derived facts, nested wrapper accumulation, and conservative handling of dynamic values.
- [ ] 4.3 Update examples and user-facing docs with representative policies for Claude Code metadata, OpenCode modes, and `ssh` host-sensitive rules.
