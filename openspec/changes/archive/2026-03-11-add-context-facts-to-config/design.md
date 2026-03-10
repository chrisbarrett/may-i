## Context

`may-i` currently evaluates rules using command names, argument matchers, and wrapper unwrapping. The hook path already receives runtime metadata such as `tool_name`, `permission_mode`, and `cwd`, but that information is discarded before evaluation. Wrapper definitions also only control how an inner command is found; they cannot contribute semantic facts like "this command runs via ssh" or "this ssh host is prod-1".

This change introduces context-aware policy without turning the DSL into a general macro or logic language. The design needs to fit the existing s-expression style, preserve conservative static analysis, and keep rule evaluation explainable in traces and checks.

## Goals / Non-Goals

**Goals:**
- Add a context query clause to rules so authorization can depend on namespaced facts from the host runtime and matched wrappers.
- Add top-level `defcontext` aliases so repeated context queries can be named and reused inside boolean context expressions.
- Extend wrappers so they infer `:via/<wrapper-command>` facts by default and can extract a single scalar fact from a matched argument via bracket binding syntax.
- Keep missing or dynamic context facts conservative so context-sensitive rules only match when their inputs are statically known.
- Keep the model extensible for tool-specific facts without forcing awkward cross-tool abstractions.

**Non-Goals:**
- Add a general macro system, parameterized aliases, or local variables in the DSL.
- Support list-valued facts, multi-token captures, or arbitrary fact mutation.
- Normalize tool-specific facts into a shared schema beyond a minimal namespaced fact model.
- Change the existing command and argument matching semantics except where context evaluation is integrated.

## Decisions

### Use namespaced fact keys instead of a fixed context schema

Rules will query a fact store keyed by namespaced atoms such as `:client/claude-code`, `:claude-code/permission-mode`, `:opencode/mode`, `:via/ssh`, and `:ssh/host`. This avoids inventing universal fields like `mode` that mean different things across tools.

Alternatives considered:
- Fixed top-level fields such as `client`, `mode`, and `permission-mode`: rejected because they hard-code tool-specific concepts into the core DSL.
- Fully generic maps with arbitrary nested data: rejected because the evaluator and query language do not need that complexity yet.

### Add a dedicated `(context ...)` rule clause with explicit boolean expressions

Rules will accept a `(context EXPR)` clause, where `EXPR` is a boolean expression over primitive predicates and alias references. The context expression will compose explicitly with `and`, `or`, and `not` rather than relying on an implicit conjunction body.

Primitive predicates will be intentionally small:
- `(has :key)` for presence facts
- `(= :key "value")` for exact scalar matches
- `(matches :key "regex")` for regex matches against scalar values

Alternatives considered:
- Implicitly-and-ed `(context ...)` bodies: rejected because the rest of the DSL prefers explicit boolean structure.
- Tool-specific predicates like `(client ...)` or `(ssh-host ...)`: deferred as future sugar; the raw namespaced key model is more honest and more extensible.

### Add top-level `defcontext` aliases as simple AST substitutions

`(defcontext NAME EXPR)` will define a reusable context expression that can appear anywhere another context expression can appear, including inside `(and ...)` and `(or ...)`. Definitions remain top-level only, cannot take parameters, and are only valid in context expressions. Cycles and references to unknown names will be configuration errors.

Alternatives considered:
- No aliasing: rejected because repeated context predicates would become noisy quickly.
- General macro expansion: rejected because it would add too much surface area and make diagnostics harder to reason about.

### Wrapper matching derives facts directly

When a wrapper matches, it will automatically add `:via/<wrapper-command>` as a presence fact. Wrapper pattern syntax will also support direct scalar fact extraction using bracket bindings like `[:ssh/host *]`, meaning "match one scalar argument and attach its statically known value to `:ssh/host`".

Bindings are facts, not local variables. There are no temporary names, multi-value captures, or post-match `fact` emission forms in the first version.

Alternatives considered:
- Explicit `(fact ...)` forms plus temporary variables: rejected because it introduces a second binding model with no demonstrated need.
- No inferred `:via/...` fact: rejected because it adds boilerplate for the most common provenance signal.

### Facts accumulate through wrapper unwrapping and runtime ingestion

Context facts come from two sources:
- Runtime ingestion at the boundary, such as hook payload metadata or CLI-selected execution mode.
- Wrapper derivation during unwrapping, where nested wrappers accumulate additional facts before the inner command is evaluated.

Context evaluation will be threaded through the engine alongside the resolved command so rule matching, traces, and checks all see the same fact set.

### Unknown or dynamic values do not produce derived scalar facts

If a wrapper can prove that it matched but the extracted value is not statically known, it will still contribute its inferred `:via/...` fact but omit the scalar fact. Context queries therefore only match extracted scalar facts when those values are trustworthy.

For runtime facts, absent fields simply mean the corresponding fact is not present.

## Risks / Trade-offs

- [Fact key collisions from multiple sources] -> Require namespaced keys and define clear parser/runtime validation so ambiguous ownership is avoided.
- [Harder traces once context joins rule evaluation] -> Extend rule annotations and JSON output so fact-based matches remain inspectable in `eval` and `check`.
- [Wrapper syntax drift from the current grammar] -> Keep bracket binding narrowly scoped to wrapper extraction and single-scalar captures.
- [Tool-specific behavior creeping into the core model] -> Keep the shared model to namespaced facts plus generic predicates; add sugar only after real usage proves it out.

## Migration Plan

- Existing configs remain valid because `context`, `defcontext`, and bracket fact bindings are additive syntax.
- Hook/runtime entry points start populating facts opportunistically from known metadata without requiring users to opt in.
- Built-in wrappers and starter config examples can be updated incrementally to demonstrate fact-aware policies, especially `ssh`.
- If future work needs more expressive extraction, it can extend the wrapper pattern language without breaking the scalar-first model.

## Open Questions

- Should repeated scalar facts for the same key be rejected, or should later facts overwrite earlier ones during wrapper accumulation?
- Which runtime facts should be populated outside hook mode, especially for `eval` and `check`, so examples stay predictable across entry points?
- How much trace detail is enough for context predicates before output becomes too noisy?
