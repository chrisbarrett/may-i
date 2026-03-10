## Why

The configuration DSL can match commands and arguments, but it cannot express rules that depend on who invoked `may-i`, what runtime mode the host is in, or what execution context wrappers like `ssh` introduce. As the tool grows beyond a single Claude Code hook flow, that makes otherwise-safe policies verbose, tool-specific, or impossible to express.

## What Changes

- Add context-aware rule matching so rules can query namespaced facts contributed by the host runtime and by wrapper unwrapping.
- Extend wrapper definitions so matched wrappers can infer a `:via/<wrapper>` fact and extract single scalar facts from matched arguments.
- Add top-level `defcontext` aliases so commonly reused context expressions can be named and composed inside `(context ...)` forms.
- Define clear behavior for missing or dynamic facts so context-sensitive rules remain conservative and predictable.

## Capabilities

### New Capabilities
- `context-aware-configuration`: Define, derive, and query namespaced context facts in the configuration DSL, including reusable context aliases and wrapper-derived facts.

### Modified Capabilities

## Impact

- Affects the config grammar, parser, and core configuration data model.
- Affects hook/runtime input handling so host-specific facts can be populated from incoming payloads.
- Affects wrapper evaluation and rule matching in the engine so derived context participates in authorization decisions.
- Requires new docs, examples, and checks covering context queries, `defcontext`, and wrapper-derived facts.
