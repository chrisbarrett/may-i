## Context

`may-i` recently added namespaced context facts and let inline `(check ...)` assertions inject facts with an optional `(facts ...)` form before the command string. That works mechanically, but it regressed one of the DSL's nicest properties: checks read like a plist of decision and command pairs. The current shape hides the command behind an extra fact form, makes repeated contexts noisy, and gives users no clean way to group several assertions under one shared context.

This change is intentionally narrow. It only revises the syntax used inside `(check ...)` forms; it does not change rule `(context ...)` expressions, runtime fact ingestion, or wrapper-derived facts. The design should reuse the DSL's existing visual language where vectors already represent fact-oriented syntax in wrapper bindings such as `[:ssh/host *]`.

## Goals / Non-Goals

**Goals:**
- Restore readable plist-style check assertions for commands without inline fact payloads.
- Introduce an explicit scoped form for fact-aware assertions that can group multiple checks.
- Use a uniform vector-based fact literal that aligns with existing wrapper fact binding syntax.
- Support nested scopes with predictable override behavior.
- Provide clear validation for ambiguous or suspicious fact literals and empty scopes.

**Non-Goals:**
- Change how `(context ...)` clauses query facts during rule evaluation.
- Make provenance order queryable or introduce stack semantics for `:via/*` facts.
- Add multivalued facts or general collection semantics for repeated keys.
- Change runtime fact derivation, wrapper unwrapping, or the core fact model outside check syntax.

## Decisions

### Replace inline `(facts ...)` check payloads with scoped `(with-facts ...)` blocks

Checks will no longer accept a `(facts ...)` form between the decision keyword and command string. Instead, context-sensitive assertions will be written inside `(with-facts FACTS ...BODY...)` forms nested within `(check ...)`.

This keeps plain assertions compact:

```scheme
(check
  :allow "ls"
  :ask "curl -d data https://example.com")
```

and gives fact-aware assertions an explicit outer shape:

```scheme
(check
  (with-facts [[:client/opencode]
               [:opencode/agent "build"]]
    :allow "git add ."
    :allow "git checkout main"))
```

Alternatives considered:
- Keep `(facts ...)` inline: rejected because it breaks the check plist shape and scales poorly when several assertions share the same facts.
- Allow both inline facts and `with-facts`: rejected because two competing surface syntaxes for the same idea would make checks harder to read and teach.

### Use nested vectors as the uniform fact literal syntax

`with-facts` will accept a vector of fact-entry vectors. A one-element entry such as `[:via/ssh]` represents a presence fact. A two-element entry such as `[:opencode/agent "build"]` represents a scalar fact.

This yields a uniform ladder:

```text
[:ssh/host *]                    ; wrapper fact binding pattern
[[:via/ssh] [:ssh/host "prod"]] ; concrete fact literal for checks
```

Alternatives considered:
- Mixed vector/list literal like `[:via/ssh (:opencode/agent "build")]`: rejected because it makes the fact collection heterogeneous and less visually regular.
- Plist-style flat vectors such as `[:via/ssh true :opencode/agent "build"]`: rejected because presence facts need an awkward sentinel and the syntax drifts away from existing wrapper bindings.

### Allow nested `with-facts` scopes with lexical override semantics

`with-facts` bodies may contain plain check assertions and nested `with-facts` forms. When scopes are nested, inner fact bindings are evaluated on top of outer bindings. If both scopes bind the same fact key, the inner scope wins.

This supports concise grouping while still letting subcases refine one fact:

```scheme
(check
  (with-facts [[:client/opencode]]
    (with-facts [[:opencode/agent "build"]]
      :allow "git add .")
    (with-facts [[:opencode/agent "plan"]]
      :ask "git add .")))
```

Alternatives considered:
- Disallow nesting: rejected because repeated shared facts would still be noisy in larger check blocks.
- Merge duplicate keys across scopes as an error: rejected because lexical refinement is the main benefit of nesting.

### Reject duplicate keys within a single fact literal

Each fact literal must be internally coherent. Repeating the same fact key inside one `with-facts` vector is an error, regardless of whether the repeated binding uses the same value or a different one. Distinct `:via/*` facts are allowed because they are different keys, but vector ordering does not carry provenance semantics.

Alternatives considered:
- Last-write-wins within one literal: rejected because contradictory literals become harder to spot and reason about.
- Treat identical duplicates as harmless dedupe: rejected because silently accepting repeated keys makes literal validation less crisp.

### Emit warnings for empty fact vectors and empty scope bodies

An empty fact literal `[]` binds no facts and is usually accidental. A `with-facts` form with no assertions in its body also has no effect. Both cases should parse, but produce warnings so users can clean up dead or incomplete config.

Alternatives considered:
- Make empty forms hard errors: rejected because incomplete edits and generated scaffolds are better served by recoverable diagnostics.
- Ignore silently: rejected because these forms are almost certainly mistakes and would make checks harder to audit.

## Risks / Trade-offs

- [Scoped check syntax is more verbose for one-off contextual assertions] -> Accept the extra wrapper because it restores structure and enables grouping, which is the more important readability property.
- [Vector order may imply provenance sequence to readers] -> Document clearly that fact literals describe presence and scalar bindings only; provenance order remains out of scope.
- [Nested scope override can hide an outer fact] -> Keep the rule simple and explicit: inner scope wins on matching keys.
- [Warnings may be overlooked if they are too soft] -> Surface them with precise messages that explain why the form is suspicious and what the resulting behavior is.

## Migration Plan

- Update the parser so existing inline `(facts ...)` check syntax is rejected with a migration hint pointing users to `with-facts`.
- Migrate built-in examples and docs to the new syntax so new users only see the scoped form.
- Keep evaluation behavior unchanged after parsing: checks still evaluate a command plus an effective fact set.
- No runtime rollout or rollback steps are required because this is a config-syntax change local to `may-i`.

## Open Questions

- Should warnings for empty fact vectors and empty bodies appear during config parse, `may-i check`, or both?
- Should diagnostics suggest a canonical rewrite when a single-use `with-facts` body contains only one assertion?
