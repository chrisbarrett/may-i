## Context

A spec audit (May 2026) of `openspec/specs/` surfaced systemic format drift across the 50-spec corpus:

- 22 stable specs retain `## ADDED Requirements` / `## MODIFIED Requirements` headings. These are the canonical headings for delta specs under `openspec/changes/*/specs/`, where they describe the delta a change applies. They have no meaning in stable specs and confuse readers (a stable spec is the current state, not a diff against some prior state).
- 17 specs have Purpose sections containing only the literal text "TBD - created by archiving change …". These were auto-generated at archive time and never filled in.
- `arg-tokenisation` documents retired DSL surface forms (`:style PLIST`, `:long-prefix`, `:pun`, `(may-i *)` recursion). The current syntax is in `dsl-form-list-syntax`. The two contradict each other directly.
- `config-load-surface` describes a one-shot structural refactor that has already landed.
- `review-followup` is a checklist of "did we finish the review tasks" — a task tracker, not a behavioural specification.
- Thin specs (8–32 lines, single requirement) overlap with larger parent specs (`evaluator-error-handling` with `eval-segment-decisions`; `unified-renderer` with `pretty-printing`; `span-coalescing` with `trace-system`).

The audit also surfaced that two in-flight changes (`parser-named-bindings`, `order-independent-rules`) will rewrite ~6 parsing and trust specs. The hygiene work cannot be done in one pass — it must sequence around the in-flight work.

The audit's core conclusion: the spec set is structurally fine where it concerns *behaviour*, and structurally drifting where it concerns *presentation*. The drift compounds because each new change inherits the shape of the most recent archive. Writing down the rules once, in a spec that itself models them, anchors future hygiene work.

## Goals / Non-Goals

**Goals:**

- A single spec under `openspec/specs/spec-conventions/spec.md` that any contributor (human or agent) can consult before editing a spec.
- Automated surfacing: Claude Code agents touching `openspec/specs/**` or `openspec/changes/**` see the conventions without having to know they exist.
- Consistency with the precedent for contributor-only specs (`code-quality`, `testing-strategy`, `parser-engine-invariants`).
- Set the stage for follow-on hygiene proposals to cite a specific requirement (e.g. "Requirement 5: TBD ban") rather than relitigating each rule.

**Non-Goals:**

- Rewriting the 22 drifted specs, the 17 TBD purposes, or the merge candidates. Those are separate change proposals (`spec-hygiene-pass`, `consolidate-thin-specs`, plus the post-in-flight merges).
- Imposing a new layout (e.g. moving specs to a flat directory or renaming buckets). The four-layer model and the contributor-vs-user vocabulary split in CONTEXT.md are taken as authoritative; this spec codifies how to apply them, not replaces them.
- Encoding the conventions outside `openspec/`. The Claude rule file is a thin trigger; the canonical text lives in the spec.
- Touching `AGENTS.md`. The Claude rule serves the same role for agents touching `openspec/`. AGENTS.md can pick up a cross-reference later if the maintainer judges it useful.

## Decisions

### Decision 1: Express the conventions as a capability spec, not a README

Two alternatives were considered:

- **Plain `openspec/specs/README.md`.** Lighter touch; humans browsing GitHub see it first. But it sits oddly alongside `<capability>/spec.md` directories and has no precedent in the repo.
- **Capability spec `spec-conventions`.** Consistent with `code-quality`, `testing-strategy`, `parser-engine-invariants` — all contributor-only specs about how to do contributor work, not user-facing behaviour. Lets follow-on changes cite a requirement number for compliance.

Chosen: capability spec. The precedent is strong, and the conventions spec gets to model the format it prescribes (the spec is its own first conformance test).

### Decision 2: Auto-surface via `.claude/rules/` rather than memory or CLAUDE.md

`.claude/rules/openspec-specs.md` with `paths: ["openspec/specs/**", "openspec/changes/**"]` frontmatter fires only when an agent reads files under those paths. Alternatives rejected:

- *Project-level CLAUDE.md.* Loaded for every session, every task. Pollutes context for unrelated work (cargo build, code reviews, etc.).
- *Auto-memory.* Per-user, not committed to the repo. The conventions are project-wide and must travel with the source tree.
- *AGENTS.md alone.* Already loaded but covers many topics; the conventions risk being skimmed past.

Path-scoped rules are the narrow tool: fire exactly when relevant, stay invisible otherwise.

### Decision 3: Rule file is a pointer, not a copy

`.claude/rules/openspec-specs.md` says "read `openspec/specs/spec-conventions/spec.md` before editing here" and lists the section headings as a tease. The full content lives in the spec. This keeps a single source of truth and lets human contributors (who don't load Claude rules) find the same content via the spec directory.

### Decision 4: Granularity threshold is advisory, not numeric-cliff

The conventions specify a soft threshold (~40 lines, single requirement → fold into parent) rather than a hard rule. Some short specs are deliberately small (e.g. a contract spec stating a single invariant the rest of the system depends on). The decision case-by-case is the reviewer's; the threshold is a prompt to consider it.

### Decision 5: Buckets are taken as-found

The proposal does not invent new buckets. The four-layer model (Rules, Facts, Parsing, Trust) is documented in CONTEXT.md and corresponds to spec clusters that already exist. The supporting buckets (Tracing-and-Output, Migration, CLI, Testing, Contributor-Internals) emerge from current filing. The spec lists them so future authors know where to file, but does not re-architect.

### Decision 6: Trust-relevance is a Purpose-line declaration, not a separate field

A spec touching trust state declares "Trust-relevant: yes" in its Purpose section and cross-refs the trust-model spec. Alternative considered: a YAML frontmatter field. Rejected because the rest of the openspec format is markdown-headings-only and frontmatter introduces a parsing seam for tools that don't use it. A one-line convention is enforceable by grep and easy to spot in a diff.

## Open questions

- Should the conventions cover a *naming* policy for capabilities (kebab-case, no version suffixes, no `v2-` prefixes)? The current set has `v2-expr-fact-binding` which violates a reasonable rule. Defer to a follow-on if it bites.
- Should the spec require a cross-reference index (each spec lists its "see also" specs)? Useful for trust↔eval, parser↔tail, but adds maintenance burden. Leave as a soft recommendation in the first cut.
