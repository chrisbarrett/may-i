## Context

The `may-i trust` interactive review exists in two forms: a legacy program-level flow (`interactive_approve` using `dialoguer::Confirm`) and a per-rule flow (`interactive_review` using `console::Term` with `y/n/s/q`). The `list_status` path dumps all rules then offers to enter the legacy flow. Neither flow clears the screen between items, and both display canonical forms as flat single-line strings.

The pretty-printer (`may_i_pp`) already handles indented rendering with proper indent specs for `rule`, `when`, `cond`, etc. It operates on `Doc` trees. A `doc_from_sexpr` conversion function exists in the pp crate but is gated behind `#[cfg(test)]`.

## Goals / Non-Goals

**Goals:**
- One rule at a time on a cleared screen, like `git add -p`.
- Pretty-printed forms everywhere users see canonical rule text.
- Progress counter and trusted summary for context.
- Minimal changes — reuse existing `interactive_review` and pp infrastructure.

**Non-Goals:**
- Annotation-aware rendering (no eval happening, plain `Doc<()>` suffices).
- Source trivia preservation (canonical forms have no trivia).
- Changes to non-interactive or JSON output paths.
- Changes to the trust store format or trust hashing.

## Decisions

### 1. Pretty-print via parse→Doc→pretty at display time

Canonical form strings are parsed back into `Doc` trees for pretty-printing. The chain: `may_i_sexpr::parse(form) → doc_from_sexpr(&sexpr) → may_i_pp::pretty(&doc, ...)`.

**Why not thread Docs through the trust pipeline?** The eval pipeline's Doc production is tightly coupled to `TracingFold` — it builds annotated `Doc<Option<Ann>>` trees as a byproduct of rule evaluation, with span tracking, pre-migration doc preservation, and trivia-guided layout. None of that applies here. Canonical forms are clean s-expressions with no trivia, no spans, no annotations. Parsing them is trivial and the pp crate already knows how to indent them.

**Why not complete `Effect::to_doc()` for all variants?** It currently returns placeholders for most variants. Completing it would be a large change orthogonal to this work, and canonical forms already exist as valid s-expressions.

**Alternative:** Render flat and rely on terminal width. Rejected — complex rules with nested `when`/`cond` are unreadable on one line.

### 2. Make `doc_from_sexpr` public in the pp crate

The function already exists at `crates/pp/src/lib.rs` behind `#[cfg(test)]`. Remove the gate, make it `pub`. It's 6 lines with no dependencies beyond `may_i_sexpr::Sexpr` and `may_i_core::Doc`, both already public.

**Alternative:** Duplicate the conversion in the CLI crate. Rejected — the pp crate is the natural home for Sexpr→Doc conversion.

### 3. Add a `pretty_form` helper in the CLI

A small function wrapping the parse→Doc→pretty chain, located in `src/interactive.rs` (or extracted to a shared module if needed elsewhere). Signature:

```rust
fn pretty_form(canonical: &str, width: usize, color: bool) -> String
```

All display sites call this instead of using `canonical_form` directly.

### 4. Screen clearing with `console::Term::clear_screen`

Before rendering each rule in `interactive_review`, call `term.clear_screen()`. The `console` crate (v0.15, already a dependency) provides this. After clearing, re-render the trusted summary line and progress HRule so context is always visible.

### 5. `list_status` skips dump when interactive + pending

Current flow: dump everything → ask "Review?" → legacy approval. New flow: when interactive with pending rules, go straight into `interactive_review`. After review, show the trusted summary (grouped-by-file listing for approved entries). Non-interactive and JSON paths are unchanged.

### 6. Pretty-printed diffs

For CHANGED rules, both old and new forms are pretty-printed before diffing. The existing `similar::TextDiff` operates on the pretty-printed multiline strings. Each diff line gets `+`/`-` prefixes with red/green coloring, matching the existing `render_diff` pattern.

### 7. Progress via HRule label

Use the existing `Layout::HRule` with a label: `──── Rule 3/15 ── NEW ──`. This matches the design language used for segment headers in trace output. The badge (NEW/CHANGED) is colored as it is today (yellow/red).

## Risks / Trade-offs

- **Parsing canonical forms adds overhead** → Negligible. Canonical forms are small (typically <200 chars), and this runs at human-interaction speed. No measurable impact.
- **`doc_from_sexpr` becomes public API** → Low risk. It's a trivial conversion with a clear contract. The pp crate already exports `pretty` and `Format`.
- **Screen clearing may lose context** → Mitigated by always showing the trusted summary line and progress counter at the top of each screen.
- **Legacy `interactive_approve` becomes unused** → It's still called from `approve_one` and `approve_all`. Can be cleaned up in a follow-up if desired, but no urgency.
