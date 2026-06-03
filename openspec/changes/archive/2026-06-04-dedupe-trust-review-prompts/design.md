## Context

`compute_trust_views` in `crates/engine/src/trust.rs:328` emits one `TrustViewMeta` per `(rule, program)` pair. Because `canonical_rule` (`crates/engine/src/trust.rs:123`) stringifies the entire rule expression — including any OR-of-programs pattern — two views derived from the same rule share both `hash` and `canonical_form` text. They differ only in the contributor-only `program` and `position` fields.

`build_pending` in `src/interactive.rs:188` maps catalog views 1:1 to `PendingRule`s. `run_review` in `src/trust/review/review_loop.rs:96` iterates the resulting slice linearly. The user therefore sees a byte-identical prompt body once per program alternative, and must keystroke an answer once per duplicate. The trust store dedups on hash (`src/trust/store.rs:206` — `BTreeMap<String, RuleEntry>`), so persistence is correct, but the prompt sequence is not.

Identical-form duplication also arises when the same rule text is loaded twice (one file, two `(load …)`s, or a textually repeated rule inside one file).

## Goals / Non-Goals

**Goals:**

- One prompt per unique canonical-form hash in the per-rule interactive review.
- One keystroke applies the decision to every view that shares the hash; no second prompt for the same form within a session.
- Behaviour parity for the non-duplicate case: existing snapshot tests, screen layout, progress counter `n/total`, and trusted-summary line continue to render byte-identically when no duplicates exist.
- Listing, JSON output, batch approval, integrity repair, and the trust gate are untouched.

**Non-Goals:**

- Changing `compute_trust_views`'s output shape. Engine-level position tracking and the `(rule, program)` granularity are load-bearing for tracing and advisory rendering elsewhere.
- Collapsing approvals at the store layer. The store already dedups on hash; no schema change.
- Redesigning OR-of-programs canonicalisation or hash semantics — out of scope and a much larger change.

## Decisions

**Dedup at the review-loop boundary, not in the catalog.**

Place the dedup in `build_pending` (`src/interactive.rs:188`): when constructing the `Vec<PendingRule>` for `run_review`, drop entries whose hash has already been emitted, preserving first-seen order. `run_review` itself stays oblivious — the input contract becomes "unique by hash."

Rationale:
- Smallest blast radius. Catalog stays a faithful 1:1 join of engine output with store state; consumers that legitimately want the per-program granularity (gate filtering, advisory body, trust listing) keep their current data.
- Keeps the loop pure: `run_review` is already total over its input slice and unit-tested with a scripted prompt. No new dedup branch inside the loop.
- The `total` shown in the progress counter (`run_review` at review_loop.rs:91) becomes the count of *unique* forms, which is what the user expects ("3 rules pending" rather than "3 rules pending across 7 program names").

Alternative considered: dedup inside the catalog (`TrustCatalog::iter_unique_by_hash` or similar). Rejected — would either fork the catalog API or quietly drop information for other consumers; the contributor-facing data shape is still useful upstream.

Alternative considered: dedup inside `compute_trust_views`. Rejected — the engine emits per-program metadata deliberately so that tracing and the per-rule advisory body can address a specific program; collapsing there ripples through trust-store integrity checks and listing.

Alternative considered: dedup downstream in `run_review` itself (skip if the current rule's hash is already in `ops`). Rejected — couples the loop to its own emission history and makes the unit tests less clean; the data-shape fix lives one layer up.

**Fanning the decision across all hash-equal views.**

After `run_review` returns its `Vec<StoreOp>`, the existing application loop in `src/interactive.rs:117-124` projects each op onto the catalog. Because the catalog still holds N views per duplicated rule, applying one `ApproveRule { hash, .. }` op via `TrustCatalog::set_state` updates every view with that hash (see `src/trust/view.rs:115` — `set_state` finds by hash, but only updates one). That's the second bug: only the first view flips to Approved; the rest stay Pending until the next run.

Fix: change `TrustCatalog::set_state` to update *every* view matching the hash (a `for v in self.views.iter_mut().filter(|v| v.hash == hash)` rather than `find`). The store-side mirror call remains a single insert — the store is hash-keyed, so re-inserting the same hash is idempotent and cheap.

Alternative considered: leave `set_state` as-is and have the dedup site track which hashes to flip externally. Rejected — `set_state` should be the authoritative mutation surface; quietly leaving stale views behind violates the invariant that catalog state mirrors store state for every view.

**Where the change lands.**

- `src/interactive.rs::build_pending` — dedup pending entries by hash, preserve first-seen order.
- `src/trust/view.rs::set_state` — fan the state change across all views with the matching hash.
- `src/trust/review/review_loop.rs` — no change; existing unit tests assert per-snapshot behaviour and remain valid.

## Risks / Trade-offs

- Risk: The advisory body and trust listing rely on per-program views. → Mitigation: the catalog is unchanged; only the *review prompt* input is deduped. Listing (`list_status_human`, `print_trusted_summary`) iterates the catalog directly and keeps its multi-program rendering.
- Risk: `position`-based diff detection (`detect_change` in `src/interactive.rs:281`) reads `prev_form` at the view's position. Dedup drops later views, so the kept view's `position` is the first one seen for that hash — currently 0 in the typical OR case. → Mitigation: acceptable; if the canonical form is duplicated across programs, the diff is the same too. Document this in the dedup site.
- Risk: Snapshot tests that depend on `total` reflecting the pre-dedup count. → Mitigation: there are no snapshot tests on the live `n/total` label today (only assertions in `run_review_*` unit tests, which build their own fixtures). New tests will assert the deduped count.
- Trade-off: A user who *wants* to see each program name acknowledged separately for an OR rule no longer sees that in the review prompt. This is a behaviour change but matches the user's stated expectation (one form = one prompt). If we later want to surface "approved for these N programs" feedback, it belongs in the post-review summary rather than the per-rule loop.
