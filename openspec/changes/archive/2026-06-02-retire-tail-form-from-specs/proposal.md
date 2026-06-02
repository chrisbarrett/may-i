## Why

The parser-body form `(tail (after …))` retired in code — `crates/config/src/parser_form.rs:167-175` rejects it at config-load with a migration hint pointing to `(flags MODE) (rest #cmd)`. Yet `openspec/specs/parser-bindings/spec.md:595,707` still lists it among the recognised parser-body declaration kinds and uses it in a load-time scenario. A reader of the spec would expect `(parser "sudo" (style gnu) (tail (after :flags)))` to load, then hit the rejection at runtime. Aligning the spec with the loader closes that gap.

Two things are explicitly NOT retired and stay out of scope:

- Rule-body `(tail (authorise))` — still valid; parses to `ArgPattern::Tail` via `crates/config/src/pattern.rs:279-303`; produced by current migrations.
- The canonicaliser's sort slot for legacy `(tail …)` — `crates/config/src/canonicalise.rs:13-17` keeps it last "during the migration window" so v1→v2 pretty-printing stays stable. `pretty-printing/spec.md`'s canonical-sort requirement matches that behaviour and stays as-is.

## What Changes

- `parser-bindings/spec.md` — remove `(tail …)` from the recognised parser-body declaration kinds list (line 595); add a scenario covering the loader's rejection of the legacy form. Rewrite the "Authorise inside tail" scenario (line 707) to use `(flags posix) (rest #cmd)` instead of `(tail (after :flags))`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `parser-bindings`: remove `(tail …)` from the recognised parser-body declaration kinds and document the loader's rejection. The retirement is already enforced by `parser_form.rs:167-175`; the spec needs to catch up.

## Impact

- One stable spec (`parser-bindings`) gets a delta updating two requirement blocks.
- No code, runtime, DSL surface, migration, trust-hash, or pretty-printing impact — the loader already rejects the retired form, and the canonicaliser still handles the legacy shape during migration.
- Rule-side `(tail (authorise))` references across `traces/spec.md`, `facts/spec.md`, `migration-system/spec.md`, and `parser-bindings/spec.md` lines 694/715 remain unchanged.
