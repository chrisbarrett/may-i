## Context

The `DisplaySafe` newtype (commit `1f79f79`) closed one field — `EvalResult.reason` —
against control-character injection, but its own commit message flags the gap:
the `--trace` TTY surface still renders input-derived `TraceEntry`/`TraceNode`
text unescaped. The root cause is structural: the `may-i-output` `Layout` DSL is
built on raw `String`, and those strings legitimately carry our own ANSI (which
is exactly why `strip_ansi`/`visible_len` exist). The compiler therefore cannot
tell our declarative styling from an `\x1b` an adversary embedded in a command
name parsed out of the command under evaluation.

Crate dependency graph (relevant edges): `core` is the shared leaf;
`pp → core`; `may-i-output → pp → core`; `engine → core` (sibling of
`may-i-output`, neither depends on the other); `config → core`; the binary
depends on all. `DisplaySafe` lives in `engine`. `colored` is depended on by
~20 files across the binary, `pp`, and `may-i-output`. Output reaches the TTY
through two fronts: the structured `write_layout` path (trace/check/eval/
advisory) and a sprawl of ~50 `print*!`/`stdout()`/`stderr()` sites in `cmd_*`
and `config`, plus the miette error path (`{e:?}`).

## Goals / Non-Goals

**Goals:**

- Make user-controlled ANSI/SGR reaching a process stream **unrepresentable by
  construction** — a type-level guarantee, not a per-site escape discipline.
- One escaping choke point per escape semantics, in `core`, shared by the Reason
  path and the Layout DSL.
- Move ANSI from embedded strings to declarative `Style` roles, so the renderer
  is the sole `\x1b` emitter.
- Funnel every process-stream write through one sink that accepts only
  escape-safe input, and enforce it with compiler facts + lints, not review.
- A falsifiable runtime proof (colour-off proptest) that backstops the types.

**Non-Goals:**

- Changing rendered output for benign input. Bytes are unchanged except that
  control characters in input-derived text are now escaped.
- The visible-width *algorithm* (`chars().count()` vs `unicode-width`) — a
  pre-existing question left untouched here.
- Any user-facing config syntax change; no migration-system entry.
- Sandboxing, execution, or any concern outside terminal output.

## Decisions

### D1: Full color-as-data, not a newtype'd pre-coloured blob

`Layout` leaves hold `SafeText` content + a closed `Style` role enum; the
renderer maps role→SGR at one site. **Alternative rejected:** wrap today's
pre-coloured `String` as `Rendered(String)` with a sanitising builder — cheaper,
but any `Rendered::from_raw` re-opens the hole, so "only `Style` emits ANSI"
stays a convention, not a compiler fact. Only color-as-data makes input ANSI
unrepresentable. Falsifiable signal: `strip_ansi`/`visible_len` and the explicit
width fields become dead and are deleted; their survival would mean a string
still carries its own styling.

### D2: Escape choke points live in `core`; two of them

`SafeText` (control-escaping, **expanding** — `escape_default`) and `SafeSource`
(control→placeholder, **length-preserving**) both live in `may-i-core`, the leaf
both `engine` and `may-i-output` already depend on. `engine::DisplaySafe` becomes
an alias/re-export of `SafeText`. **Alternative rejected:** keep the type in
`engine` or `may-i-output` — either forces a backwards `output → engine` (or
`engine → output`) dependency edge, or duplicates the escaper. Two types, not
one, because the spanned-source surface (miette) is addressed by byte offsets:
`SafeText`'s expansion (`\x1b` → 4 bytes) shifts every offset and misaligns span
underlines, whereas `SafeSource` replaces each control byte 1→1 so offsets stay
valid.

### D3: Style is a closed set of semantic roles, not structural colour

`Style` enumerates roles (keyword, string-literal, form-head, dimmed, heading,
match-hit, match-miss, …), mirroring what `colorize_atom` already does
(content-class → colour). The renderer owns the role→SGR palette and the single
`NO_COLOR`/`--color` branch. **Alternative rejected:** a structural
`(Color, attributes)` representation — it scatters palette decisions back to call
sites, the exact sprawl being removed. Roles are added only when a surface needs
one; never a raw colour.

### D4: One sink, accepting Layout / SafeText / serialisable-JSON

A single module acquires `stdout`/`stderr` and exposes `layout(&Layout,
&Terminal)`, `line(SafeText)`, and `json(&impl Serialize)`. **Alternative
rejected:** `Layout`-only — forcing every `eprintln!("error: …")` into a Layout
tree is scope-balloon for no safety gain; the invariant only needs each entry
type to be escape-safe. JSON is ANSI-safe by serialisation (serde escapes control
bytes to `\uXXXX`).

### D5: miette is trusted on sanitised input

Rather than treat miette as an untrusted renderer, sanitise everything it
ingests: the one spanned source (`shape_diag`) is `SafeSource`-wrapped;
input-derived `miette!` interpolations are `SafeText`-wrapped; a rendered
`Report` reaches a stream only through the sink. miette then emits only its own
(trusted) SGR over escape-free content. **Alternative rejected:** disabling
miette colour and routing plaintext — loses miette's diagnostics value, and still
needs the source sanitised to be safe.

### D6: The gate is a compiler fact first, a lint second

The strongest enforcement of "only the renderer emits ANSI" is removing `colored`
from every crate except `may-i-output` — an inline `.red()` elsewhere then fails
to compile. On top: `clippy::print_stdout`/`print_stderr`/`dbg_macro` denied
workspace-wide with the sink as the sole allow site, and a prek grep banning
stream-handle acquisition (which clippy's macro lints miss, e.g.
`writeln!(stderr(), …)`). The gate lands **last** within the change — after the
sink and role migration — or it is a wall of errors before the call sites move.

### D7: Two-phase migration inside one change

Phase 1 seals the adversary-eval path (trace/check/eval/advisory + miette):
`SafeText`/`SafeSource`, color-as-data `Layout`, role renderer, single sink, then
the gate. Phase 2 folds `pp`/`fmt`/`migrate` off `colorize_atom → String` onto
roles, removing `colored` from `pp` last. `pp` is lower-severity (operates on
user-passed files) so it trails, but ships in the same change so no
inline-ANSI island is left behind.

## Risks / Trade-offs

- **Snapshot churn / byte drift** → Benign-input snapshots are unaffected
  (escaping is a no-op on control-free text), so the `output-rendering`
  "Rendered output bytes are unchanged" requirement still holds for its fixtures.
  Only fixtures that contain control characters need re-baselining; audit
  snapshot inputs before regenerating.
- **miette span misalignment** → The single subtle correctness point. `SafeSource`
  must be exactly length-preserving (1 control byte → 1 printable byte, equal
  UTF-8 byte length). A property test asserts byte-length equality and span
  in-bounds-ness.
- **Width-field removal regressions** → Layout maths currently trusts
  caller-supplied widths. Computing width in the renderer can drift on wide/
  zero-width Unicode, but that bug pre-exists `visible_len` (which also counted
  chars); the colour-off snapshot tests guard alignment.
- **Large blast radius** → Touches `core`, `may-i-output`, `engine`, `pp`, and
  every `cmd_*`. Mitigation: land in the D7 order with the gate last, keeping the
  tree compiling at each step; the colour-off proptest gates the seal.
- **Incomplete sink funnel** → A stray `eprintln!` in a non-output crate (e.g.
  `config`'s load-time warnings) would breach the single-sink claim. The clippy
  deny + prek grep are workspace-wide precisely to catch these; the migration
  must route `config`/`cmd_fmt` diagnostics through the sink (a typed advisory
  channel) rather than ad-hoc strings.

## Migration Plan

1. `may-i-core`: add `SafeText` (move/generalise `DisplaySafe`) and `SafeSource`
   with proptests (no-control, idempotent, offset/length-preserving).
2. `engine`: re-alias `DisplaySafe` to `SafeText`; no behaviour change.
3. `may-i-output`: introduce `Style` roles; convert `Layout` leaves to
   `SafeText` + `Style`; delete width fields and `strip_ansi`/`visible_len`;
   move the role→SGR + colour-enable decision into the renderer.
4. Build the single sink module (owns `stdout`/`stderr`; `layout`/`line`/`json`).
5. Migrate `src/output/*` builders and every `cmd_*`/`config` print site through
   the sink; sanitise miette input (`SafeSource` for `shape_diag`, `SafeText` for
   `miette!` interpolations).
6. Add the colour-off / colour-on proptests over the render surfaces.
7. **Gate (last):** remove `colored` from bin/`config`/(then `pp`); add the
   clippy denies with the sink allow; add the prek grep.
8. Phase 2: fold `pp`/`fmt`/`migrate` onto roles; remove `colored` from `pp`.

Rollback: the change is internal; reverting the commit restores the prior
surface. No persisted state or user config is touched.
