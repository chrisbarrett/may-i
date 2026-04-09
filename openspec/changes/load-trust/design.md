## Context

The `(load ...)` directive splices external config files into the main config at
the IO layer. Currently all loaded forms are treated identically to forms in the
primary config — there is no trust boundary. The `binding-environment` change
(prerequisite) introduces a runtime binding env for defines, giving us AST nodes
to hang provenance metadata on.

The user's config uses regex in arg patterns extensively but not in command
dispatch — the only regex command pattern is in a comment. Removing
`CommandPattern::Regex` makes program names enumerable, which is required for
per-program trust hashing.

## Goals / Non-Goals

**Goals:**

- Loaded rules/defines are tagged with provenance at load time
- Per-program trust hashing for programs that have any loaded content
- Persistent trust store with approve/reject workflow
- `safe-env-vars` from loaded files has its own trust scope
- `CommandPattern::Regex` removed to make program set decidable
- Users can review and approve via `may-i trust`

**Non-Goals:**

- Per-file trust tracking (trust is per-program-closure, not per-source-file)
- Trust UI beyond a CLI subcommand (no interactive TUI, no GUI)
- Revoking trust for primary config content (always trusted)
- Granular per-rule approval (trust is per-program)

## Decisions

### 1. Provenance as an enum on Rule and Define

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provenance {
    PrimaryConfig,
    Loaded,
}
```

Added to both `Rule` and `Define`. Set during load expansion in `io.rs` — forms
from the root file get `PrimaryConfig`, forms from `(load ...)` targets get
`Loaded`.

**Why:** Simple, sufficient. No need for file paths or more granular tracking —
the trust boundary is binary (your config vs external).

**Alternative:** Track source file path per form. Rejected — adds complexity
with no user-facing benefit since trust is per-program, not per-file.

### 2. Trust hash is per-program, over the resolved closure

For each program name P with any `Loaded` rule or referencing any `Loaded`
define:

1. Collect all rules whose `command_effect` mentions P (both provenances)
2. Preserve config order (first-match-wins is order-dependent)
3. Resolve defines to compute the full predicate trees
4. Canonically serialize the resolved rules
5. SHA-256 hash the serialization

The hash covers the full closure (both provenances) because evaluation order
matters — a primary rule's position relative to a loaded rule affects semantics.

**Why:** Per-program granularity means changing git rules doesn't invalidate
docker trust. Including both provenances in the hash ensures reordering is
detected.

**Alternative:** Hash only the loaded rules. Rejected — interleaving a loaded
rule between two primary rules changes first-match-wins semantics without
changing any individual rule.

### 3. Canonical serialization via the Doc pretty-printer

Reuse the existing `ToDoc` implementations to produce a canonical
s-expression string for hashing. Strip spans, normalize whitespace.

**Why:** `ToDoc` already exists for all AST types. Producing a deterministic
string from it is straightforward. Avoids implementing a separate `Hash` trait
on every AST node.

**Alternative:** Derive `Hash` on AST types. Rejected — fragile across
refactors (field additions silently change hashes) and requires `Hash` on
`regex::Regex` (which doesn't implement it). Since we're removing regex from
`CommandPattern` this is less of an issue, but `ToDoc` is still simpler.

### 4. Trust store as a JSON file

Store trust hashes in `~/.local/share/may-i/trust.json`:

```json
{
  "git": "sha256:abc123...",
  "docker": "sha256:def456...",
  ":safe-env-vars": "sha256:789..."
}
```

**Why:** Simple, human-readable, easy to debug. The file is small (one entry per
program). JSON is already a dependency.

**Alternative:** SQLite, individual files per program, or a binary format.
All overkill for a few dozen entries.

### 5. Blocking behaviour on trust mismatch

When a program's hash doesn't match the stored value, evaluation for that
program returns `ask` with a reason indicating trust needs approval. Exit code 2
(blocking error) is used in hook mode.

**Why:** Consistent with the existing "ask" fallback for unknown commands.
Exit code 2 is already the convention for blocking errors that get fed back to
Claude Code hooks.

### 6. safe-env-vars trust scope

`safe-env-vars` from loaded files gets a separate trust key (`:safe-env-vars`).
The hash covers the full merged `safe-env-vars` set (both provenances) when any
entry comes from a loaded file.

**Why:** `safe-env-vars` is a security boundary for information exposure, but
it's orthogonal to program closures. A separate key means changing
`safe-env-vars` doesn't invalidate program trust.

### 7. Remove CommandPattern::Regex

Remove the `Regex` variant from `CommandPattern`. The config parser rejects
regex in command position. Migration emits a warning for any v1 config using
regex commands.

**Why:** Regex command patterns make the program name set undecidable — you
can't enumerate which programs a regex matches. This blocks per-program trust
hashing. The feature is unused in practice (only appears in a comment in the
user's config).

## Risks / Trade-offs

- **[Risk] Breaking change: CommandPattern::Regex removal** — Any config using
  regex in command position will fail to parse. Mitigation: the feature is
  unused in practice. Migration emits a clear warning.
- **[Risk] Hash instability across versions** — If `ToDoc` output changes
  (formatting, field order), stored hashes become invalid and all programs need
  re-approval. Mitigation: document the canonical format; add a test that
  asserts hash stability for a reference config.
- **[Trade-off] Full closure hashing vs loaded-only** — Hashing the full
  closure means reordering primary rules relative to loaded rules triggers
  re-approval even though the user only changed their own config. Accepted
  because order affects semantics and the cost of re-approval is low.
- **[Trade-off] No TOFU** — First load of a file requires explicit approval.
  This is more secure than trust-on-first-use but adds friction. Accepted as
  the safer default; TOFU could be added later as an opt-in.
