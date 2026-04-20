## Context

The trust system gates evaluation of rules from `(load ...)` files behind user approval. Currently `Provenance` is a unit enum (`PrimaryConfig | Loaded`) with no file path, `TrustHashes` discards canonical forms after hashing, and the trust store only persists hashes. This means no component in the pipeline has enough data to tell the user *what* they're trusting or *where* it came from.

The layout crate provides `Layout::Columns`, `Layout::Note`, `Layout::Text`, and `Layout::Stack` primitives already used by trace and check output. The trust UI should use the same primitives.

## Goals / Non-Goals

**Goals:**
- Users can see which files contribute untrusted rules and what those rules say before approving.
- Changed rules show a diff against the previously-trusted version.
- The `may-i trust` listing groups information by file for scannability.
- Block messages (eval + hook) name the source files involved.
- JSON output includes all metadata for programmatic consumption.

**Non-Goals:**
- Syntax-aware structural diffing of rule s-expressions. Line-level diff of canonical forms is sufficient.
- Showing rule content inline in the hook block response (JSON reason string stays short; detail available via `may-i trust`).

## Decisions

### 1. Provenance carries PathBuf

`Provenance::Loaded { path: PathBuf }` instead of unit variant. Every `expand_loads` call already knows the file path — thread it through.

**Alternative**: Separate side-table mapping spans to file paths. Rejected — provenance is the natural carrier and avoids a second data structure.

### 2. Trust store format: versioned with canonical forms

New format:
```json
{
  "version": 2,
  "programs": {
    "git": {
      "hash": "sha256:...",
      "rules": ["(rule \"git\" (effect :allow))"]
    }
  }
}
```

Backward compat: if top-level has no `"version"` key, treat as v1 (flat `{program: hash}`), migrate in-memory, write v2 on next save. No explicit migration command needed.

**Integrity**: The hash is the source of truth. Stored canonical forms are untrusted display metadata. On load, each entry's forms are re-hashed using the same algorithm as `compute_trust_hashes` (join with `\n`, SHA-256). Entries that pass verification load normally. Entries that fail are flagged as *suspect*.

### 2a. Interactive integrity repair

When suspect entries are detected, `may-i trust` gates all operations behind an interactive repair session. This prevents a tampered trust store from poisoning diff output.

**Flow:**
1. `TrustStore::load` returns both the store and a `Vec<SuspectEntry>` (program name, stored hash, unverified forms).
2. If suspects exist and the session is interactive (TTY on stdin, no `--json`), `cmd_trust` enters repair mode before the requested operation.
3. For each suspect entry, display: program name, stored hash, the stored (unverified) forms.
4. User chooses per-entry: **re-approve** (re-hash the stored forms → new hash, keeping the forms) or **drop** (remove entry entirely, program becomes NEW on next check).
5. Save the repaired store, then proceed with the originally requested operation.

**Non-interactive fallback**: In hook mode, piped stdin, or `--json`, skip repair. Treat suspect forms as unavailable (empty). Emit a stderr warning directing the user to run `may-i trust` interactively.

**Interactive prompting**: Use `dialoguer` for the per-entry confirm/select prompt (already common in Rust CLI tools). If not already a dependency, it's small and well-maintained. Alternative: raw stdin line reading, but `dialoguer` handles TTY detection and gives a consistent UX.

**Alternative considered**: Silent discard of tampered forms. Rejected — user should know their trust store may have been modified by another tool, and should explicitly decide whether to accept or reject the stored forms.

**Alternative**: Store forms in a separate file. Rejected — single file is simpler and the data is small.

### 2b. Interactive approval for trust operations

Trust approval (`may-i trust --all`, `may-i trust <program>`) becomes interactive when on a TTY. Instead of blindly writing hashes, the system walks the user through each pending entry.

**Flow for `may-i trust --all`:**
1. Collect all NEW/CHANGED entries.
2. For each entry, display: program name, status badge, source file(s), canonical rule forms. For CHANGED, also show the diff against previously-trusted forms.
3. Prompt: approve or skip.
4. Approved entries are written to the store. Skipped entries remain pending.
5. Save store after all entries are processed.

**Flow for `may-i trust <program>`:**
Same as above but for a single entry. Display detail, prompt confirm.

**Flow for `may-i trust` (no args):**
Show the listing (grouped-by-file for trusted, detail for pending). If pending entries exist, offer to walk through them for approval.

**Non-interactive fallback:** When stdin is not a TTY or `--json` is set, approve without prompting (preserves existing batch behavior for scripts and CI). This ensures `may-i trust --all` in a pipeline still works.

**Shared interactive primitive:** Both integrity repair (section 2a) and approval use the same pattern: display entry detail, prompt per-entry action. Factor into a shared `interactive_review` function that takes a list of entries and action choices, returns user decisions.

**Interactive prompting library:** Use `dialoguer` for TTY-aware prompts. Gives consistent UX (select/confirm), handles raw mode, and is lightweight.

### 3. TrustHashes expanded with ProgramMeta

```rust
pub struct ProgramMeta {
    pub hash: String,
    pub canonical_rules: Vec<String>,
    pub source_files: BTreeSet<PathBuf>,
}

pub struct TrustHashes {
    pub programs: BTreeMap<String, ProgramMeta>,
}
```

`compute_trust_hashes` already builds canonical strings and iterates rules — retain them instead of discarding.

### 4. Trust listing layout

**All trusted**: Group programs by source file, two-column packed layout using `Layout::Columns` with `ColContent::Breakable` for program names.

```
  echo, cat, ls                ~/rules/basics.lisp
  git, gh                      ~/rules/vcs.lisp

  All trusted.
```

**Untrusted entries exist**: Use `Layout::Note` (warn level) containing a `Layout::Stack` of per-program detail blocks. Each block shows: program name + status badge + file path, then indented rule forms. For CHANGED, show line-level diff with `-`/`+` prefixes (red/green).

### 5. Diff rendering

Simple line-by-line diff of canonical rule strings (one rule per line). Use the `similar` crate's `TextDiff` for unified diff hunks — it's lightweight and already commonly used. If not already a dependency, add it; otherwise hand-roll a basic LCS diff since the inputs are small (typically 1-5 lines per program).

**Alternative**: Shell out to `diff`. Rejected — adds process overhead and platform dependency.

### 6. Block message includes file paths

Eval block message changes from:
```
Loaded config rules for 'echo' need trust approval. Run: may-i trust "echo"
```
to:
```
Untrusted rules for 'echo' (from ~/rules/basics.lisp). Run: may-i trust "echo"
```

Hook JSON adds `untrustedFiles` to the reason but keeps `permissionDecision` as `"ask"`. The reason string includes file paths. Structured file list goes in JSON trust listing, not in the hook response (to avoid breaking hook consumers).

## Risks / Trade-offs

- **Trust store format change** → Old may-i reading new store will see unknown keys and `serde_json` will fail or ignore. Mitigation: v1→v2 is forward-compatible (old binary ignores unknown fields via `#[serde(flatten)]`... actually it won't since the new format nests objects). Mitigation: the store path doesn't change; old binaries will error on load and re-create from scratch, which is safe (just re-prompts trust approval). Acceptable since this is pre-1.0.
- **PathBuf in Provenance increases struct size** → Minimal concern; rules are few (tens, not thousands). Could use `Arc<Path>` if needed later.
- **Adding `similar` crate** → Small dependency. Check if it's already transitive. If not, it's ~15KB and well-maintained. Alternatively, for the small inputs here, a simple longest-common-subsequence on lines is trivial to hand-roll.
