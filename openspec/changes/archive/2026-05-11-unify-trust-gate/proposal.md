## Why

Trust orchestration is smeared across three CLI commands (`cmd_eval`, `cmd_check`,
`cmd_claude_code_hook`). Each loads the trust store, decides whether to render
an advisory or emit a JSON block, extracts the program name, and filters
untrusted rules — with subtle per-mode differences. Program-name extraction is
literally duplicated in `cmd_eval.rs` and `cmd_claude_code_hook.rs`. Adding a
new mode (audit, dry-run) or changing what "blocking on untrusted" means
requires editing three places that must stay in sync.

The seam today is two adapter modules (`trust_advisory`, `trust_store`) meeting
at the caller. Apply the deletion test: removing either module's surface
helpers reveals the same orchestration code reappearing in three CLI commands
— the seam is shallow.

## What Changes

- **New module** `src/trust_gate.rs` exposing one entry point that takes the
  loaded `Config`, the command being evaluated, and a `GateMode` (text / json /
  hook), and returns a `GateOutcome`:
  - `Proceed { config, advisory: Option<Layout> }` — untrusted rules already
    filtered; advisory pre-built (or `None` if not text mode / nothing to warn
    about).
  - `Block { reason, files, decision }` — caller serialises in its own response
    shape; the gate has already decided that the command must be blocked.
- **Move into the gate**:
  - Trust store loading (currently `default_trust_store_path()` +
    `TrustStore::load` repeated three times).
  - Program-name extraction from a command string (currently duplicated in
    `cmd_eval.rs:249-261` and `cmd_claude_code_hook.rs:138-149`).
  - Untrusted-rule filtering (`trust_advisory::filter_trusted_rules`).
  - Advisory note construction for text mode (`trust_advisory::render`,
    currently producing a side-effecting render; will return a `Layout`
    instead).
- **Caller shape after**: each of `cmd_eval`, `cmd_check`,
  `cmd_claude_code_hook` calls `trust_gate::evaluate(&config, command, mode)`
  once, then either proceeds with the returned filtered config + writes the
  optional advisory, or serialises the block in its mode-appropriate shape.
- **Internal modules** `trust_advisory.rs` and `trust_store.rs` keep their
  current responsibilities but become implementation details of the gate;
  their helpers are no longer called directly from CLI commands. (Direct
  access from `cmd_trust` for trust-store administration is preserved.)
- **Tests**: gate behaviour tested directly as a unit (per `GateMode`,
  fabricated configs and trust stores), removing the need to test trust
  orchestration through three CLI integration paths.

## Capabilities

### New Capabilities

- `trust-gate`: single entry-point through which CLI commands consult Trust
  before evaluating a command — owns store lookup, program-name extraction,
  untrusted-rule filtering, and advisory/block construction per mode.

### Modified Capabilities

- None. This change is a refactor: external behaviour (text advisory boxes,
  JSON block shape, hook block shape, filtered-config evaluation semantics)
  is preserved exactly. Existing specs (`trust-block-context`,
  `trust-advisory-boxes`, `trust-provenance`, `per-rule-trust`) describe
  *what* happens; the gate is the *where*.

## Impact

- `src/trust_gate.rs` — new.
- `src/cmd_eval.rs` — replace ~40 lines of trust orchestration with one
  `trust_gate::evaluate` call per output mode.
- `src/cmd_check.rs` — replace `trust_advisory::render` call with gate.
- `src/cmd_claude_code_hook.rs` — replace `check_trust` (lines 123-186) and
  the filter block (lines 39-44) with gate.
- `src/trust_advisory.rs` — `render()` becomes `build_layout() -> Option<Layout>`
  (no side effects); `compute()` and `filter_trusted_rules` stay but become
  `pub(crate)` to the gate.
- `src/trust_store.rs` — unchanged.
- `src/lib.rs` — export `trust_gate`; demote `trust_advisory` and
  `trust_store` to `pub(crate)` where the hook crate boundary allows.
- Tests — new `tests/trust_gate.rs` (or unit tests in module) covering each
  `GateMode`. Existing integration tests continue to pass unchanged.
