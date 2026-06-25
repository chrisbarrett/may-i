## Why

Several prelude Carrier parsers are declared `(rest #cmd)` (or
`positional + rest`) with **no grammar for their value-taking option flags**.
Under `(flags posix)` an undeclared value-flag is consumed as if valueless, so
its argument — the next non-flag token — becomes the first token of `(rest)` and
is mistaken for the inner command. The real command then escapes all rule
coverage. This is security-relevant: evaluating `sudo -u postgres rm -rf /`
today recurses into a phantom command `postgres`, so a `(rule "rm" (deny …))`
never fires and the decision floors to `:ask` on a name that was never run.
`sudo -u`, `ssh -p`/`ssh -i`, and `env -u` are everyday invocations.

The one carrier that already declares its value-flag — `nice` (`-n`) — parses
correctly, which proves the fix: declare each Carrier's value-taking flags.

## What Changes

- Harden the prelude parsers for **sudo, env, ssh, ionice, chrt, strace, time,
  xargs** by declaring their value-taking option flags as `(parameter …)`, so the
  inner command is identified correctly and carrier rules recurse into the real
  target. `chrt` additionally gains a required `#priority` positional (the
  `timeout`-proven single-positional shape).
- **Ground every flag list in the tool's man page**, and cover **both the BSD
  (macOS) and GNU/util-linux (Linux) variants** as a union — a flag is declared
  value-taking only where it is value-taking on every platform it exists on, so a
  declaration never re-introduces a mis-parse on the other OS. Linux-only carriers
  (`ionice`, `chrt`, `strace`) are grounded in util-linux/strace docs.
- Land **integration tests** for the motivating invocations (`sudo -u USER rm`,
  `ssh -p 22 host rm`, `env -u VAR rm`, the `xcrun … swift test` shape) asserting
  recursion reaches the real inner command, with `nice` as the template.

Explicitly **out of scope** (each raised as its own change while dogfooding the
DSL):

- **env `NAME=VALUE` assignment prefix** (`env FOO=bar cmd`) — needs a quantified
  positional before `(rest)`, which currently breaks the `(rest)` binding (a
  parser-engine bug found here). env's value-flags are fixed now; the prefix waits
  on that fix.
- **su** — BSD `su` has no `-c command`; Linux `su -c CMD` does. The recursion
  target diverges by platform; needs its own design.
- **direnv `exec DIR cmd`** — the `DIR` between verb and command needs multi-slot
  positionals (same engine gap as the env prefix).
- **Absolute-path vs basename command identity** — `sudo /usr/bin/rm` does not
  match `(rule "rm")`; a security-model decision, not a parser fix.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `parser-bindings`: add requirements that the prelude's shipped Carrier parsers
  declare their value-taking option flags (so inner-command identification is
  correct), grounded in man pages and valid across BSD (macOS) and GNU (Linux)
  variants.

## Impact

- **Files**: `crates/config/src/prelude.lisp` (the eight hardened parsers).
- **Tests**: new integration tests under `tests/` for carrier recursion across the
  motivating commands; prelude-parse and `may-i fmt` round-trip remain green.
- **Behaviour**: carrier rules now recurse into the correct inner command;
  decisions that previously floored to `:ask` on a phantom name now reflect the
  real command's rule (e.g. `sudo -u USER rm -rf /` → `:deny`). No user-facing
  config syntax change; no migration-system entry.
- **No engine or DSL changes** in this change — prelude data only.
