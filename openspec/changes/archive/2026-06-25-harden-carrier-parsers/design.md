## Context

The prelude (`crates/config/src/prelude.lisp`) ships Carrier parsers so rules can
recurse into wrapped commands via `(authorise #cmd)`. Most are `(flags posix)`
with `(rest #cmd)` and no `(parameter …)` declarations. Under `posix`, flag
scanning stops at the first non-flag token; an undeclared value-flag (`-u`, `-p`,
…) is treated as valueless, so its argument is the first non-flag and lands at
`rest[0]` — read as the inner command name. Empirically (debug binary, this
session):

| invocation | inner command may-i sees | real command |
| --- | --- | --- |
| `sudo -u postgres rm -rf /` | `postgres` | `rm` (escapes deny) |
| `ssh -i key -p 22 host rm …` | `host` (and `#host`=`22`) | `rm` |
| `env -u SDKROOT rm …` | `SDKROOT` | `rm` |
| `ionice -c 2 rm …` | `2` | `rm` |
| `chrt -r 10 rm …` | `10` | `rm` |
| `strace -s 256 rm …` | `256` | `rm` |
| `time -o out rm …` | `out` | `rm` |
| `nice -n 5 rm …` | `rm` ✓ (declares `-n`) | `rm` |

`nice` is the existence proof: declaring the value-flag fixes recursion. After
declaring value-flags, `sudo -u postgres rm -rf /` → `:deny`, `ssh -i key -p 22
host rm` → `:deny`, `env -u VAR rm` → recurses to `rm` (all verified this
session).

## Goals / Non-Goals

**Goals:**

- Correct inner-command identification for the eight defective Carriers, closing
  the `sudo -u` / `ssh -p` bypass class.
- Every flag list grounded in the tool's man page; declarations valid on both
  macOS (BSD) and Linux (GNU / util-linux).
- Tests for the motivating invocations, `nice` as template.

**Non-Goals:**

- No engine or DSL changes — prelude data only.
- env's `NAME=VALUE` assignment prefix, `su`, `direnv exec DIR`, and absolute-path
  command identity — each is its own change (see Open Questions).
- Adding new Carriers not already in the prelude.

## Decisions

### D1: Declare value-flags as the union of BSD + GNU, verified per-flag

A flag is declared `(parameter …)` only if it is value-taking on **every**
platform where it exists. This avoids the inverse mis-parse: declaring a flag
that is valueless on, say, macOS would make `tool -x operand` swallow `operand`
as `-x`'s value there. Platform-exclusive value-flags (BSD `env -P`, GNU
`env --chdir`) are safe to include because the other platform never emits them.
Grounded against the macOS man pages (read this session) and GNU/util-linux docs.

Per-carrier value-flags (short + long where applicable):

- **sudo** (identical cross-platform): `-C/--close-from`, `-D/--chdir`,
  `-g/--group`, `--host`, `-p/--prompt`, `-R/--chroot`, `-r/--role`,
  `-t/--type`, `-T/--command-timeout`, `-U/--other-user`, `-u/--user`.
  Short `-h` is **excluded**: it is overloaded (`-h` alone = help,
  `-h host` = host), so declaring it value-taking would let `sudo -h rm`
  swallow `rm` (violates the scenario-6 inverse-mis-parse rule). The
  unambiguous long `--host` is declared instead.
- **env**: BSD `-u -C -P -S`; GNU `--unset --chdir --split-string`
  (`-S` = BSD split / GNU `--split-string`; `-C` = BSD altwd / GNU chdir).
- **ssh** (OpenSSH, identical): `-b -c -D -E -e -F -I -i -J -L -l -m -O -o -p -Q
  -R -S -W -w`. Keep `(positional #host (regex "^[^-].*")) (rest #cmd)`.
- **ionice** (Linux): `-c/--class -n/--classdata -p/--pid -P/--pgid -u/--uid`.
- **chrt** (Linux): value `-T/--sched-runtime -P/--sched-period
  -D/--sched-deadline`; plus required `#priority` positional, then `(rest #cmd)`.
- **strace** (Linux): existing `-e -p -o` plus `-s -E -a -O -S -u -P -b -I`
  (long: `--string-limit --env --username` …).
- **time**: BSD `-o`; GNU `-o/--output -f/--format`.
- **xargs**: existing `-n -I -L -P -d`; add `-s/--max-chars`, BSD `-J -R -S`,
  GNU `-a/--arg-file -E`. GNU `-e/--eof` is **excluded**: its eof-string
  argument is *optional*, so `xargs -e rm` treats `-e` as valueless and
  declaring it would swallow `rm` (scenario-6 inverse mis-parse). `-E`
  (mandatory arg on BSD and GNU) covers the value-taking case.

### D2: Only proven-safe DSL primitives

Use `(parameter …)`, single **required** positionals, and `(rest …)` — all of
which are exercised and working (`timeout`, `nice`, `ssh`). Do **not** use a
quantified (`*`/`+`) positional before `(rest)`: that combination currently
starves the `(rest)` binding (see Open Questions / DSL-A), so it cannot carry
env's assignment prefix in this change. `chrt`'s priority is a single required
positional, which is the `timeout` `#duration` shape and works.

### D3: Tests assert the recursion target, not just the decision

Each carrier test binds `(rule "<carrier>" (authorise #cmd))` + `(rule "rm"
(deny …))` and asserts `<carrier> <value-flags> rm -rf …` → `:deny`, proving the
inner command is `rm` and not the swallowed flag value. The gotracksuit
motivating shape (`env -u … /usr/bin/xcrun swift test …`) is included as a
realistic regression.

## Risks / Trade-offs

- **Over-declaring a flag that is valueless on one OS** → would cause the inverse
  mis-parse on that OS. Mitigation: D1's per-flag both-platforms rule; tests
  exercise representative BSD- and GNU-form invocations.
- **Long-form coverage under gnu style** → gnu `(separators " " "=")` means
  `--user=root` and `--user root` both parse once `user` is a declared parameter;
  verified by the parameter-binding semantics in `parser-bindings`.
- **Prelude shadowing** → user configs that redeclare these parsers silently
  shadow the prelude (last-wins); unaffected, but the hardening only helps configs
  that rely on the prelude parser.
- **`fmt` round-trip / trust hash** → prelude is parsed and may be pretty-printed;
  `may-i fmt` on the prelude and the existing prelude-parse tests must stay green.

## Open Questions

Raised while dogfooding the parser DSL — each to be its own change, landing the
concrete motivating prelude parser with the fix:

1. **DSL-A — quantified positional starves `(rest)`.** `(positional #v PAT *)`
   (or `+`) before `(rest #cmd)` leaves `#cmd` unbound even when the positional
   should match zero tokens (`env xcrun` with such a parser yields `(rule "env"
   nil)`). Blocks the env assignment-prefix and `direnv exec DIR cmd`. Likely a
   parser-engine bug; warrants a focused diagnosis.
2. **DSL-B — env `NAME=VALUE` prefix.** Depends on DSL-A. Until then
   `env FOO=bar rm …` reports `:ask "dynamic or malformed inner command name"` —
   fail-safe but `rm` escapes its rule.
3. **su platform divergence.** BSD `su` has no `-c command`; Linux `su -c CMD`
   does, and the recursion target differs. Own design.
4. **Absolute-path vs basename identity.** `sudo /usr/bin/rm` does not match
   `(rule "rm")`. Security-model decision, not a parser fix.
