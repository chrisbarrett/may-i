## 1. Ground the flag lists

- [x] 1.1 Confirm each carrier's value-taking flags against the macOS (BSD) man page and the GNU/util-linux docs; record the union and any platform-exclusive flags (per design D1). Union recorded in design D1; env verified against macOS man (`-u -C -P -S` value-taking, `-i -v` valueless).
- [x] 1.2 Note any flag that is value-taking on one platform but valueless on another (must NOT be declared) — expect none, but verify `env`, `time`, `xargs`, `ssh`, `sudo`. None found: env's value-flags (`-u -C -P -S`) are value-taking on BSD and have GNU long-form equivalents; remaining flags are clustered valueless (`-i -v`). Per design D1 the declared set is value-taking on every platform it exists on.

## 2. Harden the prelude parsers (TDD: failing test first per carrier)

- [x] 2.1 `sudo`: add value-params (`-C -D -g -h -p -R -r -t -T -U -u` + long forms). Test: `sudo -u USER rm -rf /` → `:deny`.
- [x] 2.2 `ssh`: add value-params (`-b -c -D -E -e -F -I -i -J -L -l -m -O -o -p -Q -R -S -W -w`), keep `#host` + `rest`. Test: `ssh -i key -p 22 host rm …` → `#host`=`host`, `:deny`.
- [x] 2.3 `env`: add value-params (BSD `-u -C -P -S` + GNU `--unset --chdir --split-string`). Test: `env -u VAR rm …` → `:deny`. (Assignment prefix is out of scope — see design Open Questions.)
- [x] 2.4 `ionice`: add value-params (`-c -n -p -P -u` + long). Test: `ionice -c 2 -n 0 rm …` → `:deny`.
- [x] 2.5 `chrt`: add value-params (`-T -P -D` + long) and a required `#priority` positional before `(rest #cmd)`. Test: `chrt -r 10 rm …` → `#priority`=`10`, `:deny`.
- [x] 2.6 `strace`: add value-params (`-s -E -a -O -S -u -P -b -I` + long) to the existing `-e -p -o`. Test: `strace -s 256 rm …` → `:deny`.
- [x] 2.7 `time`: add value-params (`-o` + GNU `-f --output --format`). Test: `time -o out.txt rm …` → `:deny`.
- [x] 2.8 `xargs`: add value-params (`-s`, BSD `-J -R -S`, GNU `-a -E -e` + long) to existing `-n -I -L -P -d`. Test: `xargs -s 1000 rm …` → `:deny`.

## 3. Motivating regression tests

- [x] 3.1 Add an integration test for the gotracksuit shape: `env -u SDKROOT DEVELOPER_DIR=… /usr/bin/xcrun swift test …` resolves the inner command to `xcrun` (path form) rather than a swallowed flag value or env var name. (Asserted via deny on the `/usr/bin/xcrun` path token — basename identity is out of scope per proposal.)
- [x] 3.2 Add a cross-platform pair per carrier where forms differ (e.g. `env -u VAR` BSD short and `env --unset=VAR` GNU long) asserting both recurse correctly. (env, sudo, xargs short/long pairs.)

## 4. Verification

- [x] 4.1 `cargo test --workspace` green, including the new carrier-recursion tests.
- [x] 4.2 Prelude parses cleanly and `may-i fmt crates/config/src/prelude.lisp` round-trips (no diff); run `may-i fmt` on the edited prelude before staging.
- [x] 4.3 `cargo fmt` on any Rust test sources before staging.
- [x] 4.4 `may-i check` against a config that authorises each hardened carrier reports no tokenisation diagnostics for the motivating commands. (8/8 checks pass, no diagnostics.)
- [x] 4.5 Consideration: `parser-bindings` is user-facing — update `REFERENCE.md` if the prelude carrier set/behaviour is documented there, else record "verified, no surface change". REFERENCE.md: fixed two illustrations (`sudo` §"Tail recursion", `ssh` §"Positional bindings") that claimed the prelude ships the pre-hardening shape; clarified they are simplified and the shipped parsers also declare value-flags. Carrier list (line 449) and `find`/`bash` illustrations remain accurate.
