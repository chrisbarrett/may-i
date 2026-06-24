## 1. Ground the flag lists

- [ ] 1.1 Confirm each carrier's value-taking flags against the macOS (BSD) man page and the GNU/util-linux docs; record the union and any platform-exclusive flags (per design D1).
- [ ] 1.2 Note any flag that is value-taking on one platform but valueless on another (must NOT be declared) — expect none, but verify `env`, `time`, `xargs`, `ssh`, `sudo`.

## 2. Harden the prelude parsers (TDD: failing test first per carrier)

- [ ] 2.1 `sudo`: add value-params (`-C -D -g -h -p -R -r -t -T -U -u` + long forms). Test: `sudo -u USER rm -rf /` → `:deny`.
- [ ] 2.2 `ssh`: add value-params (`-b -c -D -E -e -F -I -i -J -L -l -m -O -o -p -Q -R -S -W -w`), keep `#host` + `rest`. Test: `ssh -i key -p 22 host rm …` → `#host`=`host`, `:deny`.
- [ ] 2.3 `env`: add value-params (BSD `-u -C -P -S` + GNU `--unset --chdir --split-string`). Test: `env -u VAR rm …` → `:deny`. (Assignment prefix is out of scope — see design Open Questions.)
- [ ] 2.4 `ionice`: add value-params (`-c -n -p -P -u` + long). Test: `ionice -c 2 -n 0 rm …` → `:deny`.
- [ ] 2.5 `chrt`: add value-params (`-T -P -D` + long) and a required `#priority` positional before `(rest #cmd)`. Test: `chrt -r 10 rm …` → `#priority`=`10`, `:deny`.
- [ ] 2.6 `strace`: add value-params (`-s -E -a -O -S -u -P -b -I` + long) to the existing `-e -p -o`. Test: `strace -s 256 rm …` → `:deny`.
- [ ] 2.7 `time`: add value-params (`-o` + GNU `-f --output --format`). Test: `time -o out.txt rm …` → `:deny`.
- [ ] 2.8 `xargs`: add value-params (`-s`, BSD `-J -R -S`, GNU `-a -E -e` + long) to existing `-n -I -L -P -d`. Test: `xargs -s 1000 rm …` → `:deny`.

## 3. Motivating regression tests

- [ ] 3.1 Add an integration test for the gotracksuit shape: `env -u SDKROOT DEVELOPER_DIR=… /usr/bin/xcrun swift test …` resolves the inner command to `xcrun` (path form) rather than a swallowed flag value or env var name.
- [ ] 3.2 Add a cross-platform pair per carrier where forms differ (e.g. `env -u VAR` BSD short and `env --unset=VAR` GNU long) asserting both recurse correctly.

## 4. Verification

- [ ] 4.1 `cargo test --workspace` green, including the new carrier-recursion tests.
- [ ] 4.2 Prelude parses cleanly and `may-i fmt crates/config/src/prelude.lisp` round-trips (no diff); run `may-i fmt` on the edited prelude before staging.
- [ ] 4.3 `cargo fmt` on any Rust test sources before staging.
- [ ] 4.4 `may-i check` against a config that authorises each hardened carrier reports no tokenisation diagnostics for the motivating commands.
- [ ] 4.5 Consideration: `parser-bindings` is user-facing — update `REFERENCE.md` if the prelude carrier set/behaviour is documented there, else record "verified, no surface change".
