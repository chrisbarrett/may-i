;;; Prelude — auto-loaded into every parsed config.
;;;
;;; User declarations of the same name shadow the prelude (last-wins
;;; per the relevant registry).

;; ── Argument styles ─────────────────────────────────────────────────

(define-arg-style gnu
  (combined-shorts t)
  (long-prefix "--")
  (pun :allow)
  (separators " " "=")
  (short-prefix "-"))

(define-arg-style single-dash-long
  (combined-shorts nil)
  (long-prefix "-")
  (pun :allow)
  (separators " " "=")
  (short-prefix "-"))

(define-arg-style legacy-bundle
  (first-token-bundle t)
  (overrides gnu))

(define-arg-style key-value
  (combined-shorts nil)
  (long-prefix "")
  (pun :error)
  (separators "=")
  (short-prefix ""))

;; ── Carrier-tool parsers ────────────────────────────────────────────
;;
;; Each declares its flag-scanning mode and the `(rest #cmd)` binding
;; that names the recurse target. Rules consult the binding via
;; `(authorise #cmd)`. Scope: tools that ship with a regular Linux
;; distribution, plus widely-used carriers whose argv semantics are
;; silent-bypass footguns (a missing or mis-spelled boundary token
;; would otherwise leak inner commands past carrier rules).

;; sudo — value-flags identical on BSD (macOS) and GNU (Linux). An
;; undeclared value-flag (`-u USER`) would otherwise swallow USER as
;; the inner command, letting the real command escape its rule.
;; Short `-h` is deliberately NOT declared: it is overloaded (`-h`
;; alone = help, `-h host` = host), so declaring it value-taking would
;; make `sudo -h rm …` swallow `rm`. The unambiguous long `--host`
;; (help is `--help`) is declared instead.
(parser "sudo"
  (style gnu)
  (flags posix)
  (parameter ["C" "D" "R" "T" "U" "chdir" "chroot"
                  "close-from" "command-timeout" "g" "group" "host"
                  "other-user" "p" "prompt" "r"
                  "role" "t" "type" "u" "user"])
  (rest #cmd))

;; env — BSD short value-flags `-u -C -P -S` plus the GNU long forms
;; `--unset --chdir --split-string`. `-C` = BSD altwd / GNU chdir;
;; `-S` = BSD split / GNU --split-string. Assignment prefix
;; (`env FOO=bar cmd`) is out of scope (needs a quantified positional,
;; blocked on a parser-engine gap — see change Open Questions).
(parser "env"
  (style gnu)
  (flags posix)
  (parameter ["C" "P" "S" "chdir" "split-string" "u" "unset"])
  (rest #cmd))

;; time — BSD `-o`; GNU `-o/--output -f/--format`.
(parser "time"
  (style gnu)
  (flags posix)
  (parameter ["f" "format" "o" "output"])
  (rest #cmd))

(parser "su"
  (style gnu)
  (flags posix)
  (rest #cmd))

;; ionice (util-linux) — `-c/--class -n/--classdata -p/--pid
;; -P/--pgid -u/--uid`.
(parser "ionice"
  (style gnu)
  (flags posix)
  (parameter ["P" "c" "class" "classdata" "n" "p" "pgid" "pid" "u" "uid"])
  (rest #cmd))

;; chrt (util-linux) — value-flags `-T/--sched-runtime
;; -P/--sched-period -D/--sched-deadline`; the scheduling priority is a
;; required positional operand (the `timeout` #duration shape), ahead
;; of the inner command in `(rest)`.
(parser "chrt"
  (style gnu)
  (flags posix)
  (parameter ["D" "P" "T" "sched-deadline" "sched-period" "sched-runtime"])
  (positional #priority (regex "^[0-9]+$"))
  (rest #cmd))

(parser "nohup"
  (style gnu)
  (flags posix)
  (rest #cmd))

(parser "xargs"
  (style gnu)
  (flags posix)
  (flag ["0" "r"])
  ;; existing `-n -I -L -P -d` plus `-s/--max-chars`, BSD `-J -R -S`,
  ;; GNU `-a/--arg-file -E`. GNU `-e/--eof` is NOT declared: its
  ;; eof-string argument is optional, so `xargs -e rm …` treats `-e` as
  ;; valueless and `rm` as the command — declaring it would swallow
  ;; `rm`. `-E` (mandatory arg on both BSD and GNU) covers the
  ;; value-taking case.
  (parameter ["E" "I" "J" "L" "P" "R" "S" "a" "arg-file" "d"
                  "max-chars"
                  "n" "s"])
  (rest #cmd))

;; timeout DURATION COMMAND … — the duration is a positional bound
;; explicitly so rule authors can read it via `(matches? #duration …)`.
;; Format: an unsigned integer or decimal, with an optional s/m/h/d
;; suffix; matches `man 1 timeout`.
(parser "timeout"
  (style gnu)
  (flags posix)
  (parameter "k")
  (parameter "s")
  (positional #duration (regex "^[0-9]+(\\.[0-9]+)?[smhd]?$"))
  (rest #cmd))

(parser "nice"
  (style gnu)
  (flags posix)
  (parameter "n")
  (rest #cmd))

(parser "watch"
  (style gnu)
  (flags posix)
  (parameter ["interval" "n"])
  (rest #cmd))

;; strace — existing `-e -p -o` plus `-s -E -a -O -S -u -P -b -I`
;; (long: --string-limit --env --username …).
(parser "strace"
  (style gnu)
  (flags posix)
  (parameter ["E" "I" "O" "P" "S" "a" "b" "e" "env" "o" "p" "s"
                  "string-limit" "u" "username"])
  (rest #cmd))

;; mise exec … -- COMMAND …
(parser "mise"
  (style gnu)
  (flags (until "--"))
  (rest #cmd))

;; nix shell … --command COMMAND …
(parser "nix"
  (style gnu)
  (flags (until "--command" "-c"))
  (rest #cmd))

;; ssh [opts] HOST COMMAND … — OpenSSH value-flags (identical on BSD
;; and GNU). Without them, `ssh -p 22 host cmd` binds `#host`=`22` and
;; loses the real command. Long forms are not used by ssh's getopt
;; grammar, so short flags suffice.
(parser "ssh"
  (style gnu)
  (flags posix)
  (parameter ["D" "E" "F" "I" "J" "L" "O" "Q" "R" "S" "W" "b" "c" "e" "i" "l"
                  "m" "o"
                  "p" "w"])
  (positional #host (regex "^[^-].*"))
  (rest #cmd))

;; direnv exec DIR COMMAND … (and friends). The verb (exec, deny,
;; reload) sits in the positional slot so rule authors can branch on it
;; via `(matches? #verb …)`; the actual command lives in `(rest …)`.
(parser "direnv"
  (style gnu)
  (flags posix)
  (positional #verb (regex "^[a-z][a-z-]*$"))
  (rest #cmd))

;; bash -c "command …" — the captured `-c` argument is the recurse
;; target. No `(rest …)` because bash's positional args after `-c` are
;; `$0 $1 …` for the captured command, not a sibling commandline.
(parser "bash"
  (style gnu)
  (flags permute)
  (parameter "c" #cmd))

;; sh -c "command …" — POSIX sh / dash. Same shape as bash -c; the
;; captured `-c` argument is the recurse target. Used by carriers
;; that hand off to `/bin/sh -c …` (sudo, ssh, xargs, watchexec, …).
(parser "sh"
  (style gnu)
  (flags permute)
  (parameter "c" #cmd))

;; nix-shell --run "command …" — same shape as bash -c.
(parser "nix-shell"
  (style gnu)
  (flags permute)
  (parameter "run" #cmd))

(parser "find"
  (style single-dash-long)
  (flags permute)
  (parameter "exec" (many-till (or ";" "+")) #exec)
  (parameter "execdir" (many-till (or ";" "+")) #execdir)
  (parameter ["iname" "mtime" "name" "path" "regex" "size" "type"])
  (parameter "ok" (many-till (or ";" "+")) #ok))
