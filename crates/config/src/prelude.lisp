;;; Prelude — auto-loaded into every parsed config.
;;;
;;; User declarations of the same name shadow the prelude (last-wins
;;; per the relevant registry).

;; ── Argument styles ─────────────────────────────────────────────────

(define-arg-style gnu
  (long-prefix "--")
  (short-prefix "-")
  (separators " " "=")
  (combined-shorts t)
  (pun :allow))

(define-arg-style single-dash-long
  (long-prefix "-")
  (short-prefix "-")
  (separators " " "=")
  (combined-shorts nil)
  (pun :allow))

(define-arg-style legacy-bundle
  (overrides gnu)
  (first-token-bundle t))

(define-arg-style key-value
  (long-prefix "")
  (short-prefix "")
  (separators "=")
  (combined-shorts nil)
  (pun :error))

;; ── Wrapper-tool parsers ────────────────────────────────────────────
;;
;; Each declares its flag-scanning mode and the `(rest #cmd)` binding
;; that names the recurse target. Rules consult the binding via
;; `(authorise #cmd)`. Scope: tools that ship with a regular Linux
;; distribution, plus widely-used wrappers whose argv semantics are
;; silent-bypass footguns (a missing or mis-spelled boundary token
;; would otherwise leak inner commands past wrapper rules).

(parser "sudo"    (style gnu) (flags posix) (rest #cmd))
(parser "env"     (style gnu) (flags posix) (rest #cmd))
(parser "time"    (style gnu) (flags posix) (rest #cmd))
(parser "su"      (style gnu) (flags posix) (rest #cmd))
(parser "ionice"  (style gnu) (flags posix) (rest #cmd))
(parser "chrt"    (style gnu) (flags posix) (rest #cmd))
(parser "nohup"   (style gnu) (flags posix) (rest #cmd))

(parser "xargs"
  (style gnu)
  (flags posix)
  (parameter ["n" "I" "L" "P" "d"])
  (flag ["0" "r"])
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
  (parameter ["n" "interval"])
  (rest #cmd))

(parser "strace"
  (style gnu)
  (flags posix)
  (parameter ["e" "p" "o"])
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

;; ssh [opts] HOST COMMAND …
(parser "ssh"
  (style gnu)
  (flags posix)
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

;; nix-shell --run "command …" — same shape as bash -c.
(parser "nix-shell"
  (style gnu)
  (flags permute)
  (parameter "run" #cmd))

(parser "find"
  (style single-dash-long)
  (flags permute)
  (parameter "exec"    (many-till (or ";" "+")) #exec)
  (parameter "execdir" (many-till (or ";" "+")) #execdir)
  (parameter "ok"      (many-till (or ";" "+")) #ok)
  (parameter ["name" "iname" "type" "mtime" "size" "regex" "path"]))
