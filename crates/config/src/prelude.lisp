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
;; Each declares a `(tail (after …))` boundary so the engine's
;; outer/tail split runs without the user having to redeclare the
;; wrapper shape. Scope: tools that ship with a regular Linux
;; distribution, plus widely-used wrappers whose argv semantics are
;; silent-bypass footguns (a missing or mis-spelled boundary token
;; would otherwise leak inner commands past wrapper rules). Other
;; third-party wrappers (e.g. mise, terragrunt) belong in the user's
;; own config.

(parser "sudo"    (style gnu) (tail (after :flags)))
(parser "env"     (style gnu) (tail (after :flags)))
(parser "timeout" (style gnu) (tail (after :flags)))
(parser "time"    (style gnu) (tail (after :flags)))
(parser "su"      (style gnu) (tail (after :flags)))
(parser "ionice"  (style gnu) (tail (after :flags)))
(parser "chrt"    (style gnu) (tail (after :flags)))

(parser "xargs"
  (style gnu)
  (parameter ["n" "I" "L" "P" "d"])
  (flag ["0" "r"])
  (tail (after :flags)))

(parser "nice"
  (style gnu)
  (parameter "n")
  (tail (after :flags)))

(parser "watch"
  (style gnu)
  (parameter ["n" "interval"])
  (tail (after :flags)))

(parser "nix"
  (style gnu)
  (tail (after ["--command" "-c"])))

(parser "find"
  (style single-dash-long)
  (parameter "exec"    (many-till (or ";" "+")))
  (parameter "execdir" (many-till (or ";" "+")))
  (parameter "ok"      (many-till (or ";" "+")))
  (parameter ["name" "iname" "type" "mtime" "size" "regex" "path"]))
