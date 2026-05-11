;;; Demo config — production-host policy through ssh + sudo wrappers.
;;;
;;; Both `ssh` and `sudo` are wrappers: their inner command is the real
;;; risk. The prelude ships parsers for both — `sudo` as `(flags posix)
;;; (rest #cmd)` and `ssh` as `(flags posix) (positional #host (regex
;;; "^[^-].*")) (rest #cmd)` — so we only add the recursion rules.

(rule "sudo" (authorise #cmd))

;; ssh — branch on the bound #host and recurse on the inner command.
(rule "ssh"
  (cond ((matches? #host (regex "(^|@).*prod.*"))
         (deny "Production host — no direct recursion"))
        (else (authorise #cmd))))

(define immutable
  (fact? [:via "ssh"]))

(rule "echo"
  (allow "Local echo is always fine"))

(rule "rm"
  (and immutable
       (deny "Production hosts are immutable")))

(rule (or "touch" "mkdir" "cp" "mv" "tee" "chmod" "chown")
  (and immutable
       (fact? :via/sudo)
       (deny "Production hosts are immutable, even through ssh + sudo")))

(rule (or "journalctl" "cat" "less" "tail" "head" "grep" "rg")
  (and immutable
       (allow "Read-only inspection on production hosts is allowed")))

(rule (or "rm" "touch" "mkdir" "cp" "mv" "tee" "chmod" "chown" "journalctl"
          "cat" "less" "tail" "head" "grep" "rg")
  (allow))
