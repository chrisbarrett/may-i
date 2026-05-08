;;; Demo config — production-host policy through ssh + sudo wrappers.
;;;
;;; Both `ssh` and `sudo` are wrappers: their inner command is the real
;;; risk. The prelude already ships `(parser "sudo" (style gnu) (tail
;;; (after :flags)))` so we only need to add the recursion rule. For
;;; `ssh` we declare the parser explicitly to capture the host as a fact
;;; before recursing.

(parser "ssh" (style gnu) (tail (after :flags)))

(rule "sudo" (tail (authorise)))
(rule "ssh"
      (and (positional [:ssh/host *])
           (tail (authorise))))

(define immutable
  (and (fact? :via/ssh)
       (fact? [:ssh/host (regex "(^|@).*prod.*")])))

(rule "echo" (allow "Local echo is always fine"))

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

(rule (or "rm" "touch" "mkdir" "cp" "mv" "tee" "chmod" "chown"
          "journalctl" "cat" "less" "tail" "head" "grep" "rg")
      (allow))
