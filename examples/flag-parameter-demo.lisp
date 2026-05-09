;;; Demo config exercising (flag …) and (parameter …) patterns.

;; Allow non-recursive rm; ask for anything with -r/-R/--recursive.
(rule "rm"
  (and (not (flag "r"))
       (not (flag "R"))
       (not (flag "recursive"))
       (allow "non-recursive delete")))

;; Allow git push only without -f / --force.
(rule "git"
  (and (positional "push")
       (not (flag ["f" "force"]))
       (allow "non-force push")))

;; curl: allow GET-style requests; ask for mutating verbs.
(rule "curl"
  (and (parameter ["X" "request"] (regex "^GET$"))
       (allow "read-only request")))

;; Recurse into bash -c VAL: the value is parsed as a command line and
;; evaluated against the rule set.
(rule "echo"
  (allow))
(rule "bash"
  (parameter "c" (authorise)))
