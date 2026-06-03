;;; Demo: gate `rm -rf` on a list of values with (every? …).
;;;
;;; The parser binds every positional path to #paths as a list, then the
;;; rule allows recursive deletion only when every path is a safe
;;; temporary/cache location. This is the motivating case for the
;;; binding shapes + quantifier surface.
;;;
;;; The predicate of (every? …) is the single-value pattern sublanguage
;;; (literal / regex / or / and / not / wildcard), inlined here — it does
;;; not take a (define …)d name.

;; Parse rm GNU-style; collect all positionals into the #paths list.
(parser "rm"
  (style gnu)
  (flags posix)
  (positional #paths * *))

(rule "rm"
  (when (flag ["r" "recursive"])
    (cond
     ;; Deletion that reaches the filesystem root is never ok.
     ((anywhere "/")
      (deny "Recursive deletion from root"))
     ;; Every target is a tmp/cache path — allow.
     ((every? #paths
              (or (regex "^/tmp/")
                  (regex "^/var/tmp/")
                  (regex "^/home/[^/]+/\\.cache/")))
      (allow "Recursive delete of tmp/cache paths only"))
     ;; Otherwise, get a human in the loop.
     (else
      (ask "Recursive deletion")))))
