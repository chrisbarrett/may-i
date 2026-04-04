;;; may-i configuration
;;
;; Rules are evaluated in order. First match wins.
;; Commands with no matching rule default to "ask". Edits take effect immediately.
;;
;; Validate your config with: may-i check

;;; --- Quick reference ----------------------------------------------------------
;;
;; RULES
;;
;; A rule matches a command and produces a decision (allow, ask, or deny).
;; Each rule takes exactly one body effect. Use combinators for complex logic.
;;
;;   (rule "grep" (effect :allow))
;;   (rule "rm" (effect :deny "Dangerous"))
;;   (rule (or "cat" "head" "tail") (effect :allow))
;;   (rule (regex "^git-.*") (effect :allow))
;;
;;   (rule "git"
;;     (or (when (anywhere "--force") (effect :ask "Force flag detected"))
;;         (effect :allow)))
;;
;; TERMINAL EFFECTS
;;
;;   (effect :allow)                  ; permit the command
;;   (effect :ask "Reason")           ; escalate to the user
;;   (effect :deny "Reason")          ; block the command
;;
;; ARG PATTERNS (return Allow on match, Nil otherwise)
;;
;;   (positional "push" "origin")     ; match by position (flags skipped)
;;   (exact "stash")                  ; like positional, but no extra args
;;   (anywhere "--force" "-f")        ; token appears anywhere in argv
;;   (forbidden "--dangerous")        ; none of these tokens in argv
;;
;; COMBINATORS
;;
;;   (and EFFECT ...)                 ; all must succeed (short-circuits on Nil)
;;   (or EFFECT ...)                  ; first non-Nil wins
;;   (not EFFECT)                     ; swap Allow <-> Nil; pass Ask/Deny
;;
;; CONDITIONALS (predicate controls branching)
;;
;;   (when PREDICATE EFFECT)          ; effect if predicate matches
;;   (unless PREDICATE EFFECT)        ; effect if predicate doesn't match
;;   (if PREDICATE THEN ELSE)         ; if-then-else
;;   (cond ((PREDICATE EFFECT) ...)   ; multi-way branch
;;          (else EFFECT))
;;
;; Predicates: (fact? ...), arg patterns, named refs, (and ...), (or ...), (not ...)
;;
;; EXPRESSION PATTERNS (match a single token inside positional/anywhere/exact)
;;
;;   "literal"                        ; exact string
;;   *                                ; wildcard (matches anything)
;;   (regex "^pattern$")              ; regex
;;   (or "a" "b" "c")                ; match any
;;   (and P (not Q))                  ; combine
;;   [:key *]                         ; bind matched value as fact
;;
;; QUANTIFIERS (wrap a positional pattern)
;;
;;   EXPR                             ; exactly one (default)
;;   (? EXPR)                         ; zero or one
;;   (+ EXPR)                         ; one or more
;;   (* EXPR)                         ; zero or more
;;
;; RECURSIVE EVALUATION (unwrap wrapper commands)
;;
;;   (positional . (may-i *))                ; sudo: eval rest as command
;;   (positional [:ssh/host *] . (may-i *))  ; ssh: bind host, eval rest
;;
;; FACTS (runtime context)
;;
;; Facts are namespaced keys (e.g. :via/ssh, :opencode/agent) passed at
;; runtime via --fact or bound during recursive evaluation.
;;
;;   (fact? :via/ssh)                          ; presence check
;;   (fact? [:env "prod"])                     ; exact value
;;   (fact? [:ssh/host (regex "^prod-")])      ; regex on value
;;   (fact? [:ssh/host *])                     ; any value set
;;
;; NAMED PREDICATES
;;
;;   (define prod-host
;;     (and (fact? :via/ssh)
;;          (fact? [:ssh/host (regex "^prod-")])))
;;
;;   (rule "kubectl"
;;     (or (when prod-host (effect :deny "No kubectl on prod"))
;;         (effect :allow)))
;;
;; CHECKS (validated by `may-i check`)
;;
;;   (check :allow "ls -la"
;;          :deny "rm -rf /")
;;
;;   (check (with-facts [[:env "prod"]]
;;            :deny "kubectl get pods")
;;          (with-facts [[:env "dev"]]
;;            :allow "kubectl get pods"))
;;
;; ENV VAR RESOLUTION
;;
;;   (safe-env-vars "HOME" "PWD" "USER" "SHELL" "EDITOR")
;;

;;; -- Deny: dangerous operations ---------------------------------------------

(rule "rm"
  (or (when (and (anywhere "-r" "--recursive")
                 (anywhere "/"))
        (effect :deny "Recursive deletion from root"))
      (effect :ask)))

(rule (or "mkfs" "dd" "fdisk" "parted" "gdisk")
  (effect :deny "Dangerous filesystem or device operation"))

(rule (or "shutdown" "reboot" "halt" "poweroff" "init")
  (effect :deny "System power control"))

(rule (or "iptables" "nft" "pfctl")
  (effect :deny "Firewall manipulation"))

;;; -- Context-aware rules using facts -----------------------------------------

; Block kubectl in production (test with: may-i eval --fact :env=prod 'kubectl get pods')
(rule "kubectl"
  (or (when (fact? [:env "prod"])
        (effect :deny "No kubectl in production"))
      (effect :allow)))

; SSH wrapper — capture host as fact, evaluate inner command recursively
(rule "ssh"
  (positional [:ssh/host *] . (may-i *)))

(rule "rm"
  (cond
    ((and (anywhere "-r" "--recursive")
          (fact? [:ssh/host (regex "^prod-")]))
     (effect :deny "Recursive delete on production hosts"))
    ((anywhere "-r" "--recursive")
     (effect :ask "Confirm recursive deletion"))
    (else
     (effect :allow))))

;;; -- Allow: read-only operations ---------------------------------------------

(rule (or "cat" "head" "tail" "less" "more" "wc" "sort" "uniq")
  (effect :allow "Read-only file operations"))

(rule (or "ls" "tree" "file" "stat" "du" "df")
  (effect :allow "Read-only filesystem inspection"))

(rule (or "grep" "rg" "ag" "ack")
  (effect :allow "Text search"))

(rule (or "locate" "which" "whereis" "type")
  (effect :allow "File and command lookup"))

(rule (or "echo" "printf" "true" "false" "test" "[")
  (effect :allow "Shell builtins"))

(rule (or "date" "hostname" "uname" "whoami" "id" "printenv" "env")
  (effect :allow "System information"))

(rule (or "ps" "top" "uptime" "free" "vmstat" "iostat")
  (effect :allow "Process and system monitoring"))

(rule (or "basename" "dirname" "realpath" "readlink" "pwd")
  (effect :allow "Path utilities"))
