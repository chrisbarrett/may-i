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
;;   (rule "grep" :effect :allow)                    ; simple allow
;;   (rule "rm" :effect [:deny "Dangerous"])         ; with reason
;;
;;   (rule (or "cat" "head" "tail")                  ; match any command
;;         :effect :allow)
;;
;;   (rule (regex "^git-.*")                         ; regex match
;;         :effect :allow)
;;
;; EFFECTS
;;
;; Terminal effects (return a decision):
;;   (effect :allow)
;;   (effect :ask "Reason")
;;   (effect :deny "Reason")
;;
;; Pattern effects (return Allow on match, Nil otherwise):
;;   (positional "push" "origin")     ; match positional args
;;   (exact "ls" "-la")               ; exact match (no extra args)
;;   (anywhere "--force" "-f")        ; match anywhere in args
;;   (forbidden "--dangerous")        ; fail if pattern found
;;
;; Combinators:
;;   (and EFFECT ...)                 ; all must match
;;   (or EFFECT ...)                  ; first match wins
;;   (not EFFECT)                     ; invert Allow/Nil
;;
;; Conditionals:
;;   (when PATTERN EFFECT)            ; effect if pattern matches
;;   (unless PATTERN EFFECT)          ; effect if pattern doesn't match
;;   (if PATTERN THEN ELSE)           ; if-then-else
;;   (cond ((PATTERN) EFFECT) ...     ; multi-way branch
;;          (else EFFECT))
;;
;; Recursive evaluation (for wrapper commands like ssh, sudo):
;;   (may-i PATTERN)                  ; evaluate inner command
;;   (positional [:host *] . (may-i *))   ; capture host, eval rest
;;
;; FACTS (runtime context)
;;
;; Facts are namespaced keys like :via/ssh or :opencode/agent.
;;
;;   presence: :via/ssh              ; key is present
;;   scalar:   [:env "prod"]         ; key has string value
;;
;; Query facts with (fact? ...):
;;   (fact? :via/ssh)                                     ; presence
;;   (fact? [:env "prod"])                                ; exact value
;;   (fact? [:ssh/host (regex "^prod-")])                ; regex match
;;   (and (fact? :via/ssh) (fact? [:env "prod"]))        ; combined
;;
;; PATTERNS (for positional/anywhere/exact)
;;
;;   "literal"                       ; exact string
;;   *                               ; wildcard (matches anything)
;;   (regex "^pattern$")             ; regex
;;   (or "a" "b" "c")                ; match any
;;   (and P1 (not P2))               ; combine patterns
;;
;; QUANTIFIERS (for positional args)
;;
;;   "cmd"                           ; exactly one (default)
;;   (? "cmd")                       ; zero or one
;;   (+ "cmd")                       ; one or more
;;   (* "cmd")                       ; zero or more
;;
;; NAMED PREDICATES
;;
;;   (define prod-host
;;     (and (fact? :via/ssh)
;;          (fact? [:ssh/host (regex "^prod-")])))
;;
;;   (rule "kubectl"
;;     (when prod-host (effect :deny "No kubectl on prod"))
;;     :effect (effect :allow))
;;
;; CHECKS (validated by `may-i check`)
;;
;;   (check :allow "ls -la"
;;          :deny "rm -rf /")
;;
;; With facts:
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
  (when (and (anywhere "-r" "--recursive")
             (anywhere "/"))
    (effect :deny "Recursive deletion from root"))
  :effect :ask)

(rule (or "mkfs" "dd" "fdisk" "parted" "gdisk")
  :effect [:deny "Dangerous filesystem or device operation"])

(rule (or "shutdown" "reboot" "halt" "poweroff" "init")
  :effect [:deny "System power control"])

(rule (or "iptables" "nft" "pfctl")
  :effect [:deny "Firewall manipulation"])

;;; -- Context-aware rules using facts -----------------------------------------

; Example: Block kubectl in production
; (pass --fact :env=prod to may-i eval to test)
(rule "kubectl"
  (when (fact? [:env "prod"])
    (effect :deny "No kubectl in production"))
  :effect :allow)

; Example: SSH wrapper - capture host, evaluate inner command
(rule "ssh"
  (positional [:ssh/host *] . (may-i *))
  :effect [:deny "SSH commands denied by default"])

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
  :effect [:allow "Read-only file operations"])

(rule (or "ls" "tree" "file" "stat" "du" "df")
  :effect [:allow "Read-only filesystem inspection"])

(rule (or "grep" "rg" "ag" "ack")
  :effect [:allow "Text search"])

(rule (or "locate" "which" "whereis" "type")
  :effect [:allow "File and command lookup"])

(rule (or "echo" "printf" "true" "false" "test" "[")
  :effect [:allow "Shell builtins"])

(rule (or "date" "hostname" "uname" "whoami" "id" "printenv" "env")
  :effect [:allow "System information"])

(rule (or "ps" "top" "uptime" "free" "vmstat" "iostat")
  :effect [:allow "Process and system monitoring"])

(rule (or "basename" "dirname" "realpath" "readlink" "pwd")
  :effect [:allow "Path utilities"])
