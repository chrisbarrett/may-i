; may-i configuration
;
; Rules are evaluated in order. First match wins (deny rules always win).
; Commands with no matching rule default to "ask". Edits to this file take
; effect immediately.
;
; Validate your config with: may-i check
;
; -- Quick reference ----------------------------------------------------------
;
; RULES
;
;   (rule (command "grep")                           ; exact command name
;         (effect :allow "Text search"))             ; decision + optional reason
;
;   (rule (command (or "cat" "head" "tail"))      ; match any of these commands
;         (effect :allow))
;
;   (rule (command (regex "^git-.*"))                 ; match by regex
;         (effect :allow))
;
; ARGUMENT MATCHERS (inside (args ...))
;
;   (positional "push" *)             ; match by position (skip flags); * = any
;   (exact "remote")                  ; like positional but requires exact arg count
;   (anywhere "-r" "--recursive")     ; any of these tokens appears in argv
;   (forbidden "-d" "--data")         ; sugar for (not (anywhere ...)))
;   (and (anywhere "-r") (anywhere "/"))   ; all sub-matchers must match
;   (or (positional "a") (positional "b")) ; any sub-matcher must match
;   (not (anywhere "--force"))             ; inverts a sub-matcher
;
; PATTERNS (inside positional/anywhere)
;
;   "literal"                         ; exact string match
;   *                                 ; wildcard (matches anything)
;   (regex "^(get|list).*")           ; regex match
;   (or "create" "delete" "fork")  ; match any of these strings
;
; COND (branch on args within a single rule; first matching branch wins)
;
;   (rule (command "tmux")
;         (args (cond
;                 ((positional "source-file" "~/.tmux.conf")
;                  (effect :allow "Reloading config"))
;                 (else
;                  (effect :deny "Unknown tmux command")))))
;
; INLINE CHECKS (validated by `may-i check`)
;
;   (check :allow "curl -I https://x.com"
;          :ask "curl -d data https://x.com")
;
; WRAPPERS (unwrap to evaluate the inner command)
;
;   (wrapper "nohup" after-flags)
;   (wrapper "mise" (positional "exec") (after "--"))
;
; SECURITY (regex patterns for blocked credential paths)
;
;   (blocked-paths "\\.secret/" "^/private/")
;
; ENV VAR RESOLUTION (allow static analysis to resolve these env vars)
;
;   (safe-env-vars "HOME" "PWD" "USER" "SHELL" "EDITOR" "TERM")
;
; -- Deny: dangerous operations -----------------------------------------------

(rule (command "rm")
      (args (and (anywhere "-r" "--recursive")
                 (anywhere "/")))
      (effect :deny "Recursive deletion from root"))

(rule (command (or "mkfs" "dd" "fdisk" "parted" "gdisk"))
      (effect :deny "Dangerous filesystem or device operation"))

(rule (command (or "shutdown" "reboot" "halt" "poweroff" "init"))
      (effect :deny "System power control"))

(rule (command (or "iptables" "nft" "pfctl"))
      (effect :deny "Firewall manipulation"))

; -- Allow: read-only operations -----------------------------------------------

(rule (command (or "cat" "head" "tail" "less" "more" "wc" "sort" "uniq"))
      (effect :allow "Read-only file operations"))

(rule (command (or "ls" "tree" "file" "stat" "du" "df"))
      (effect :allow "Read-only filesystem inspection"))

(rule (command (or "grep" "rg" "ag" "ack"))
      (effect :allow "Text search"))

(rule (command (or "locate" "which" "whereis" "type"))
      (effect :allow "File and command lookup"))

(rule (command (or "echo" "printf" "true" "false" "test" "["))
      (effect :allow "Shell builtins"))

(rule (command (or "date" "hostname" "uname" "whoami" "id" "printenv" "env"))
      (effect :allow "System information"))

(rule (command (or "ps" "top" "uptime" "free" "vmstat" "iostat"))
      (effect :allow "Process and system monitoring"))

(rule (command (or "basename" "dirname" "realpath" "readlink" "pwd"))
      (effect :allow "Path utilities"))

; -- Security: blocked credential paths ----------------------------------------

(blocked-paths
  "(^|/)\\.env($|[./])"
  "(^|/)\\.ssh/"
  "(^|/)\\.aws/"
  "(^|/)\\.gnupg/"
  "(^|/)\\.docker/"
  "(^|/)\\.kube/"
  "(^|/)credentials\\.json($|[./])"
  "(^|/)\\.netrc($|[./])"
  "(^|/)\\.npmrc($|[./])"
  "(^|/)\\.pypirc($|[./])")
