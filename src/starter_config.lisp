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
;         (allow "Text search"))                     ; decision + optional reason
;
;   (rule (command (or "cat" "head" "tail"))      ; match any of these commands
;         (allow))
;
;   (rule (command (regex "^git-.*"))                 ; match by regex
;         (allow))
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
; INLINE EXAMPLES (validated by `may-i check`)
;
;   (example "curl -I https://x.com" allow)
;   (example "curl -d data https://x.com" ask)
;
; WRAPPERS (unwrap to evaluate the inner command)
;
;   (wrapper "nohup" after-flags)
;   (wrapper "mise" (positional "exec") (after "--"))
;
; SECURITY (regex patterns for blocked credential paths, appended to defaults)
;
;   (blocked-paths "\\.secret/" "^/private/")
;
; -- Deny: dangerous operations -----------------------------------------------

(rule (command "rm")
      (args (and (anywhere "-r" "--recursive")
                 (anywhere "/")))
      (deny "Recursive deletion from root"))

(rule (command (or "mkfs" "dd" "fdisk" "parted" "gdisk"))
      (deny "Dangerous filesystem or device operation"))

(rule (command (or "shutdown" "reboot" "halt" "poweroff" "init"))
      (deny "System power control"))

(rule (command (or "iptables" "nft" "pfctl"))
      (deny "Firewall manipulation"))

; -- Allow: read-only operations -----------------------------------------------

(rule (command (or "cat" "head" "tail" "less" "more" "wc" "sort" "uniq"))
      (allow "Read-only file operations"))

(rule (command (or "ls" "tree" "file" "stat" "du" "df"))
      (allow "Read-only filesystem inspection"))

(rule (command (or "grep" "rg" "ag" "ack"))
      (allow "Text search"))

(rule (command (or "locate" "which" "whereis" "type"))
      (allow "File and command lookup"))

(rule (command (or "echo" "printf" "true" "false" "test" "["))
      (allow "Shell builtins"))

(rule (command (or "date" "hostname" "uname" "whoami" "id" "printenv" "env"))
      (allow "System information"))

(rule (command (or "ps" "top" "uptime" "free" "vmstat" "iostat"))
      (allow "Process and system monitoring"))

(rule (command (or "basename" "dirname" "realpath" "readlink" "pwd"))
      (allow "Path utilities"))
