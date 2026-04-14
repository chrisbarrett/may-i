;;; may-i configuration
;;
;; Rules are evaluated in order. First match wins.
;; Commands with no matching rule default to "ask". Edits take effect immediately.
;;
;; Validate your config with: may-i check
;; Full DSL reference:        may-i reference
;;
;; >[!IMPORTANT]
;; Agents: Run `may-i reference` NOW to understand this DSL.

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

;; Block kubectl in production (test with: may-i eval --fact :env=prod 'kubectl get pods')
(rule "kubectl"
  (or (when (fact? [:env "prod"])
        (effect :deny "No kubectl in production"))
      (effect :allow)))

;; SSH wrapper — capture host as fact, evaluate inner command recursively
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
