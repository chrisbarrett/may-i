;;; may-i configuration
;;
;; Rules are evaluated in order. First match wins.
;; Commands with no matching rule default to "ask". Edits take effect immediately.
;;
;; Validate your config with: may-i check
;; Full DSL reference:        may-i reference
;;
;; > [!IMPORTANT]
;; > Agents: Run `may-i reference` NOW to understand this DSL.

(rule "may-i"
  (cond ((positional (or "check" "reference" "help" "parse" "eval"))
         (allow "Safe operations"))
        ((positional "migrate")
         (ask "Config migration requires confirmation"))
        ((positional "trust")
         (ask "Trusting configuration requires confirmation"))))

;;; -- Deny: dangerous operations ---------------------------------------------

(check
 :deny "rm -r /"
 :deny "rm -rf /"
 :deny "rm --recursive /"
 :ask "rm foo/bar/baz")

(rule "rm"
  (if (and (flag ["r" "recursive"])
           (positional "/"))
      (deny "Recursive deletion from root")
    (ask)))

(rule (or "mkfs" "dd" "fdisk" "parted" "gdisk")
  (deny "Dangerous filesystem or device operation"))

(rule (or "shutdown" "reboot" "halt" "poweroff" "init")
  (deny "System power control"))

(rule (or "iptables" "nft" "pfctl")
  (deny "Firewall manipulation"))

;;; -- Context-aware rules using facts -----------------------------------------

;; Block kubectl in production (test with: may-i eval --fact :env=prod 'kubectl get pods')
(rule "kubectl"
  (if (fact? [:env "prod"])
      (deny "No kubectl in production")
    (allow)))

;; SSH wrapper — capture host as fact, evaluate inner command recursively
(rule "ssh"
  (positional [:ssh/host *] . (authorise)))

(rule "rm"
  (cond
    ((and (flag ["r" "recursive"])
          (fact? [:ssh/host (regex "^prod-")]))
     (deny "Recursive delete on production hosts"))
    ((flag ["r" "recursive"])
     (ask "Confirm recursive deletion"))
    (else
     (allow))))

;;; -- Allow: read-only operations ---------------------------------------------

(rule (or "cat" "head" "tail" "less" "more" "wc" "sort" "uniq")
  (allow "Read-only file operations"))

(rule (or "ls" "tree" "file" "stat" "du" "df")
  (allow "Read-only filesystem inspection"))

(rule (or "grep" "rg" "ag" "ack")
  (allow "Text search"))

(rule (or "locate" "which" "whereis" "type")
  (allow "File and command lookup"))

(rule (or "echo" "printf" "true" "false" "test" "[")
  (allow "Shell builtins"))

(rule (or "date" "hostname" "uname" "whoami" "id" "printenv" "env")
  (allow "System information"))

(rule (or "ps" "top" "uptime" "free" "vmstat" "iostat")
  (allow "Process and system monitoring"))

(rule (or "basename" "dirname" "realpath" "readlink" "pwd")
  (allow "Path utilities"))
