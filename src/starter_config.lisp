; may-i configuration
; Rules are evaluated in order. First match wins (deny rules always win).
; Commands with no matching rule default to "ask".

; -- Deny: dangerous operations -----------------------------------------------

(rule (command "rm")
      (args (and (anywhere "-r" "--recursive")
                 (anywhere "/")))
      (deny "Recursive deletion from root"))

(rule (command (oneof "mkfs" "dd" "fdisk" "parted" "gdisk"))
      (deny "Dangerous filesystem or device operation"))

(rule (command (oneof "shutdown" "reboot" "halt" "poweroff" "init"))
      (deny "System power control"))

(rule (command (oneof "iptables" "nft" "pfctl"))
      (deny "Firewall manipulation"))

; -- Allow: read-only operations -----------------------------------------------

(rule (command (oneof "cat" "head" "tail" "less" "more" "wc" "sort" "uniq"))
      (allow "Read-only file operations"))

(rule (command (oneof "ls" "tree" "file" "stat" "du" "df"))
      (allow "Read-only filesystem inspection"))

(rule (command (oneof "grep" "rg" "ag" "ack"))
      (allow "Text search"))

(rule (command (oneof "locate" "which" "whereis" "type"))
      (allow "File and command lookup"))

(rule (command (oneof "echo" "printf" "true" "false" "test" "["))
      (allow "Shell builtins"))

(rule (command (oneof "date" "hostname" "uname" "whoami" "id" "printenv" "env"))
      (allow "System information"))

(rule (command (oneof "ps" "top" "uptime" "free" "vmstat" "iostat"))
      (allow "Process and system monitoring"))

(rule (command (oneof "basename" "dirname" "realpath" "readlink" "pwd"))
      (allow "Path utilities"))
