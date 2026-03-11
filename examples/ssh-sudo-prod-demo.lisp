;;; demo config for README screencasts

(wrapper "ssh" (positional [:ssh/host *] :command+args))
(wrapper "sudo" :command+args)

(defcontext immutable
  (and (has :via/ssh)
       (has [:ssh/host (regex "(^|@).*prod.*")])))

(rule (command "echo")
      (effect :allow "Local echo is always fine"))

(rule (command "rm")
      (context immutable)
      (effect :deny "Production hosts are immutable"))

(rule (command (or "touch" "mkdir" "cp" "mv" "tee" "chmod" "chown"))
      (context (and immutable
                    (has :via/sudo)))
      (effect :deny "Production hosts are immutable, even through ssh + sudo"))

(rule (command (or "journalctl" "cat" "less" "tail" "head" "grep" "rg"))
      (context immutable)
      (effect :allow "Read-only inspection on production hosts is allowed"))

(rule (command (or "rm" "touch" "mkdir" "cp" "mv" "tee" "chmod" "chown"
                   "journalctl" "cat" "less" "tail" "head" "grep" "rg"))
      (effect :allow))
