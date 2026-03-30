;;; Reduced V1 config fixture for oracle snapshot tests.
;;;
;;; Covers the key V1 syntax patterns:
;;;   - (command ...) wrapper
;;;   - (args ...) wrapper with (effect ...) as sibling
;;;   - (or ...) command patterns
;;;   - (anywhere ...), (positional ...), (forbidden ...) arg matchers
;;;   - (and ...), (or ...), (not ...) combinators
;;;   - (cond ...) branching
;;;   - (if ...) / (when ...) conditionals
;;;   - (defcontext ...) / (context ...) fact queries
;;;   - Quantifiers: (? ...), (* ...), (+ ...)

(defcontext build-mode
  (or (has [:claude-code/permission-mode "acceptEdits"])
      (has [:opencode/agent "build"])))

(defcontext plan-mode
  (or (has [:claude-code/permission-mode "plan"])
      (has [:opencode/agent "plan"])))

;; --- rm: anywhere + and combinator, deny with reason ---

(rule (command "rm")
      (args (and (anywhere "-r" "--recursive")
                 (anywhere "/")))
      (effect :deny "Recursive deletion from root"))

(rule (command "rm")
      (context build-mode)
      (args (and (anywhere "-r" "--recursive")
                 (if (anywhere (regex "^/tmp/.*"))
                     (effect :allow "Deleting tmp files is allowed")
                   (effect :ask "Recursive deletion requires confirmation"))))
      )

(rule (command "rm")
      (context build-mode)
      (effect :allow "Non-recursive delete is allowed"))

;; --- git: positional, or combinator, multiple matching rules ---

(rule (command "git")
      (args (and (positional "reset") (anywhere "--hard")))
      (effect :ask "Dangerous git reset"))

(rule (command "git")
      (args (or (positional "remote")
                (positional (or "clean" "gc" "push"))))
      (effect :ask "Dangerous git operation"))

(rule (command "git")
      (args (or (positional (or "switch" "restore" "merge" "rebase"
                                "pull" "clone"))
                (positional "checkout" "--")
                (positional "worktree")))
      (context plan-mode)
      (effect :ask "git mutation requires approval in non-writing agents"))

(rule (command "git")
      (effect :allow))

;; --- curl: forbidden args ---

(rule (command "curl")
      (args (forbidden "-d" "--data" "-X" "--request"))
      (effect :allow "GET request (no mutating flags)"))

(rule (command "curl")
      (effect :ask "Network operation requires approval"))

;; --- brew: cond branching ---

(rule (command "brew")
      (args (cond
             ((positional "install")
              (effect :deny "Package installation not allowed"))
             ((positional (or "list" "search"))
              (effect :allow)))))

;; --- mv: if/else ---

(rule (command "mv")
      (args (if (anywhere "-f" "--force")
                (effect :ask "Force move is destructive")
              (effect :allow))))

;; --- or command pattern ---

(rule (command (or "cat" "ls" "grep"))
      (effect :allow "Read-only access"))

;; --- cargo: positional quantifiers + cond ---

(rule (command "cargo")
      (args (or
             (when (exact)
               (effect :allow))
             (positional (? "affected") (? (or "watch" "run" "r")) (? "--")
                         (cond
                          ((or "install" "uninstall")
                           (effect :deny))
                          ((or "build" "b" "check" "c" "test" "t" "fmt" "clippy")
                           (effect :allow)))))))

;; Wrapper: ssh evaluates the inner command recursively
(wrapper "ssh" (positional [:ssh/host *] :command+args))
