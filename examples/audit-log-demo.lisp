;;; Demo config — the Audit log.
;;;
;;; The `(audit …)` form persists an append-only JSONL trail of evaluation
;;; outcomes for after-the-fact forensics. It changes no decision; it only
;;; records. Honoured only from the primary config.
;;;
;;; Threshold (ordered by strictness): :off (default) records nothing,
;;; :deny records denials, :ask records asks and denials, :all records
;;; everything. A command that fails to parse is always recorded at any
;;; non-:off threshold.
;;;
;;; Query the trail with jq, e.g.:
;;;   jq 'select(.decision == "deny") | .command' \
;;;     ~/.local/state/may-i/audit.jsonl

(audit
 (file "/tmp/may-i-audit-demo.jsonl")
 (threshold :ask))

(rule "ls"
  (allow))

(rule "rm"
  (cond
   ((positional "/")
    (deny "Filesystem root"))
   ((flag ["r" "recursive"])
    (ask "Recursive deletion"))
   (else
    (allow))))

(check
 (allow "ls -la")
 (ask "rm -rf /tmp/foo")
 (deny "rm -rf /"))
