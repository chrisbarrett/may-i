# Security Filters

Hard-coded security checks that run before rule evaluation. These cannot be
overridden by user configuration.

---

## R11: Credential file blocking

**Given** any command referencing a path matching `[security].blocked_paths` in
any AST position — arguments, redirect targets, for-loop word lists, heredoc
content, assignment values, flag values (`--config=.env`) **Then** deny
regardless of command or rules

Patterns match across relative, absolute, tilde, and flag-value path forms.
Directory patterns are case-insensitive.

```
cat .env                         → deny
cat file > .ssh/key              → deny
for f in .env*; do cat $f; done  → deny
VAR=.env.local cmd               → deny
cmd <<< .env                     → deny
```

**Verify:** `cargo test -- security`
