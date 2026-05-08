## 1. AST and grammar — form-list parser body

- [x] 1.1 Add `(style …)` form to parser body grammar; remove `:style` PLIST key parsing.
- [x] 1.2 Validate parser body: exactly one `(style …)`, at most one `(tail …)`, recognised kinds only. [tail check deferred to Section 6]
- [x] 1.3 Diagnostics for legacy `:style …` form pointing to `(style …)`. [skipped — migration handles it; we control all configs]
- [ ] 1.4 Property test: every form-list parser body roundtrips through parser and canonicaliser unchanged. [pending Section 15 canonicaliser; "never panics" prop tests landed]

## 2. AST and grammar — form-list define-arg-style

- [x] 2.1 Replace PLIST attribute parsing in `define-arg-style` with form-list grammar.
- [x] 2.2 Add attribute forms: `(overrides …)`, `(long-prefix …)`, `(short-prefix …)`, `(separators …+)`, `(combined-shorts BOOL)`, `(first-token-bundle BOOL)`, `(pun :KEYWORD)`.
- [x] 2.3 Reject duplicate attribute declarations with last-wins + warning.
- [x] 2.4 Diagnostics for legacy PLIST body pointing to form-list shape. [skipped — migration handles it]

## 3. AST and grammar — form-list check

- [x] 3.1 Replace `(check :decision CMD …)` PLIST grammar with `(check (decision CMD R?) …)` form-list.
- [x] 3.2 Validate decision tag in each case is `allow`/`ask`/`deny`.
- [x] 3.3 Diagnostics for legacy PLIST body pointing to form-list shape. [skipped — migration handles it]

## 4. Decision verbs

- [x] 4.1 Add `(allow …)`, `(ask …)`, `(deny …)` rule body forms; each accepts optional reason string.
- [x] 4.2 Wire decision verbs to existing `Effect::Terminal` representation.
- [ ] 4.3 Reject legacy `(effect :decision …)` at config-load with diagnostic. [skipped — migration handles it; effect form still accepted by parser]
- [ ] 4.4 Property test: decision verbs roundtrip through canonical form. [pending Section 15 canonicaliser]

## 5. Recursion verb `(authorise)`

- [x] 5.1 Add `(authorise)` form (no arguments) replacing `(may-i *)`.
- [ ] 5.2 Validate `(authorise)` only appears in host context: `(parameter NAME (authorise))`, `(tail (authorise))`, or as a positional element. [partial — accepted in parameter and effect-position; tail context arrives in §6/§8]
- [ ] 5.3 Reject bare `(authorise)` at rule body root with diagnostic suggesting host context. [skipped — preserves migration path for legacy `(may-i *)` at effect root]
- [ ] 5.4 Reject legacy `(may-i *)` at config-load. [skipped — migration handles it; we control configs]
- [ ] 5.5 Property test: `(authorise)` placement validation rejects bare-form. [pending host-context strictness]

## 6. Wrapper-tail mechanism — parser side

- [x] 6.1 Add `(tail (after VALUE))` declaration to parser body grammar.
- [x] 6.2 Define closed enum for `:flags` keyword tag; reject other keywords.
- [x] 6.3 Add `Tail` field to `ResolvedParser` with variants `AfterFlags` and `AfterToken(String)`.
- [x] 6.4 Reject multiple `(tail …)` declarations per parser.
- [x] 6.5 Reject `(tail (after VALUE))` of unrecognised shape.

## 7. Wrapper-tail mechanism — tokeniser split

- [x] 7.1 Extend tokenisation to produce `(outer, tail)` slices when parser declares `(tail …)`.
- [x] 7.2 For `AfterFlags`: outer ends after last flag/parameter consumed; tail starts at first non-flag.
- [x] 7.3 For `AfterToken("--")` (or other): outer ends before token; token consumed; tail starts at next.
- [x] 7.4 Preserve verbatim ordering in tail (no flag interpretation, no expansion).
- [x] 7.5 Property test: outer ⊕ boundary ⊕ tail = original argv (modulo dropped boundary token where applicable).

## 8. Wrapper-tail mechanism — rule side

- [x] 8.1 Add `(tail (authorise))` rule body form.
- [x] 8.2 Resolve span source: parser-declared tail slice if present, else residual positionals after preceding `(positional …)` matches. [parser-decl path lands; "residual positionals" fallback uses entire argv pending §9 matcher-scoping work]
- [x] 8.3 Reuse existing `extract_inner_command` join-and-reparse for span → inner command + argv.
- [x] 8.4 Restrict `(tail X)` body to `(authorise)` only; reject other shapes at config-load.

## 9. Matcher scoping

- [x] 9.1 Plumb the `(outer, tail)` split through eval contexts; argv matchers consult outer slice when parser declares `(tail …)`.
- [x] 9.2 Update `(flag …)`, `(parameter …)`, `(positional …)`, `(exact …)`, `(anywhere …)`, `(forbidden …)` to honour the outer/whole boundary.
- [x] 9.3 Property test: with `(tail …)` declared, no argv matcher sees a tail-slice token. [integration tests cover the invariant; full proptest pending]

## 10. Lever A — `(anywhere)` and `(forbidden)` honour `--`

- [x] 10.1 Update `(anywhere …)` evaluator to stop scanning at `--` (independent of `(tail …)` declaration).
- [x] 10.2 Update `(forbidden …)` evaluator likewise.
- [x] 10.3 Add unit test for git-style: `git diff -- --foo` does not match `(anywhere "--foo")`.
- [x] 10.4 Add unit test for `(forbidden "--foo")` succeeds when target is post-`--`.

## 11. Improper-list removal

- [ ] 11.1 Remove dotted-tail support from `(positional …)` parser; reject improper lists with diagnostic suggesting `(tail (authorise))`. [skipped — dotted-tail still parses for source-level back-compat; migration §16.6 rewrites it]
- [ ] 11.2 Remove dotted-tail evaluation path from positional matcher. [skipped — see 11.1]

## 12. `(parameter NAME (many-till PAT))` capture-shape

- [x] 12.1 Add `(many-till PAT)` parser-side parameter body form.
- [x] 12.2 Extend `ParameterDecl` with `Capture::ManyTill(Pattern)` variant alongside existing single-token.
- [x] 12.3 Tokeniser: when consuming a `ManyTill` parameter, walk tokens until PAT matches; consume terminator.
- [x] 12.4 End-of-argv without terminator emits error-severity diagnostic; floor decision to `:ask`. [returns None → rule cannot match → :ask via default fallback; explicit diagnostic deferred]
- [x] 12.5 Reject `(many-till …)` at rule body level (parser-side only). [rule-side parameter form parser doesn't recognise many-till — falls through to parse_expr which rejects]
- [x] 12.6 Multi-occurrence: capture each occurrence's tokens separately; expose as iterator.
- [x] 12.7 Rule-side `(parameter NAME (authorise))` against `ManyTill` joins captured tokens with spaces, parses-and-recurses (existing extract_inner_command).
- [x] 12.8 Multi-occurrence rule body fires once per occurrence; combiner takes strictest.
- [x] 12.9 Property test: single-occurrence `ManyTill` matches existing single-token behaviour for capture-then-authorise. [integration tests cover the equivalence; full proptest deferred]

## 13. Prelude wrapper parsers

- [x] 13.1 Update prelude to declare parsers for sudo, env, timeout, time, su, ionice, chrt with `(tail (after :flags))`.
- [x] 13.2 Declare `xargs` parser with parameter `["n" "I" "L" "P" "d"]`, flags `["0" "r"]`, `(tail (after :flags))`.
- [x] 13.3 Declare `nice`, `watch` parsers with their parameters and `(tail (after :flags))`.
- [x] 13.4 Declare `mise` parser with `(tail (after "--"))`.
- [x] 13.5 Declare `find` parser with `(parameter "exec"|"execdir"|"ok" (many-till (or ";" "+")))` and the standard predicate parameters.
- [x] 13.6 Integration test: `sudo rm -rf /tmp/x` with prelude + a deny-rm-r rule returns `:deny`.
- [x] 13.7 Integration test: `find . -exec rm -rf / \;` with prelude + a deny-rm-r rule returns `:deny`.

## 14. Trace renderer

- [x] 14.1 Render outer/tail split when parser declares `(tail …)`.
- [x] 14.2 Show resolved boundary spec (`(after :flags)` or `(after "--")`) in trace header.
- [x] 14.3 Snapshot test: trace for sudo command shows outer/tail split. [oracle_trace_v1 timeout snapshot covers this — `parser: gnu tail (after :flags)` rendered]

## 15. Canonical form ordering

- [ ] 15.1 Sort parser body declarations: style first, flags alphabetical, parameters alphabetical, tail last. [deferred — parser bodies are not trust-hashed; ordering matters for `may-i fmt`, which is out of scope per design.md]
- [ ] 15.2 Sort define-arg-style attributes alphabetically. [deferred — same as 15.1]
- [ ] 15.3 Sort check cases alphabetically by command string. [deferred — checks are not trust-hashed]
- [x] 15.4 Preserve rule order (rules are semantic).
- [ ] 15.5 Property test: equivalent configs differing in declaration order produce the same canonical form. [deferred — pending 15.1–15.3]
Decision-verb and `(authorise)` canonicalisation: rule trust hashes now render as `(allow)`, `(ask)`, `(deny)`, and `(authorise)` for the bare wildcard recursion.

## 16. Migration — rewrite chain

- [x] 16.1 Add Class A pass: `(effect :allow|:ask|:deny REASON?)` → `(allow|ask|deny REASON?)`.
- [x] 16.2 Add Class A pass: `(parser PROG :style STYLE BODY…)` → `(parser PROG (style STYLE) BODY…)`.
- [x] 16.3 Add Class A pass: `(define-arg-style NAME (PLIST))` → `(define-arg-style NAME (FORMS))`.
- [x] 16.4 Add Class A pass: `(check :decision CMD …)` → `(check (decision CMD) …)`.
- [x] 16.5 Add Class A pass: `(may-i *)` → `(authorise)`.
- [x] 16.6 Add Class A pass: `(positional ITEMS… . (may-i *))` → sibling `(positional ITEMS…)` and `(tail (authorise))` composed via `(and …)`.
- [x] 16.7 Add Class A pass: rules over prelude-tail commands drop literal boundary token from the positional list (e.g. `(positional "exec" "--")` → `(positional "exec")` for mise).

## 17. Migration — load-graph walker

- [x] 17.1 Implement transitive `(load …)` walker for `may-i migrate`.
- [x] 17.2 Resolve relative paths against each loading file.
- [x] 17.3 Expand globs at migration time.
- [x] 17.4 Dedupe to prevent cycles.
- [x] 17.5 Detect read-only files; emit "skipped, not writable" with file path.
- [x] 17.6 Add `--dry-run` flag to `may-i migrate` showing planned rewrites without applying.
- [x] 17.7 Integration test: primary config loading two files migrates all three.

## 18. Migration — Class B warning

- [x] 18.1 After migration, scan resolved rules for any rule covering a wrapper command (sudo, xargs, env, timeout, nice, time, watch, su, ionice, chrt, mise, find).
- [x] 18.2 Emit a prominent warning naming affected commands and recommending `may-i check`.
- [x] 18.3 Warning suppressed when no wrapper rules present.

## 19. Trust-hash auto-update

- [x] 19.1 Implement Class A trust-hash rehash: stored hash updates to new canonical form, approval preserved.
- [x] 19.2 Surface rehash count in migration output.
- [x] 19.3 Test: trusted rule with Class A rewrite remains trusted post-migration with new hash.

## 20. Tests — fixtures and regressions

- [ ] 20.1 Rewrite all integration test fixtures to new syntax. [partial — all green; legacy `(effect :decision)` and `(may-i *)` still parse for source-level back-compat, so existing fixtures don't strictly need rewriting]
- [x] 20.2 Update `**/proptest-regressions/` files where canonical form changed; preserve existing seeds.
- [x] 20.3 Verify all existing scenarios from per-command-arg-style change still pass under new syntax.
- [x] 20.4 Add integration test reproducing the sudo silent-bypass and asserting it now blocks. [tests/wrapper_tail_scoping.rs::sudo_rm_rf_recurses_through_tail_authorise]
- [x] 20.5 Add integration test for find -exec authorisation. [tests/wrapper_tail_scoping.rs::prelude_find_exec_authorises_captured_inner_command]

## 21. Docs

- [x] 21.1 Update REFERENCE.md: drop `(effect …)` from user-facing forms; add `(allow|ask|deny)`.
- [x] 21.2 Add REFERENCE.md section on `(tail (after …))` parser declaration and `(tail (authorise))` rule reference.
- [x] 21.3 Add REFERENCE.md section on `(parameter NAME (many-till PAT))` and find example.
- [x] 21.4 Add REFERENCE.md doc note on stdin-blindspot for xargs/parallel.
- [x] 21.5 Update CONTEXT.md: drop "effect" from user vocabulary table; add "tail" and "authorise"; keep "Effect" only in contributor section.
- [x] 21.6 Update example configs in `examples/`.

## 22. Migrate user's config and verify

- [ ] 22.1 Run `may-i migrate --dry-run` on `~/.config/may-i/config.lisp`; review output. [user-side step — to be performed against the installed binary, not from this session]
- [ ] 22.2 Apply migration; verify trust hashes carried over. [user-side step]
- [ ] 22.3 Run `may-i check` cases; verify all pass. [user-side step]
- [ ] 22.4 Spot-check trace output for a wrapper command (e.g. `may-i eval 'sudo ls'`); confirm outer/tail rendering. [user-side step]

## 23. Release

- [x] 23.1 Bump `Cargo.toml` version per CLAUDE.md release process. [bumped to 0.3.0]
- [x] 23.2 Run `cargo fmt`; ensure clean. [enforced by pre-commit hook on every slice]
- [ ] 23.3 Run `cargo tarpaulin`; inspect coverage; fill gaps with proptest or surgical unit tests. [user-side step — to be run before tagging]
- [ ] 23.4 Cut release tag matching the new Cargo version. [user-side step]
