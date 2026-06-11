> [!NOTE]
> Draft for review — depends on `policy-sees-redirects-and-env-prefixes`
> landing first. No implementation until the design is approved.

## Why

`policy-sees-redirects-and-env-prefixes` floors every redirect to a
non-standard file target at `:ask`, with no opt-out. That is the right safe
default, but it makes redirect-heavy idioms permanently noisy: `tee out.txt`,
`sort < f`, `cmd >> log` all ask forever, even under rules whose commands are
fully trusted. The missing piece is not path matching — `may-i` classifies by
command; constraining *where* a redirect points is the job of sandboxing
layers beneath it — but a *capability*: a rule declaring that its command may
carry redirects at all.

## What Changes

- Add a capability sub-form to `(rule …)` granting redirect carriage, in
  alist style, e.g.:

  ```lisp
  (rule "tee"
    (redirects :allow)
    (allow "trusted sink"))
  ```

  Exact form name and value enum (`:allow` only, or `:allow`/`:ask`) to be
  settled in design. A rule carrying the capability suppresses the redirect
  floor for commands it matches; rules without it keep the floor.
- The capability never widens past the rule's own decision: it removes the
  floor, it does not add an allow.
- An expansion-bearing redirect target is governed by the
  asymmetric-soundness invariant ("Match and parse imprecision never widens
  toward allow") — open design question whether the capability passes such
  targets through (the capability is path-agnostic, so arguably yes) or
  floors them anyway.

## Capabilities

### New Capabilities

<!-- none -->

### Modified Capabilities

- `shell-command-security-model` (bucket: parsing; trust-relevant): modify
  "Redirect targets are not silently ignored" to admit the rule-granted
  capability as the sole opt-out.
- Rules DSL surface (bucket: rules-and-evaluation): the new sub-form, its
  vocabulary (CONTEXT.md term for the capability), and its trust-hash impact
  (a capability grant widens authority, so it participates in rule hashing).

## Impact

- `crates/config` — parse the sub-form into the rule representation.
- `crates/engine/src/eval` — consult the matched rule's capability before
  applying the redirect floor.
- Trust: rule hashing must cover the capability (it changes what a rule
  authorises).
- Docs/CONTEXT.md: new user-facing term.
- Migration: additive; none.
