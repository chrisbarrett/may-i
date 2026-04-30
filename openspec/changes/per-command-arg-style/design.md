## Context

`crates/engine/src/eval/entry.rs:44-95` defines two functions that together
encode an implicit single GNU-ish CLI convention:

- `expand_combined_flags(&[String]) -> Vec<String>` — splits `-rf` into `-r
  -f` if every char in the cluster is alphabetic.
- `positional_args(&[String]) -> Vec<&str>` — filters out flags, treats
  long options (`--foo`) as consuming the next arg as a value, treats short
  options as not consuming.

Both run unconditionally at evaluator entry. There is no place a config can
say "for `find`, don't split combined alpha flags". The same functions are
called by `Effect::MayI` recursion (effects.rs:220, 273) and by predicates
(predicates.rs:151).

Top-level config forms today: `Rule`, `Define`, `Check`, `SecurityConfig`,
`SafeEnvVars`, `Load`. Adding a new top-level form is well-trodden.

## Goals / Non-Goals

**Goals:**
- A single `(args-style PROGRAM …)` declaration per command shifts
  tokenisation behaviour without touching individual rules.
- The four profiles (`:gnu`, `:single-dash-long`, `:legacy-bundle`,
  `:key-value`) cover the working majority of real-world CLI conventions.
- `:gnu` is the no-op default; existing configs continue to work unchanged.
- The `(may-i …)` recursion path picks up the inner command's profile
  automatically (lookup by `ctx.command`).

**Non-Goals:**
- Per-flag specs (`(flag-spec "-c" :takes-value)` style declarations) —
  out of scope. The follow-on `flag-and-parameter-patterns` change adds
  per-rule flag handling that subsumes most of this need.
- Per-subcommand profiles (`git rebase` vs `git push`) — too granular for
  typical needs; users can always add a separate `args-style` for the
  subcommand if it presents as its own program (rare).
- Inferring profiles by parsing tool help text — magical, fragile.

## Decisions

### 1. Profile set: four named values

```
   :gnu                short -x, long --foo, combine -rf, --foo=val,
                       --foo val. Default when not declared.
   :single-dash-long   every -foo is a long flag, no combining,
                       value via -foo val (no =val by default).
   :legacy-bundle      first non-dashed cluster of letters is a flag
                       bundle; thereafter :gnu rules.
   :key-value          tokens of form key=value are flag-equivalent;
                       every other token is positional.
```

These cover ~95% of common tools. The 5% tail (BSD ps without dash,
openssl per-subcommand) can be handled with `:flags-with-values`
overrides or left to users to express via rule-level patterns.

**Alternative**: orthogonal boolean attributes (`:combine-shorts? true
:short-prefix "-"`). Rejected — increases surface area, most users
want a profile not a checklist.

### 2. Single override: `:flags-with-values`

```
   (args-style "kubectl" :gnu
               :flags-with-values ("-n" "--namespace"
                                   "-c" "--container"))
```

Lists flags that consume the next arg as a value. Layers on top of any
profile. Intentionally minimal — other overrides not added until a real
need arises.

### 3. Default fallback: `:gnu`

Commands without an `args-style` declaration use `:gnu`. This preserves
all existing behaviour. A user who wants stricter behaviour for unknown
commands can declare a wildcard later (separate proposal if needed).

### 4. Tokeniser shape: `Convention` value type

```rust
struct Convention {
    profile: Profile,                 // Gnu | SingleDashLong | LegacyBundle | KeyValue
    flags_with_values: Vec<String>,   // additional value-bearing flags
}
```

`expand_combined_flags(args, &convention)` and `positional_args(args,
&convention)` consult the convention. A null/default convention reproduces
current `:gnu` behaviour.

### 5. Lookup by command name at recursion boundary

`evaluate_with_fold` (entry.rs:31) currently calls `expand_combined_flags`
on the args. New version: looks up the convention for `command` first,
then expands. `Effect::MayI` recursion already swaps `ctx.command` to the
inner command, so the inner gets its own convention.

### 6. Trace output

Trace shows the resolved convention once per evaluation, alongside the
parsed-args view. Helps users debug "why didn't `-n` get treated as a
value-bearing flag?".

### 7. Baseline shipped declarations (optional)

A small built-in table of `args-style` declarations for tools the project
has opinions on:

```
   (args-style "find"      :single-dash-long)
   (args-style "go"        :single-dash-long)
   (args-style "terraform" :single-dash-long)
   (args-style "tar"       :legacy-bundle)
   (args-style "dd"        :key-value)
```

User declarations override the baseline. Either ship as a built-in module
loaded by default, or as a separate optional file users can `(load …)`.
Lean: baseline ships as built-in; user can disable via `(args-style
"find" :gnu)` to override.

## Risks / Trade-offs

- **Behaviour change for some commands.** Tools getting a non-`:gnu`
  baseline (find, go, terraform, tar, dd) will see different tokenisation.
  Existing rules that worked by accident may break. Mitigate: visible
  trace showing the resolved profile; `may-i check` exercises rules
  against representative inputs.
- **Discoverability.** A user with a misbehaving rule may not know an
  `args-style` declaration exists. Mitigate: trace surfaces the active
  profile; documentation in `may-i reference`.
- **Multiple declarations for the same program.** Last-wins with a
  warning at config load. Could be an error instead — pick last-wins for
  consistency with rule precedence.
- **Performance.** Convention lookup is per-command, O(1) hash. Negligible.

## Open Questions

- Should the override accept `=`-attached forms specifically? (i.e. some
  tools accept only `--foo=val`, not `--foo val`.) Probably not for v1 —
  add `:value-style :equals-only` later if a tool needs it.
- Should `:single-dash-long` accept `--long` too? Lean: no — it's a
  distinct profile. Tools that accept both (rare) declare `:gnu` and use
  `:flags-with-values`.
- Where in the rule grammar reference does this live? Add a "Tokenisation"
  section to `may-i reference` output.
