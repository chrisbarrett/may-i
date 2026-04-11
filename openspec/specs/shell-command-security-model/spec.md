# Shell Command Security Model

> Specifies how may-i parses, decomposes, and evaluates shell command strings
> to produce accurate security decisions. Covers the complete path from raw
> input to final decision, including compound command handling, error recovery,
> and embedded command detection.

## Status

Draft — derived from codebase exploration on 2026-04-12.

## Problem Statement

may-i evaluates shell commands against a user-defined policy. The tool must
accurately understand the *complete set of operations* a shell command will
perform, because any operation it fails to evaluate is an operation it fails to
protect. Today, several paths through the code produce incomplete or divergent
security evaluations:

1. **The hook path (security-critical) does not segment compound commands.** A
   command like `echo hello && rm -rf /` is evaluated only as `echo`, bypassing
   policy on `rm`.

2. **Command substitutions are invisible to the evaluator.** `echo $(rm -rf /)`
   evaluates only `echo`; the embedded `rm` is never checked.

3. **Malformed input silently recovers.** The parser never fails — it produces a
   best-effort AST. This means syntactically invalid bash (unterminated quotes,
   missing closing keywords) passes through without any signal that the input
   may not mean what the user thinks it means.

4. **The JSON and non-JSON eval paths produce different security decisions** for
   the same input, because only the non-JSON path performs segmentation.

## Design Principles

### P1: Every executable command must be individually evaluated

If `bash` would execute N distinct commands from a single input string, may-i
must evaluate all N commands. The final decision is the most restrictive
(max over the Decision ordering: Allow < Ask < Deny).

### P2: Fail closed on ambiguity

If the parser cannot confidently determine what commands will execute, the
result must be at least `:ask` (never `:allow`). Malformed input that could be
interpreted multiple ways must not silently pass.

### P3: One evaluation path, one security model

All entry points — hook mode, `eval --json`, `eval` (pretty) — must use
identical evaluation logic. Divergence between paths is a security defect.

### P4: Errors are diagnostic, not silent

When the parser encounters genuinely malformed input, the system should report
what it found, where, and why it can't evaluate confidently. miette diagnostics
with source spans provide the mechanism.

## Scope: Shell Language Coverage

### What must be parsed

may-i targets the **POSIX sh** subset that is common across bash and zsh, since
Claude Code may generate commands for either shell. The parser must handle:

| Construct | Example | Status |
|---|---|---|
| Simple commands | `ls -la` | Implemented |
| Pipelines | `cat f \| grep x` | Implemented |
| AND/OR lists | `make && make install` | Implemented |
| Sequences (`;`) | `echo a; echo b` | Implemented |
| Background (`&`) | `sleep 10 &` | Implemented |
| Subshells | `(cd /tmp && ls)` | Implemented |
| Brace groups | `{ echo a; echo b; }` | Implemented |
| If/elif/else/fi | `if test -f x; then cat x; fi` | Implemented |
| For loops | `for x in a b; do echo $x; done` | Implemented |
| While/until loops | `while read l; do echo $l; done` | Implemented |
| Case statements | `case $x in a) echo A;; esac` | Implemented |
| Function definitions | `f() { echo hi; }` | Implemented |
| Redirections | `echo x > file` | Implemented |
| Heredocs / herestrings | `cat <<EOF` / `cat <<< "hi"` | Implemented |
| Command substitution | `$(cmd)` / `` `cmd` `` | Parsed, **not evaluated** |
| Process substitution | `<(cmd)` / `>(cmd)` | Parsed, **not evaluated** |
| Arithmetic expansion | `$((1+2))` | Parsed, not evaluated |
| Parameter expansion | `${var:-default}` | Parsed, not evaluated |
| Quoting (single, double, ANSI-C, backslash) | `'x'` `"x"` `$'x'` `\x` | Implemented |
| Brace expansion | `{a,b,c}` | Implemented |
| Glob patterns | `*.txt` `[a-z]` `?` | Parsed as patterns |
| Assignments | `VAR=value cmd` | Implemented |

### What is out of scope

- **Alias expansion**: may-i does not resolve shell aliases.
- **Tilde expansion**: `~` is treated as a literal character.
- **Arithmetic evaluation**: `$((expr))` is captured but not computed.
- **Runtime variable values**: `$VAR` is opaque; may-i cannot know its value.
- **Conditional execution semantics**: may-i evaluates all branches, regardless
  of whether `&&` or `||` would short-circuit at runtime.

## Requirements

### R1: Unified Evaluation Pipeline

All entry points MUST use the same evaluation function that:

1. Decomposes the input into individual executable commands (see R2)
2. Evaluates each command against the policy
3. Aggregates decisions using `max()` over the Decision ordering

The current split between `parse_command_args` (hook/JSON) and
`evaluate_segments` (pretty) MUST be eliminated. A single function — operating
on the parsed AST, not on lexer-level segments — must serve all paths.

```
  INPUT STRING
       │
       ▼
  ┌──────────┐
  │  parse()  │──→ Result<Command, ParseDiagnostics>
  └────┬─────┘
       │
       ▼
  ┌──────────────────┐
  │ decompose(cmd)   │──→ Vec<ExecutableUnit>
  │  (AST walk)      │    each: (command_name, args, embedded_commands)
  └────┬─────────────┘
       │
       ▼
  ┌──────────────────┐
  │ evaluate_all()   │──→ aggregate Decision
  │  per-unit eval   │    max(decisions)
  └──────────────────┘
```

**Rationale**: The current `segment()` function operates at the lexer level and
cannot see inside compound constructs. AST-based decomposition is strictly more
accurate.

### R2: AST-Based Command Decomposition

Given a parsed `Command` AST, the evaluator must extract every **simple
command** that would execute, recursing into all compound structures:

| AST Node | Decomposition |
|---|---|
| `Simple(cmd)` | Evaluate `cmd` directly |
| `Pipeline(cmds)` | Evaluate each element |
| `And(a, b)` | Evaluate both `a` and `b` |
| `Or(a, b)` | Evaluate both `a` and `b` |
| `Sequence(cmds)` | Evaluate each element |
| `Background(cmd)` | Evaluate `cmd` |
| `Subshell(cmd)` | Recurse into `cmd` |
| `BraceGroup(cmd)` | Recurse into `cmd` |
| `If { condition, then, elif*, else? }` | Evaluate all branches |
| `For { body, .. }` | Evaluate `body` |
| `Loop { condition, body, .. }` | Evaluate `condition` and `body` |
| `Case { arms, .. }` | Evaluate all arm bodies |
| `FunctionDef { body, .. }` | Evaluate `body` |
| `Redirected { command, .. }` | Recurse into `command` |
| `Assignment(..)` | No command to evaluate (safe) |

**Note on branches**: may-i evaluates *all* branches of conditionals (`if`,
`case`, `&&`, `||`), not just the ones that would execute at runtime. This is
conservative: if any branch is dangerous, the user should be prompted.

### R3: Embedded Command Evaluation

Commands embedded inside arguments via substitution must also be evaluated:

| Construct | Example | Embedded command |
|---|---|---|
| `$(...)` command substitution | `echo $(rm -rf /)` | `rm -rf /` |
| `` `...` `` backtick substitution | `` echo `rm -rf /` `` | `rm -rf /` |
| `<(...)` process substitution | `diff <(ls /a) <(ls /b)` | `ls /a`, `ls /b` |
| `>(...)` process substitution | `tee >(wc -l)` | `wc -l` |

The embedded command string must be **recursively parsed and evaluated** through
the same pipeline. The final decision for the outer command is
`max(outer_decision, max(embedded_decisions))`.

**Current state**: The parser already extracts these as `CommandSubstitution`,
`Backtick`, and `ProcessSubstitution` word parts. The evaluator needs to walk
the word parts of each simple command and recursively evaluate any embedded
commands.

**Edge case — nested substitutions**: `$(echo $(rm -rf /))` contains two levels
of nesting. The recursive parse handles this naturally: parsing `echo $(rm -rf
/)` will itself find the inner `$(rm -rf /)`.

**Edge case — substitution as command name**: `$(which python) --version` means
the command name is dynamic. Since may-i cannot know the runtime value, this
must evaluate to at least `:ask`.

### R4: Parse Error Reporting

The parser MUST report errors as structured diagnostics when it cannot
confidently parse the input. The current "never fail" approach must change to
"parse what you can, but report what you couldn't".

#### R4.1: Parse Result Type

```rust
pub struct ParseResult {
    /// The best-effort AST (always present).
    pub command: Command,
    /// Diagnostics encountered during parsing. Non-empty means the AST
    /// is a best-effort recovery and may not accurately represent the input.
    pub diagnostics: Vec<ParseDiagnostic>,
}

pub struct ParseDiagnostic {
    /// Byte offset range in the original input.
    pub span: Span,
    /// What went wrong.
    pub kind: ParseDiagnosticKind,
    /// Severity: warning (parse recovered) vs error (parse may be wrong).
    pub severity: Severity,
}

pub enum Severity {
    /// The parser recovered and the AST is likely correct.
    Warning,
    /// The parser recovered but the AST may not accurately represent the input.
    /// The evaluator should treat this as ambiguous (fail closed → :ask).
    Error,
}

pub enum ParseDiagnosticKind {
    UnterminatedDoubleQuote,
    UnterminatedSingleQuote,
    UnterminatedBacktick,
    UnterminatedCommandSubstitution,
    UnterminatedArithmetic,
    UnterminatedParameterExpansion,
    MissingClosingKeyword { expected: &'static str },  // fi, done, esac, }, )
    UnexpectedToken { found: String, context: String },
    EmptyCommand,
}
```

#### R4.2: Severity Guidelines

| Situation | Severity | Rationale |
|---|---|---|
| Unterminated quote (single/double) | Error | Could hide operators: `echo "hello; rm -rf /` |
| Unterminated backtick/`$()` | Error | Embedded command boundary is ambiguous |
| Missing `fi`/`done`/`esac` | Warning | Body is unambiguous, just unclosed |
| Empty command in pipeline (`\| cmd`) | Warning | Leading empty is harmless |
| Bare operators (`&&`, `\|\|`, `;`) with no command | Warning | Falls to :ask naturally |

#### R4.3: Error Integration with Evaluator

When `ParseResult.diagnostics` contains any `Error`-severity items:

1. The evaluator MUST still evaluate the best-effort AST (to provide trace info)
2. The final decision MUST be at least `:ask` (never `:allow`)
3. The trace output MUST include the parse diagnostics
4. In JSON mode, diagnostics appear in a `"parse_diagnostics"` array

#### R4.4: miette Integration

`ParseDiagnostic` converts to a miette `Diagnostic` at the CLI boundary using
the same two-stage pattern as config errors:

```
ParseDiagnostic (internal, no source text)
       │
       ▼ attach source text at CLI boundary
ShellParseError (miette::Diagnostic with #[source_code], #[label])
```

Example rendered output for `echo "hello; rm -rf /`:

```
  ⚠ unterminated double quote
   ╭─[command:1:6]
 1 │ echo "hello; rm -rf /
   ·      ┬
   ·      ╰── quote opened here, never closed
   ╰────
  help: the parser treated EOF as the closing quote, but this may hide
        operators inside the quoted string
```

### R5: Dynamic Command Names

When the command name (first word of a simple command) contains dynamic parts
that cannot be resolved at parse time, the evaluator must handle this
explicitly:

| Command name contains | Example | Behaviour |
|---|---|---|
| Only literals | `ls -la` | Normal evaluation |
| Parameter (`$VAR`) | `$EDITOR file` | → `:ask` with reason |
| Command substitution | `$(which python) -V` | Evaluate inner, outer → `:ask` |
| Arithmetic | `$((x))` | → `:ask` with reason |
| Glob | `*` | → `:ask` with reason |

The reason string must indicate *why* the command name is dynamic, e.g.:
`"command name is dynamic: contains parameter expansion $EDITOR"`.

### R6: Whitespace and Empty Input

| Input | Behaviour |
|---|---|
| `""` (empty string) | → `:ask "empty command"` |
| `"   "` (whitespace only) | → `:ask "empty command"` |
| `"  ; ;  "` (only operators) | → `:ask` for each empty segment |

Empty input must never produce `:allow`.

## Non-Requirements

- **NR1**: may-i does not need to handle multi-line scripts or shebangs. Input
  is always a single shell command string (which may contain `;` or `\n`
  separators).

- **NR2**: may-i does not need to be a conforming POSIX parser. It needs to
  understand enough shell syntax to identify all commands that would execute.
  Exotic syntax that doesn't affect command identity (e.g., coprocesses,
  `select` loops) can fall through to `:ask`.

- **NR3**: may-i does not evaluate variable values, arithmetic, or globs at
  runtime. It operates on the syntactic structure, not the runtime semantics.

## Traceability

| Requirement | Relates to |
|---|---|
| R1 | [claude-code-hook](../claude-code-hook/spec.md), [eval-stdin](../eval-stdin/spec.md) |
| R2 | [eval-fold-trait](../eval-fold-trait/spec.md) |
| R3 | New capability — recursive embedded command eval |
| R4 | [evaluator-error-handling](../evaluator-error-handling/spec.md) |
| R5 | New — dynamic command name handling |
| R6 | [eval-stdin](../eval-stdin/spec.md) |

## Test Vectors

These inputs must produce the specified behaviour. They serve as acceptance
criteria for any implementation.

### Compound commands (R1, R2)

```
INPUT: echo hello && rm -rf /
RULE:  (rule "echo" (effect :allow))
EXPECT: :ask (rm is unevaluated)

INPUT: echo hello | rm -rf /
RULE:  (rule "echo" (effect :allow))
EXPECT: :ask (rm is unevaluated)

INPUT: echo hello; rm -rf /
RULE:  (rule "echo" (effect :allow))
EXPECT: :ask (rm is unevaluated)

INPUT: if true; then rm -rf /; fi
RULE:  (rule "rm" (effect :deny))
EXPECT: :deny (rm in then-branch)

INPUT: for x in /; do rm $x; done
RULE:  (rule "rm" (effect :deny))
EXPECT: :deny (rm in loop body)

INPUT: (echo hello && rm -rf /)
RULE:  (rule "echo" (effect :allow))
EXPECT: :ask (rm inside subshell)
```

### Embedded commands (R3)

```
INPUT: echo $(rm -rf /)
RULE:  (rule "echo" (effect :allow)), (rule "rm" (effect :deny))
EXPECT: :deny (embedded rm is denied)

INPUT: echo `rm -rf /`
RULE:  (rule "echo" (effect :allow)), (rule "rm" (effect :deny))
EXPECT: :deny (backtick substitution)

INPUT: diff <(ls /a) <(ls /b)
RULE:  (rule "diff" (effect :allow)), (rule "ls" (effect :allow))
EXPECT: :allow (all commands allowed)

INPUT: echo $(echo $(rm -rf /))
RULE:  (rule "echo" (effect :allow)), (rule "rm" (effect :deny))
EXPECT: :deny (nested substitution)
```

### Parse errors (R4)

```
INPUT: echo "hello; rm -rf /
EXPECT: :ask (unterminated quote → Error severity)
DIAGNOSTICS: UnterminatedDoubleQuote at offset 5

INPUT: echo 'hello
EXPECT: parse warning, evaluate normally (unterminated single quote)

INPUT: if true; then echo hi
EXPECT: parse warning (missing fi), evaluate echo normally
```

### Dynamic command names (R5)

```
INPUT: $EDITOR file.txt
EXPECT: :ask "command name is dynamic: contains parameter $EDITOR"

INPUT: $(which python) --version
RULE:  (rule "which" (effect :allow))
EXPECT: :ask for outer command; :allow for embedded `which`
```

### Empty/whitespace (R6)

```
INPUT: ""
EXPECT: :ask "empty command"

INPUT: "   "
EXPECT: :ask "empty command"
```
