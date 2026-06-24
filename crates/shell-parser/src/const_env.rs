use crate::ast::{ArrayKind, AssignmentValue, Command, SimpleCommand, Subscript, Word, WordPart};
use std::collections::{HashMap, HashSet};

/// The provably-constant value of a variable: either a scalar literal or an
/// ordered sequence of element literals (an indexed array). Generalising the
/// constant env to a value kind lets scalars stay the singleton case while
/// arrays carry their full element sequence, so a subscripted expansion
/// (`${arr[i]}`, `"${arr[@]}"`, `${#arr[@]}`) can resolve against it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstValue {
    Scalar(String),
    /// An **indexed** array's element literals, in order. Associative arrays
    /// are never represented here (their element order is unspecified, so
    /// resolving `"${m[@]}"` would be unsound) — they are disqualified during
    /// analysis.
    Array(Vec<String>),
}

/// Read-only lookup over a constant env, abstracting the value kind so the
/// resolution path (`Word::resolve`, the verbatim gate) works against both a
/// scalar-only `HashMap<String, String>` (used throughout the existing tests
/// and scalar callers) and the array-carrying `HashMap<String, ConstValue>`
/// the analysis now produces. Scalar lookups behave identically across both,
/// so generalising the env never changes scalar resolution.
pub trait ConstLookup {
    /// The scalar literal bound to `name`, if any. An array name returns
    /// `None` here (an array is not a scalar value).
    fn lookup_scalar(&self, name: &str) -> Option<&str>;
    /// The ordered element literals of the indexed array bound to `name`, if
    /// any. Always `None` for a scalar-only env.
    fn lookup_array(&self, name: &str) -> Option<&[String]>;
}

impl ConstLookup for HashMap<String, String> {
    fn lookup_scalar(&self, name: &str) -> Option<&str> {
        self.get(name).map(String::as_str)
    }
    fn lookup_array(&self, _name: &str) -> Option<&[String]> {
        None
    }
}

impl ConstLookup for HashMap<String, ConstValue> {
    fn lookup_scalar(&self, name: &str) -> Option<&str> {
        match self.get(name) {
            Some(ConstValue::Scalar(s)) => Some(s.as_str()),
            _ => None,
        }
    }
    fn lookup_array(&self, name: &str) -> Option<&[String]> {
        match self.get(name) {
            Some(ConstValue::Array(elems)) => Some(elems.as_slice()),
            _ => None,
        }
    }
}

/// Build the set of variables whose value is *provably constant* for the whole
/// command. A variable qualifies only when it has exactly one straight-line,
/// static-literal assignment that executes unconditionally before any use, and
/// is never reassigned or `unset`.
///
/// The analysis is a structural walk, not a path enumeration: an assignment
/// inside a conditional, loop, function body, subshell, or pipeline stage is
/// treated as "not provable" and disqualifies the variable. Anything uncertain
/// (a substitution RHS, an unresolved variable, a glob, a loop variable, a
/// prefix assignment, a reassignment) keeps the variable out of the result, so
/// callers fall back to treating its uses as dynamic.
pub fn constant_env(cmd: &Command) -> HashMap<String, ConstValue> {
    let mut occ: HashMap<String, Occurrence> = HashMap::new();
    // Names that have already been *read* (appeared as a parameter expansion in
    // some word) on the straight-line spine seen so far. A constant assignment
    // to a name already in this set is disqualified: at the earlier use site the
    // value was the inherited environment, not the later assignment (D2).
    let mut used: HashSet<String> = HashSet::new();
    collect(cmd, false, &mut occ, &mut used);
    occ.into_iter()
        .filter_map(|(name, o)| match o {
            Occurrence::Constant(value) => Some((name, value)),
            Occurrence::Disqualified => None,
        })
        .collect()
}

/// What we have learned about a variable so far. The first qualifying
/// assignment makes it `Constant`; any second occurrence of any kind, or any
/// disqualifying occurrence, makes it `Disqualified` for good.
enum Occurrence {
    Constant(ConstValue),
    Disqualified,
}

/// Record a binding whose RHS is a proven static literal (scalar or indexed
/// array) at straight-line top level. A second binding of the same name flips
/// it to disqualified.
fn record_constant(occ: &mut HashMap<String, Occurrence>, name: &str, value: ConstValue) {
    occ.entry(name.to_string())
        .and_modify(|e| *e = Occurrence::Disqualified)
        .or_insert(Occurrence::Constant(value));
}

/// Record an occurrence that can never qualify (nested, prefix, non-literal,
/// reassignment, loop variable, or `unset`). It permanently disqualifies the
/// name, including over a previously-recorded constant.
fn record_disqualified(occ: &mut HashMap<String, Occurrence>, name: &str) {
    occ.insert(name.to_string(), Occurrence::Disqualified);
}

/// The provable finite value set of a `for` loop's variable when the loop is
/// **statically enumerable** against `env`, or `None` otherwise.
///
/// A loop is enumerable iff every word of its list resolves to a value the
/// shell passes verbatim (a static literal or a provably-constant variable —
/// no command/process substitution, glob, `$@`/`$*`, or non-constant variable)
/// and the loop variable is not reassigned or `unset` anywhere in the body. The
/// returned vector has one entry per list word, in source order (each verbatim
/// word contributes exactly one value — bash word-splitting cannot apply to a
/// verbatim word).
///
/// `env` is the command's [`constant_env`]; passing it lets `for k in $D x`
/// enumerate when `D` is provably constant. Soundness rests on every list word
/// being verbatim, so the resolved value is exactly what each iteration binds.
pub fn enumerable_for_values<L: ConstLookup>(
    var: &str,
    words: &[Word],
    body: &Command,
    env: &L,
) -> Option<Vec<String>> {
    // The loop variable must survive the body unmutated, or a later use sees a
    // different value than the iteration binding (D2). Any reassignment or
    // `unset` of `var` in the body disqualifies the whole loop, conservatively.
    if body_mutates(body, var) {
        return None;
    }
    let mut values = Vec::with_capacity(words.len());
    for word in words {
        // A word is enumerable only when every expansion resolves verbatim:
        // this rejects command/process substitutions, globs, `$@`/`$*` (an
        // unset special parameter never resolves), and non-constant variables.
        if !word.resolves_to_verbatim_literal(env) {
            return None;
        }
        values.push(word.resolve(env).to_str());
    }
    Some(values)
}

/// Whether `body` reassigns or `unset`s `name` anywhere. Walks the whole
/// subtree; over-approximating toward "mutated" only costs precision (the loop
/// falls back to flagged), never soundness — so this errs broad on every shell
/// construct that can rebind a variable, including builtins that read external
/// input into it (`read`, `mapfile`, …). Missing a rebind would let a later use
/// resolve to the seeded list value while bash holds a different, possibly
/// attacker-controlled, value — a wrong-`:allow` (security review C2).
fn body_mutates(body: &Command, name: &str) -> bool {
    match body {
        Command::Assignment(a) => a.name == name,
        Command::Simple(sc) => simple_mutates(sc, name),
        // A nested `for NAME …` rebinds the variable: bash for-loops do not scope
        // their variable, so after the inner loop it retains the inner list's
        // last value. `children()` exposes only the inner body, never its `var`,
        // so this arm is required — without it a use of the variable after the
        // inner loop would resolve to the (stale) outer seed (security review
        // C-NEW). Conservative even inside a subshell, where bash *does* scope
        // it: disqualifying there only over-asks.
        Command::For { var, body, .. } => var == name || body_mutates(body, name),
        other @ (Command::Pipeline(_)
        | Command::And(_, _)
        | Command::Or(_, _)
        | Command::Sequence(_)
        | Command::Background(_)
        | Command::Subshell(_)
        | Command::BraceGroup(_)
        | Command::If { .. }
        | Command::Loop { .. }
        | Command::Case { .. }
        | Command::FunctionDef { .. }
        | Command::Redirected { .. }) => other.children().iter().any(|c| body_mutates(c, name)),
    }
}

/// Whether a single simple command rebinds `name`: a prefix assignment, or any
/// builtin that assigns/reads into it. Over-broad on purpose (see `body_mutates`).
fn simple_mutates(sc: &SimpleCommand, name: &str) -> bool {
    // A command-prefix assignment (`k=x cmd`) rebinds for that command, and a
    // bare-assignment simple command (`k=x`) persists — both flow through here.
    if sc.assignments.iter().any(|a| a.name == name) {
        return true;
    }
    let args = || sc.words.iter().skip(1);
    let names_operand = |w: &Word| literal_name(w).as_deref() == Some(name);
    let assigns_operand =
        |w: &Word| parse_assignment_word(w).is_some_and(|(n, _)| n == name) || names_operand(w);
    match sc.command_name() {
        Some("unset") => args().any(names_operand),
        // Declaration builtins: `declare k=…`, `local k`, `readonly k=…`, etc.
        // bind the bare name or a `name=value` operand.
        Some("export" | "declare" | "typeset" | "local" | "readonly") => {
            args().any(assigns_operand)
        }
        // `let k=…` / `let "k += 1"` assigns via an arithmetic operand whose
        // left-hand side is the name. Conservatively: the name appears as the
        // identifier prefix of any operand.
        Some("let") => args().any(|w| arith_assigns(&w.to_str(), name)),
        // `printf -v k …` writes the formatted output into `k`.
        Some("printf") => printf_target_is(sc, name),
        // These builtins read external input (stdin, a file, parsed options)
        // into the named variable(s). If the loop variable is (or could be) a
        // target, it is rebound to an unprovable value.
        Some("read" | "mapfile" | "readarray") => read_targets(sc, name),
        // `getopts optstring NAME [args]` stores the parsed option into NAME
        // (the third word).
        Some("getopts") => sc.words.get(2).is_some_and(names_operand),
        _ => false,
    }
}

/// Whether `printf`'s `-v NAME` target (the var it writes into) is `name`.
/// Handles both the separate (`-v k`) and joined (`-vk`) spellings.
fn printf_target_is(sc: &SimpleCommand, name: &str) -> bool {
    let mut it = sc.words.iter().skip(1);
    while let Some(w) = it.next() {
        let text = w.to_str();
        if text == "-v" {
            if it.next().map(|n| n.to_str()).as_deref() == Some(name) {
                return true;
            }
        } else if let Some(rest) = text.strip_prefix("-v")
            && !rest.is_empty()
            && rest == name
        {
            return true;
        }
    }
    false
}

/// Whether a `read`/`mapfile`/`readarray` invocation could store into `name`.
/// Over-approximates: the name appearing as any non-flag operand, or the value
/// of an array-target flag (`-a name`, `-A name`), counts. A flagless `read`
/// with no operands writes `REPLY`, never a named var, so it does not mutate.
fn read_targets(sc: &SimpleCommand, name: &str) -> bool {
    let mut it = sc.words.iter().skip(1).peekable();
    while let Some(w) = it.next() {
        let text = w.to_str();
        if let Some(flag) = text.strip_prefix('-') {
            // `-a name` / `-A name` (mapfile/read array target) and `-d`/`-n`/…
            // take a following argument; only the array-target flags name a
            // destination variable. Be conservative: if a flag's argument is
            // `name`, treat it as a target.
            if flag.is_empty() {
                continue;
            }
            // Joined `-aname` form.
            if (flag.starts_with('a') || flag.starts_with('A')) && &flag[1..] == name {
                return true;
            }
            // Separate `-a name` form: consume the next word as the flag's value.
            if matches!(
                flag,
                "a" | "A" | "d" | "n" | "N" | "t" | "u" | "C" | "c" | "i" | "O" | "s"
            ) && it.peek().map(|n| n.to_str()).as_deref() == Some(name)
            {
                return true;
            }
            continue;
        }
        // A non-flag operand is a destination variable name.
        if text == name {
            return true;
        }
    }
    false
}

/// Whether the `let` arithmetic operand `expr` assigns to `name` — its
/// identifier left-hand side is `name`, possibly with a compound operator
/// (`name=`, `name+=`, `name++`, `name--`, `name *=`, …). Conservative: any
/// occurrence of `name` immediately followed by an assignment/increment operator.
fn arith_assigns(expr: &str, name: &str) -> bool {
    let trimmed = expr.trim_start();
    let Some(rest) = trimmed.strip_prefix(name) else {
        // `let` can also carry leading `((`/whitespace; scan token-wise as a
        // fallback so `let "k += 1"` (quoted) and bare forms both match.
        return arith_assigns_scan(trimmed, name);
    };
    // The char after the name must end the identifier (not extend it) and begin
    // an assignment/increment.
    let after = rest.trim_start();
    after.starts_with('=')
        || after.starts_with("+=")
        || after.starts_with("-=")
        || after.starts_with("*=")
        || after.starts_with("/=")
        || after.starts_with("%=")
        || after.starts_with("++")
        || after.starts_with("--")
        || arith_assigns_scan(trimmed, name)
}

/// Token-wise fallback for `arith_assigns`: find `name` as a standalone
/// identifier followed (after optional spaces) by an assignment/increment.
fn arith_assigns_scan(expr: &str, name: &str) -> bool {
    let bytes = expr.as_bytes();
    let nb = name.as_bytes();
    let mut i = 0;
    while i + nb.len() <= bytes.len() {
        let boundary_before = i == 0 || !is_ident_byte(bytes[i - 1]);
        let matches_here = &bytes[i..i + nb.len()] == nb;
        let boundary_after = i + nb.len() == bytes.len() || !is_ident_byte(bytes[i + nb.len()]);
        if boundary_before && matches_here && boundary_after {
            let after = expr[i + nb.len()..].trim_start();
            if after.starts_with('=')
                || after.starts_with("+=")
                || after.starts_with("-=")
                || after.starts_with("*=")
                || after.starts_with("/=")
                || after.starts_with("%=")
                || after.starts_with("++")
                || after.starts_with("--")
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

fn collect(
    cmd: &Command,
    nested: bool,
    occ: &mut HashMap<String, Occurrence>,
    used: &mut HashSet<String>,
) {
    match cmd {
        Command::Assignment(a) => match &a.value {
            AssignmentValue::Scalar(w) => record_assignment(&a.name, w, nested, occ, used),
            // An array literal (`arr=(a b c)`). Record the names its element
            // words read (in source order, before recording), then record the
            // array as a constant when every element is a provable literal and
            // the kind is indexed; otherwise disqualify.
            AssignmentValue::Array {
                array_kind,
                elements,
            } => {
                for w in elements {
                    mark_used(w, used);
                }
                record_array_assignment(&a.name, *array_kind, elements, nested, occ, used);
            }
        },
        Command::Simple(sc) => collect_simple(sc, nested, occ, used),
        Command::For { var, body, .. } => {
            // The loop variable is rebound on each iteration — never constant.
            record_disqualified(occ, var);
            collect(body, true, occ, used);
        }
        // Straight-line composition keeps the current nesting level.
        Command::Sequence(cmds) => {
            for c in cmds {
                collect(c, nested, occ, used);
            }
        }
        Command::Redirected { command, .. } => collect(command, nested, occ, used),
        // Everything else (pipelines, subshells, brace groups, conditionals,
        // loops, function bodies, `&&`/`||`, background) is conditional or
        // runs in a subshell: assignments within may not execute, may execute
        // out of order, or may not persist. Treat their contents as nested.
        other @ (Command::Pipeline(_)
        | Command::And(_, _)
        | Command::Or(_, _)
        | Command::Background(_)
        | Command::Subshell(_)
        | Command::BraceGroup(_)
        | Command::If { .. }
        | Command::Loop { .. }
        | Command::Case { .. }
        | Command::FunctionDef { .. }) => {
            for child in other.children() {
                collect(child, true, occ, used);
            }
        }
    }
}

fn collect_simple(
    sc: &SimpleCommand,
    nested: bool,
    occ: &mut HashMap<String, Occurrence>,
    used: &mut HashSet<String>,
) {
    // Record the names this command reads *before* any assignment it performs,
    // so a name read here cannot be established as constant by a later
    // assignment on the spine (D2). Both the assignment values and the argv
    // words are read at this point in source order.
    for a in &sc.assignments {
        for w in a.value.words() {
            mark_used(w, used);
        }
    }
    for word in &sc.words {
        mark_used(word, used);
    }

    // A prefix assignment (`VAR=lit cmd`) binds only the invoked command's
    // environment and does not persist, so it can never be the constant
    // binding for a later use. Recording it as an occurrence also disqualifies
    // a name that is otherwise assigned at top level (ambiguous).
    for a in &sc.assignments {
        record_disqualified(occ, &a.name);
    }

    // An array element assignment (`arr[i]=x`) or append (`arr+=…`) parses as
    // an ordinary command word, not an `Assignment` node, so it must be
    // detected here and disqualify the array name — otherwise a later
    // `"${arr[@]}"` use would resolve to the pre-mutation sequence (unsound).
    // Scanning every word over-approximates (an `echo arr[0]=x` argument also
    // disqualifies `arr`), which only costs precision, never soundness.
    for word in &sc.words {
        if let Some(name) = array_mutation_target(word) {
            record_disqualified(occ, &name);
        }
    }

    match sc.command_name() {
        Some("export") => {
            for word in sc.words.iter().skip(1) {
                if let Some((name, value)) = parse_assignment_word(word) {
                    record_assignment(&name, &value, nested, occ, used);
                }
                // A bare `export FOO` re-exports an existing value without
                // rebinding it, so it is left alone.
            }
        }
        Some("unset") => {
            for word in sc.words.iter().skip(1) {
                if let Some(name) = unset_target_name(word) {
                    record_disqualified(occ, &name);
                }
            }
        }
        _ => {}
    }
}

fn record_assignment(
    name: &str,
    value: &Word,
    nested: bool,
    occ: &mut HashMap<String, Occurrence>,
    used: &mut HashSet<String>,
) {
    match literal_value(value) {
        // A name read earlier on the spine takes its value from the inherited
        // environment at that use, not from this assignment (D2): disqualify.
        Some(v) if !nested && !used.contains(name) => {
            record_constant(occ, name, ConstValue::Scalar(v))
        }
        _ => record_disqualified(occ, name),
    }
}

/// Record an array-literal assignment (`arr=(a b c)`) as a provably-constant
/// indexed array when every condition holds; otherwise disqualify the name.
///
/// The array qualifies only when: its kind is **indexed** (associative element
/// order is unspecified, so resolving `"${m[@]}"` would be unsound); every
/// element is a provable static literal; the assignment is straight-line
/// (`!nested`); and the name was not read earlier on the spine (use-order, D2).
/// A second array assignment to the name flips it to disqualified via
/// [`record_constant`]'s dup handling, which is how an `arr+=(…)` append (the
/// parser models it as a fresh array assignment to the same name) disqualifies.
fn record_array_assignment(
    name: &str,
    array_kind: ArrayKind,
    elements: &[Word],
    nested: bool,
    occ: &mut HashMap<String, Occurrence>,
    used: &mut HashSet<String>,
) {
    if array_kind != ArrayKind::Indexed || nested || used.contains(name) {
        record_disqualified(occ, name);
        return;
    }
    let mut values = Vec::with_capacity(elements.len());
    for w in elements {
        match literal_element(w) {
            Some(v) => values.push(v),
            // Any non-literal element (command substitution, glob, unresolved
            // variable) keeps the whole array unresolved (all-or-nothing).
            None => {
                record_disqualified(occ, name);
                return;
            }
        }
    }
    record_constant(occ, name, ConstValue::Array(values));
}

/// Record the variable name each parameter expansion in this word *reads* —
/// the `$NAME`/`${NAME}`/`${NAME…}` head — recursing through double quotes and
/// the structured substitutions captured out of operator operands. These are
/// the reads `Word::resolve` resolves directly, and are the ones the use-order
/// check (D2) must order against assignments.
///
/// Two read positions are deliberately *not* tracked, and both are sound:
/// command/arithmetic substitution bodies (`$(…)`, `$((…))`) run in a subshell
/// the analysis already treats as unprovable; and a bare `$VAR` left as verbatim
/// text inside an operator operand (`${X:-$VAR}`) is not resolved by
/// `resolve_param_op` either (operands with such reads stay unresolved, see
/// `op_operands_are_inert`), so a later constant binding of that name is never
/// actually read into this word. The only ordering that can produce a wrong
/// resolution — a name read *before* its sole assignment, at the resolved use —
/// is always a tracked head read, so D2 catches it.
fn mark_used(word: &Word, used: &mut HashSet<String>) {
    mark_used_parts(&word.parts, used);
}

fn mark_used_parts(parts: &[WordPart], used: &mut HashSet<String>) {
    for part in parts {
        match part {
            WordPart::Parameter(name) | WordPart::ParameterExpansion(name) => {
                used.insert(name.clone());
            }
            WordPart::ParameterExpansionOp { name, embedded, .. } => {
                used.insert(name.clone());
                // Substitutions lexed out of the operator's operands
                // (`${x:-$(cmd)}`) run in a subshell, but any structured reads
                // they carry are still reads on this spine.
                mark_used_parts(embedded, used);
            }
            // A subscripted array reference (`${arr[i]}`, `"${arr[@]}"`) reads
            // the array variable, so the name is a use on this spine: a later
            // sole assignment to it must not be treated as the value seen here
            // (D2). The `Index` subscript may itself read a scalar (`${arr[$i]}`).
            WordPart::ArrayExpansion {
                name, subscript, ..
            } => {
                used.insert(name.clone());
                if let Subscript::Index(w) = subscript {
                    mark_used_parts(&w.parts, used);
                }
            }
            WordPart::DoubleQuoted(inner) => mark_used_parts(inner, used),
            WordPart::Literal(_)
            | WordPart::SingleQuoted(_)
            | WordPart::AnsiCQuoted(_)
            | WordPart::CommandSubstitution { .. }
            | WordPart::Backtick { .. }
            | WordPart::Arithmetic { .. }
            | WordPart::BraceExpansion(_)
            | WordPart::Glob(_)
            | WordPart::ProcessSubstitution { .. }
            | WordPart::Opaque(_) => {}
        }
    }
}

/// The value of an assignment RHS when it is provably a non-empty static
/// literal. Resolving against an empty env routes parameter expansions through
/// `resolve_param_op`; with nothing to resolve, any expansion, substitution,
/// glob, or opaque part keeps the word non-literal and yields `None`.
fn literal_value(value: &Word) -> Option<String> {
    let resolved = value.resolve(&HashMap::<String, String>::new());
    if !resolved.is_literal() {
        return None;
    }
    let v = resolved.to_str();
    (!v.is_empty()).then_some(v)
}

/// The value of a single array element when it is a provable static literal.
/// Unlike [`literal_value`], an empty element (`arr=("" b)`) is admitted — an
/// empty string is a legitimate array element, not the "no literal" signal it
/// is for a scalar binding. Any dynamic, glob, brace, or opaque part keeps the
/// element non-literal and yields `None`, which disqualifies the whole array.
fn literal_element(value: &Word) -> Option<String> {
    // `is_literal` alone admits a glob/brace (it tracks only substitutions and
    // opaque values), but bash glob-/brace-expands array elements at assignment
    // time, so those are not provable. Require *both* not-dynamic/opaque and
    // not-expansion-bearing (which also rejects a leading tilde).
    (value.is_literal() && !value.is_expansion_bearing()).then(|| value.to_str())
}

/// Split a single `NAME=VALUE` word (as it appears in `export NAME=VALUE`)
/// into the name and a value word. Returns `None` for a bare `NAME` (no `=`)
/// or an invalid name. The value word preserves any dynamic trailing parts so
/// `export X=$(cmd)` resolves to a non-literal value and is disqualified.
fn parse_assignment_word(word: &Word) -> Option<(String, Word)> {
    let WordPart::Literal(lit) = word.parts.first()? else {
        return None;
    };
    let eq = lit.find('=')?;
    let name = &lit[..eq];
    if !is_valid_name(name) {
        return None;
    }
    let mut value_parts = Vec::new();
    let rest = &lit[eq + 1..];
    if !rest.is_empty() {
        value_parts.push(WordPart::Literal(rest.to_string()));
    }
    value_parts.extend(word.parts.iter().skip(1).cloned());
    Some((name.to_string(), Word { parts: value_parts }))
}

/// The bare array name an `unset` argument removes, stripping any element
/// subscript: `unset arr` and `unset 'arr[0]'` both disqualify `arr`. Returns
/// `None` for a non-literal argument (`unset $X` names nothing statically) or
/// an invalid identifier.
fn unset_target_name(word: &Word) -> Option<String> {
    if !word.is_literal() {
        return None;
    }
    let s = word.to_str();
    let bare = match s.find('[') {
        Some(open) => &s[..open],
        None => s.as_str(),
    };
    is_valid_name(bare).then(|| bare.to_string())
}

/// If `word` is an array-mutating assignment in command/prefix position — an
/// element assignment (`arr[i]=…`) or an append (`arr+=…` / `arr[i]+=…`) —
/// return the bare array name it mutates. These parse as ordinary command
/// words rather than `Assignment` nodes, so the constant-array analysis must
/// detect them here. A plain `name=value` (no `+`, no subscript) is a scalar
/// assignment handled on the assignment path and is not flagged here.
fn array_mutation_target(word: &Word) -> Option<String> {
    // Flatten the word: a subscript like `[1]` lexes as its own `Glob` part, so
    // `parts.first()` is only `arr`, not the whole `arr[1]=x`. The flattened
    // form reunites them.
    let s = word.to_str();
    let eq = s.find('=')?;
    let lhs = &s[..eq];
    let appended = lhs.ends_with('+');
    let lhs = lhs.strip_suffix('+').unwrap_or(lhs);
    let (bare, subscripted) = match lhs.find('[') {
        Some(open) => (&lhs[..open], true),
        None => (lhs, false),
    };
    if !appended && !subscripted {
        return None;
    }
    is_valid_name(bare).then(|| bare.to_string())
}

/// The plain variable name of a literal identifier argument (used by the
/// loop-body mutation scan). Returns `None` for a subscripted or non-literal
/// word.
fn literal_name(word: &Word) -> Option<String> {
    if !word.is_literal() {
        return None;
    }
    let name = word.to_str();
    is_valid_name(&name).then_some(name)
}

fn is_valid_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}
