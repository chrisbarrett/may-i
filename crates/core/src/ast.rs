// Core AST types for the unified rule DSL.
// Redesigned for unified effect model where everything returns Decision | Nil.

use std::path::PathBuf;

use crate::doc::Doc;
use crate::pattern::{ArgPattern, CommandPattern};
use crate::primitives::{Decision, ToDoc};
use crate::span::Span;

/// Whether a config form came from the primary config or a loaded file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Provenance {
    /// From the root config file (implicitly trusted).
    PrimaryConfig,
    /// From a file included via `(load ...)`.
    Loaded { path: PathBuf },
    /// Shipped with the binary (e.g. wrapper-tool parser declarations).
    /// Implicitly trusted; user declarations of the same name shadow
    /// without a duplicate warning.
    Prelude,
}

impl Provenance {
    /// Returns true if this is a `Loaded` variant (regardless of path).
    pub fn is_loaded(&self) -> bool {
        matches!(self, Provenance::Loaded { .. })
    }

    /// Returns true if this entry came from the binary's built-in
    /// prelude rather than a user-authored config.
    pub fn is_prelude(&self) -> bool {
        matches!(self, Provenance::Prelude)
    }

    /// Returns the source file path if this is a `Loaded` variant.
    pub fn path(&self) -> Option<&std::path::Path> {
        match self {
            Provenance::Loaded { path } => Some(path),
            Provenance::PrimaryConfig | Provenance::Prelude => None,
        }
    }
}

/// A value with source span tracking.
#[derive(Debug, Clone)]
pub struct Spanned<T> {
    pub value: T,
    pub span: Span,
}

impl<T> Spanned<T> {
    /// Create a new spanned value.
    pub fn new(value: T, span: Span) -> Self {
        Self { value, span }
    }

    #[cfg(test)]
    pub(crate) fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Spanned<U> {
        Spanned {
            value: f(self.value),
            span: self.span,
        }
    }
}

/// Result of evaluating an effect: either a terminal decision or Nil (no match).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectResult {
    /// Terminal decision reached with optional reason.
    Decision(Decision, Option<String>),
    /// No match - continue evaluating.
    Nil,
}

impl EffectResult {
    /// Check if this is Nil.
    pub fn is_nil(&self) -> bool {
        matches!(self, EffectResult::Nil)
    }

    #[cfg(any(test, feature = "test-generators"))]
    pub fn is_decision(&self) -> bool {
        matches!(self, EffectResult::Decision(_, _))
    }

    #[cfg(any(test, feature = "test-generators"))]
    pub fn decision(&self) -> Option<Decision> {
        match self {
            EffectResult::Decision(d, _) => Some(*d),
            EffectResult::Nil => None,
        }
    }

    #[cfg(any(test, feature = "test-generators"))]
    pub fn reason(&self) -> Option<&str> {
        match self {
            EffectResult::Decision(_, r) => r.as_deref(),
            EffectResult::Nil => None,
        }
    }
}

/// Unified Effect type where all forms evaluate to Decision | Nil.
#[derive(Debug, Clone)]
pub enum Effect {
    // Terminal decisions
    /// A terminal decision (allow, ask, or deny) with optional reason.
    /// Syntax: `(allow)`, `(ask "reason")`, etc.
    Terminal {
        decision: Decision,
        reason: Option<String>,
    },

    // Pattern effects (return Allow on match, Nil otherwise)
    /// Command pattern match - returns Allow if command matches, Nil otherwise.
    /// Syntax: `"git"` or `(or "git" "gh")` in rule position
    CommandPattern(CommandPattern),

    /// Argument pattern match - returns Allow if args match, Nil otherwise.
    /// Syntax: `(positional ...)`, `(exact ...)`, `(anywhere ...)`, etc.
    ArgPattern(ArgPattern),

    // Effect combinators
    /// All effects must return non-Nil; returns first Nil or last effect's result.
    /// Syntax: `(and EFFECT ...)`
    And { effects: Vec<Spanned<Effect>> },

    /// Returns first non-Nil effect, or Nil if all return Nil.
    /// Syntax: `(or EFFECT ...)`
    Or { effects: Vec<Spanned<Effect>> },

    /// Inverts Allow/Nil, passes through Ask/Deny.
    /// Syntax: `(not EFFECT)`
    Not { effect: Box<Spanned<Effect>> },

    // Conditionals (predicates used for branching)
    /// Evaluate effect only if predicate matches.
    /// Syntax: `(when PREDICATE EFFECT)`
    When {
        predicate: Spanned<Predicate>,
        effect: Box<Spanned<Effect>>,
    },

    /// Evaluate effect only if predicate doesn't match.
    /// Syntax: `(unless PREDICATE EFFECT)`
    Unless {
        predicate: Spanned<Predicate>,
        effect: Box<Spanned<Effect>>,
    },

    /// Choose branch based on predicate.
    /// Syntax: `(if PREDICATE THEN-EFFECT ELSE-EFFECT)`
    If {
        predicate: Spanned<Predicate>,
        then_effect: Box<Spanned<Effect>>,
        else_effect: Box<Spanned<Effect>>,
    },

    /// First matching branch wins.
    /// Syntax: `(cond ((PREDICATE EFFECT) ...) [else EFFECT])`
    Cond {
        branches: Vec<(Spanned<Predicate>, Spanned<Effect>)>,
        fallback: Option<Box<Spanned<Effect>>>,
    },

    /// Recurse on the value of `binding`, accumulating `:via PROG` in
    /// inner facts. Lifts the bound value into a command line (single
    /// token → tokenise; token list → join then tokenise) and
    /// re-evaluates against the active rule set.
    /// Syntax: `(authorise #var)`
    Authorise { binding: BindingName },
}

impl Effect {
    #[cfg(test)]
    pub(crate) fn allow(reason: Option<String>) -> Self {
        Effect::Terminal {
            decision: Decision::Allow,
            reason,
        }
    }

    #[cfg(test)]
    pub(crate) fn ask(reason: Option<String>) -> Self {
        Effect::Terminal {
            decision: Decision::Ask,
            reason,
        }
    }

    #[cfg(test)]
    pub(crate) fn deny(reason: Option<String>) -> Self {
        Effect::Terminal {
            decision: Decision::Deny,
            reason,
        }
    }

    #[cfg(test)]
    pub(crate) fn command_pattern(pattern: CommandPattern) -> Self {
        Effect::CommandPattern(pattern)
    }

    #[cfg(test)]
    pub(crate) fn arg_pattern(pattern: ArgPattern) -> Self {
        Effect::ArgPattern(pattern)
    }

    /// Check if this is a terminal effect (Allow, Ask, or Deny).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Effect::Terminal { .. })
    }

    /// Check if this effect would match the given command name.
    /// Only meaningful for CommandPattern effects.
    pub fn matches_command(&self, command: &str) -> bool {
        match self {
            Effect::CommandPattern(pattern) => pattern.is_match(command),
            _ => false,
        }
    }

    #[cfg(test)]
    fn is_pattern(&self) -> bool {
        matches!(self, Effect::CommandPattern(_) | Effect::ArgPattern(_))
    }

    #[cfg(test)]
    fn is_combinator(&self) -> bool {
        matches!(
            self,
            Effect::And { .. } | Effect::Or { .. } | Effect::Not { .. }
        )
    }

    #[cfg(test)]
    fn is_conditional(&self) -> bool {
        matches!(
            self,
            Effect::When { .. } | Effect::Unless { .. } | Effect::If { .. } | Effect::Cond { .. }
        )
    }
}

impl std::fmt::Display for Effect {
    #[coverage(off)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Effect::Terminal {
                decision,
                reason: None,
            } => write!(f, "(effect {})", decision.keyword()),
            Effect::Terminal {
                decision,
                reason: Some(r),
            } => write!(f, "(effect {} \"{}\")", decision.keyword(), r),
            Effect::CommandPattern(_) => write!(f, "<command-pattern>"),
            Effect::ArgPattern(_) => write!(f, "<arg-pattern>"),
            Effect::And { .. } => write!(f, "<and-effect>"),
            Effect::Or { .. } => write!(f, "<or-effect>"),
            Effect::Not { .. } => write!(f, "<not-effect>"),
            Effect::When { .. } => write!(f, "<when-effect>"),
            Effect::Unless { .. } => write!(f, "<unless-effect>"),
            Effect::If { .. } => write!(f, "<if-effect>"),
            Effect::Cond { .. } => write!(f, "<cond-effect>"),
            Effect::Authorise { binding } => write!(f, "(authorise {binding})"),
        }
    }
}

/// Predicate for use in conditional contexts (when/unless/if/cond).
/// Predicates evaluate to Match/NoMatch for branching decisions.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Predicate {
    /// Fact query: checks if a fact exists or matches a pattern.
    /// Syntax: `(fact? FACT-QUERY)` (renamed from `has`)
    Fact(FactQuery),

    /// Argument pattern match as predicate: checks if arguments match.
    /// Returns Match if pattern matches, NoMatch otherwise.
    /// Syntax: `(positional ...)`, `(exact ...)`, `(anywhere ...)`, etc.
    Arg(ArgPattern),

    /// Reference to a named predicate defined with `(define NAME PREDICATE)`.
    /// Syntax: `NAME` (atom reference, resolved during validation)
    Named(String),

    /// All sub-predicates must match.
    /// Syntax: `(and PREDICATE ...)`
    And(Vec<Predicate>),

    /// Any sub-predicate must match.
    /// Syntax: `(or PREDICATE ...)`
    Or(Vec<Predicate>),

    /// Inverts a sub-predicate.
    /// Syntax: `(not PREDICATE)`
    Not(Box<Predicate>),

    /// True iff the named parser-binding resolves to a value (not
    /// `Unbound`) in the active binding environment.
    /// Syntax: `(bound? #var)`
    Bound { binding: BindingName },

    /// True iff the named parser-binding resolves and its value
    /// matches `pattern` (Token values matched directly; Tokens values
    /// coerced via space-join).
    /// Syntax: `(matches? #var PAT)`
    Matches {
        binding: BindingName,
        pattern: crate::pattern::Expr<Effect>,
    },
}

impl Predicate {
    /// Create a simple fact presence check.
    pub fn fact_presence(key: impl Into<String>) -> Self {
        Predicate::Fact(FactQuery::Presence {
            key: crate::Keyword::new(key).unwrap(),
        })
    }

    #[cfg(test)]
    fn fact_value(key: impl Into<String>, value: impl Into<String>) -> Self {
        use crate::predicates::FactPattern;
        Predicate::Fact(FactQuery::Value {
            key: crate::Keyword::new(key).unwrap(),
            pattern: FactPattern::Literal(value.into()),
        })
    }

    #[cfg(test)]
    pub(crate) fn arg(pattern: ArgPattern) -> Self {
        Predicate::Arg(pattern)
    }

    #[cfg(test)]
    pub(crate) fn and(predicates: Vec<Predicate>) -> Self {
        if predicates.len() == 1 {
            predicates.into_iter().next().unwrap()
        } else {
            Predicate::And(predicates)
        }
    }

    #[cfg(test)]
    pub(crate) fn or(predicates: Vec<Predicate>) -> Self {
        if predicates.len() == 1 {
            predicates.into_iter().next().unwrap()
        } else {
            Predicate::Or(predicates)
        }
    }

    #[cfg(test)]
    pub(crate) fn negate(predicate: Predicate) -> Self {
        Predicate::Not(Box::new(predicate))
    }
}

impl ToDoc for Predicate {
    fn to_doc(&self) -> Doc {
        match self {
            Predicate::Fact(query) => Doc::list(vec![Doc::atom("fact?"), query.to_doc()]),
            Predicate::Arg(_) => Doc::atom("<arg-predicate>"),
            Predicate::Named(name) => Doc::atom(name.clone()),
            Predicate::And(preds) => {
                let mut cs = vec![Doc::atom("and")];
                cs.extend(preds.iter().map(|p| p.to_doc()));
                Doc::broken_list(cs)
            }
            Predicate::Or(preds) => {
                let mut cs = vec![Doc::atom("or")];
                cs.extend(preds.iter().map(|p| p.to_doc()));
                Doc::broken_list(cs)
            }
            Predicate::Not(pred) => Doc::list(vec![Doc::atom("not"), pred.to_doc()]),
            Predicate::Bound { binding } => {
                Doc::list(vec![Doc::atom("bound?"), Doc::atom(binding.to_string())])
            }
            Predicate::Matches { binding, .. } => Doc::list(vec![
                Doc::atom("matches?"),
                Doc::atom(binding.to_string()),
                Doc::atom("<expr>"),
            ]),
        }
    }
}

/// A predicate with source span tracking.
pub type SpannedPredicate = Spanned<Predicate>;

/// Fact query types (re-exported from predicates module).
pub use crate::predicates::FactQuery;

/// A named predicate definition.
/// Syntax: `(define NAME PREDICATE)`
#[derive(Debug, Clone)]
pub struct Define {
    /// The name of the predicate.
    pub name: String,

    /// The predicate body.
    pub predicate: SpannedPredicate,

    /// Source span for error reporting.
    pub span: Span,

    /// Where this define came from.
    pub provenance: Provenance,
}

impl Define {
    /// Create a new named predicate definition.
    pub fn new(name: impl Into<String>, predicate: SpannedPredicate, span: Span) -> Self {
        Self {
            name: name.into(),
            predicate,
            span,
            provenance: Provenance::PrimaryConfig,
        }
    }
}

/// An authorization rule.
/// Syntax: `(rule COMMAND EFFECT [CHECK...])`
///
/// A rule takes exactly two positional forms: a command pattern and a single
/// body effect. The body effect can be a terminal, a combinator, or a
/// conditional. Optional `(check ...)` forms may follow.
#[derive(Debug, Clone)]
pub struct Rule {
    /// The command effect (position 1) - must return non-Nil for rule to apply.
    pub command_effect: Spanned<Effect>,

    /// The single body effect for this rule.
    pub effect: Spanned<Effect>,

    /// Validation checks associated with this rule.
    pub checks: Vec<Check>,

    /// Source span for error reporting.
    pub span: Span,

    /// Where this rule came from.
    pub provenance: Provenance,
}

impl Rule {
    /// Create a new rule.
    pub fn new(
        command_effect: Spanned<Effect>,
        effect: Spanned<Effect>,
        checks: Vec<Check>,
        span: Span,
    ) -> Self {
        Self {
            command_effect,
            effect,
            checks,
            span,
            provenance: Provenance::PrimaryConfig,
        }
    }
}

/// Bare-parameter handling policy in arg-parsing styles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PunPolicy {
    /// Bare parameter token (no value, no separator) ⇒ value-less
    /// presence. Matches `(flag X)`, but `(parameter X *)` returns Nil.
    Allow,
    /// Bare parameter token ⇒ tokenisation error.
    Error,
}

impl PunPolicy {
    /// Stable keyword form (`:allow`, `:error`).
    pub fn keyword(&self) -> &'static str {
        match self {
            PunPolicy::Allow => ":allow",
            PunPolicy::Error => ":error",
        }
    }

    /// Parse from keyword form.
    pub fn from_keyword(s: &str) -> Option<Self> {
        match s {
            ":allow" => Some(PunPolicy::Allow),
            ":error" => Some(PunPolicy::Error),
            _ => None,
        }
    }
}

/// Raw style declaration as written in config — fields are optional and
/// `:overrides` is unresolved. Use `StyleRegistry` to resolve into a
/// `Style`.
///
/// This is a parse-time DTO: shape matches the surface PLIST grammar.
#[derive(Debug, Clone)]
pub struct StyleSpec {
    /// Name bound by `(define-arg-style NAME …)`.
    pub name: String,
    /// `:overrides BASE` — resolve before applying this spec's keys.
    pub overrides: Option<String>,
    pub long_prefix: Option<String>,
    pub short_prefix: Option<String>,
    pub separators: Option<Vec<String>>,
    pub combined_shorts: Option<bool>,
    pub first_token_bundle: Option<bool>,
    pub pun: Option<PunPolicy>,
    pub span: Span,
    pub provenance: Provenance,
}

/// Fully resolved arg-parsing style — defaults filled in, `:overrides`
/// chain applied. Private fields with accessors so callers can't mint a
/// `Style` that bypasses validation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Style {
    name: String,
    long_prefix: String,
    short_prefix: String,
    separators: Vec<String>,
    combined_shorts: bool,
    first_token_bundle: bool,
    pun: PunPolicy,
}

impl Style {
    /// Default `gnu`-shaped style — kept here so the resolver can produce
    /// it before the prelude has run, and so tests have a known baseline.
    pub fn default_gnu() -> Self {
        Self {
            name: "gnu".into(),
            long_prefix: "--".into(),
            short_prefix: "-".into(),
            separators: vec![" ".into(), "=".into()],
            combined_shorts: true,
            first_token_bundle: false,
            pun: PunPolicy::Allow,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn long_prefix(&self) -> &str {
        &self.long_prefix
    }
    pub fn short_prefix(&self) -> &str {
        &self.short_prefix
    }
    pub fn separators(&self) -> &[String] {
        &self.separators
    }
    pub fn combined_shorts(&self) -> bool {
        self.combined_shorts
    }
    pub fn first_token_bundle(&self) -> bool {
        self.first_token_bundle
    }
    pub fn pun(&self) -> PunPolicy {
        self.pun
    }
}

/// Errors from style resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StyleResolveError {
    /// `:overrides BASE` named a style that isn't registered.
    UnknownBase { name: String, base: String },
    /// `:overrides` chain forms a cycle.
    Cycle { name: String },
}

impl std::fmt::Display for StyleResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StyleResolveError::UnknownBase { name, base } => {
                write!(f, "style `{name}` overrides unknown base style `{base}`")
            }
            StyleResolveError::Cycle { name } => {
                write!(f, "cycle in `:overrides` chain involving style `{name}`")
            }
        }
    }
}

impl std::error::Error for StyleResolveError {}

/// Resolves named styles by walking `:overrides` chains. Holds the raw
/// specs; resolution is on-demand and produces a `Style`.
#[derive(Debug, Clone, Default)]
pub struct StyleRegistry {
    specs: Vec<StyleSpec>,
}

impl StyleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a spec. If a spec with the same name already exists, the new
    /// one shadows it (`resolve` walks in reverse). Caller is expected to
    /// emit a warning on duplicates if user-visible.
    pub fn push(&mut self, spec: StyleSpec) {
        self.specs.push(spec);
    }

    /// Iterate registered specs (latest insertion last).
    pub fn iter(&self) -> impl Iterator<Item = &StyleSpec> {
        self.specs.iter()
    }

    /// Most recent spec for `name`, if any.
    pub fn get(&self, name: &str) -> Option<&StyleSpec> {
        self.specs.iter().rev().find(|s| s.name == name)
    }

    /// Resolve `name` to a `Style` by walking `:overrides`, then layering
    /// spec keys (this spec last). List-valued keys *replace*, they do
    /// not merge (per design).
    pub fn resolve(&self, name: &str) -> Result<Style, StyleResolveError> {
        let mut visiting = std::collections::HashSet::new();
        self.resolve_inner(name, &mut visiting)
    }

    fn resolve_inner(
        &self,
        name: &str,
        visiting: &mut std::collections::HashSet<String>,
    ) -> Result<Style, StyleResolveError> {
        if !visiting.insert(name.to_string()) {
            return Err(StyleResolveError::Cycle {
                name: name.to_string(),
            });
        }
        let spec = self
            .get(name)
            .ok_or_else(|| StyleResolveError::UnknownBase {
                name: name.to_string(),
                base: name.to_string(),
            })?;

        // Start from base (or default) and overlay this spec.
        let mut base = if let Some(base_name) = &spec.overrides {
            match self.resolve_inner(base_name, visiting) {
                Ok(style) => style,
                Err(StyleResolveError::UnknownBase { base, .. }) => {
                    return Err(StyleResolveError::UnknownBase {
                        name: name.to_string(),
                        base,
                    });
                }
                Err(e) => return Err(e),
            }
        } else {
            // No base: start from a blank slate with the GNU defaults
            // baked in. Spec keys present below override these.
            Style::default_gnu()
        };

        // Rename to this spec.
        base.name = name.to_string();
        if let Some(v) = &spec.long_prefix {
            base.long_prefix = v.clone();
        }
        if let Some(v) = &spec.short_prefix {
            base.short_prefix = v.clone();
        }
        if let Some(v) = &spec.separators {
            base.separators = v.clone();
        }
        if let Some(v) = spec.combined_shorts {
            base.combined_shorts = v;
        }
        if let Some(v) = spec.first_token_bundle {
            base.first_token_bundle = v;
        }
        if let Some(v) = spec.pun {
            base.pun = v;
        }
        visiting.remove(name);
        Ok(base)
    }
}

/// A parser-bound name (the bare identifier from a `#NAME` sigil — the
/// stored form does NOT include the leading `#`). Constructed only via
/// the smart constructor [`BindingName::parse`], which enforces the
/// invariants:
///
/// - non-empty,
/// - no embedded `#` (the sigil belongs to surface syntax, not the value),
/// - no whitespace,
/// - no `:` (binding names are not keyword paths),
/// - starts with an ASCII letter or `_`, then ASCII alphanumeric / `_` / `-`.
///
/// `Display` re-prints the sigil so user-facing output reads naturally.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BindingName(String);

/// Error returned by [`BindingName::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingNameError {
    Empty,
    LeadingSigilOnly,
    InvalidChar(char),
    InvalidStart(char),
}

impl std::fmt::Display for BindingNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindingNameError::Empty => write!(f, "binding name is empty"),
            BindingNameError::LeadingSigilOnly => {
                write!(f, "binding name `#` has no name after the sigil")
            }
            BindingNameError::InvalidChar(c) => {
                write!(f, "binding name contains invalid character {c:?}")
            }
            BindingNameError::InvalidStart(c) => {
                write!(f, "binding name must start with letter or `_`, got {c:?}")
            }
        }
    }
}

impl std::error::Error for BindingNameError {}

impl BindingName {
    /// Parse a binding name from surface syntax. Accepts either
    /// `"#cmd"` (with sigil) or `"cmd"` (bare); stores the bare form.
    pub fn parse(input: impl AsRef<str>) -> Result<Self, BindingNameError> {
        let raw = input.as_ref();
        let bare = raw.strip_prefix('#').unwrap_or(raw);
        if bare.is_empty() {
            return Err(if raw == "#" {
                BindingNameError::LeadingSigilOnly
            } else {
                BindingNameError::Empty
            });
        }
        let mut chars = bare.chars();
        let first = chars.next().expect("non-empty checked above");
        if !(first.is_ascii_alphabetic() || first == '_') {
            return Err(BindingNameError::InvalidStart(first));
        }
        for c in chars {
            if !(c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                return Err(BindingNameError::InvalidChar(c));
            }
        }
        Ok(BindingName(bare.to_owned()))
    }

    /// Bare name (no leading `#`).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Surface form (with leading `#`).
    pub fn with_sigil(&self) -> String {
        format!("#{}", self.0)
    }
}

impl std::fmt::Display for BindingName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.0)
    }
}

impl std::fmt::Debug for BindingName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BindingName(#{})", self.0)
    }
}

/// Flag-scanning mode declared by a parser body's `(flags MODE)` form.
/// Replaces the implicit defaults that the engine previously inferred
/// from the presence/shape of `(tail …)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlagsMode {
    /// `posix` — outer flags appear only before the first positional;
    /// the first non-flag token stops outer scanning. Matches
    /// `POSIXLY_CORRECT` semantics. Default for wrappers like sudo,
    /// xargs, env, timeout.
    Posix,
    /// `permute` — outer flags may appear anywhere; the outer parser
    /// peels declared flags and parameters wherever they occur. Matches
    /// GNU getopt's permuting default.
    Permute,
    /// `(until STR…)` — outer parser scans up to the first occurrence
    /// of any listed boundary token; the boundary token is consumed
    /// and dropped. Used by `mise --` and `nix --command|-c`. The
    /// vector is non-empty.
    Until(Vec<String>),
}

/// A positional declaration in a parser body: `(positional [#var] PAT
/// [QUANT])`. The optional binding promotes the matched arg(s) to
/// `#var` for rule-body reference.
#[derive(Debug, Clone)]
pub struct PositionalDecl {
    pub binding: Option<BindingName>,
    pub pattern: crate::pattern::Expr<Effect>,
    pub quantifier: crate::pattern::Quantifier,
}

/// Parser-level treatment of a parameter's *value*. Future expansion
/// slot (e.g. type-checked values).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ParameterTreatment {
    /// Register as value-bearing only — no extra processing of the value.
    None,
    /// Re-authorise the captured value as a command line via `(authorise)`.
    /// The recursion result becomes a fact `:via NAME`; it does not
    /// short-circuit the outer rule.
    Authorise,
}

/// Capture-shape of a parameter declaration. The default is single-token
/// (the parameter consumes one trailing token); `ManyTill` consumes
/// multiple tokens until a terminator pattern matches, used to model
/// `find -exec … ;` and friends.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Capture {
    /// Single-token capture (the historical and default behaviour).
    Single,
    /// Multi-token capture: consume tokens after the parameter occurrence
    /// until a token matches `terminator`. The terminator is consumed and
    /// discarded; the captured value is the tokens before it joined with
    /// single spaces.
    ManyTill {
        /// Single-token expression matched against each candidate
        /// terminator.
        terminator: crate::pattern::Expr<Effect>,
    },
}

/// One parameter declaration in a `(parser …)` body. `names` lists the
/// short/long spellings (e.g. `["n", "namespace"]`). For a single
/// spelling, the vector has one entry.
#[derive(Debug, Clone)]
pub struct ParameterDecl {
    pub names: Vec<String>,
    pub treatment: ParameterTreatment,
    /// How the parameter consumes tokens at tokenisation time. Defaults
    /// to single-token capture; `ManyTill` supports `find -exec … ;`.
    pub capture: Capture,
    /// Optional `#var` binding for the captured value. When set, the
    /// captured token (or token list for `ManyTill`) is exposed under
    /// this name to rule bodies via `(authorise #var)` / `(matches?
    /// #var …)` / `(bound? #var)`.
    pub binding: Option<BindingName>,
}

/// Parsed `(parser PROGRAM (style STYLE) BODY…)` declaration. The style is
/// referenced by name; resolution against the `StyleRegistry` happens at
/// `Config::parser_for` time.
#[derive(Debug, Clone)]
pub struct Parser {
    pub program: String,
    pub style_name: String,
    /// `(flag NAME)` body items — each entry is a single short/long
    /// spelling list.
    pub flags: Vec<Vec<String>>,
    pub parameters: Vec<ParameterDecl>,
    /// Declared positional slots in source order (parser-body
    /// `(positional [#var] PAT [QUANT])`). Matched in declaration order
    /// against the residual outer slice.
    pub positionals: Vec<PositionalDecl>,
    /// Flag-scanning mode from `(flags MODE)`. Mandatory in the new
    /// parser body.
    pub flags_mode: FlagsMode,
    /// Optional `(rest #var)` declaration. Binds the unconsumed tail
    /// of argv to a name.
    pub rest: Option<BindingName>,
    pub span: Span,
    pub provenance: Provenance,
}

/// Fully-resolved parser ready for the tokeniser: style is looked up,
/// declarations carried verbatim.
#[derive(Debug, Clone)]
pub struct ResolvedParser {
    pub program: String,
    pub style: Style,
    pub flags: Vec<Vec<String>>,
    pub parameters: Vec<ParameterDecl>,
    pub positionals: Vec<PositionalDecl>,
    pub flags_mode: FlagsMode,
    pub rest: Option<BindingName>,
}

impl ResolvedParser {
    /// Synthetic default parser used when no `(parser PROGRAM …)` is
    /// declared: GNU style, no parameter declarations.
    pub fn synthetic_gnu(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            style: Style::default_gnu(),
            flags: Vec::new(),
            parameters: Vec::new(),
            positionals: Vec::new(),
            flags_mode: FlagsMode::Permute,
            rest: None,
        }
    }

    /// Style-aware token form for a parameter/flag name.
    ///
    /// Single-character names are short flags (use the style's
    /// short-prefix); multi-character names are long flags (use the
    /// style's long-prefix).
    pub fn token_for_name(&self, name: &str) -> String {
        if crate::pattern::is_short_flag_name(name) {
            format!("{}{}", self.style.short_prefix(), name)
        } else {
            format!("{}{}", self.style.long_prefix(), name)
        }
    }

    /// All on-the-wire spellings of every parameter declared in this parser.
    pub fn parameter_tokens(&self) -> Vec<String> {
        let mut out = Vec::new();
        for decl in &self.parameters {
            for name in &decl.names {
                let tok = self.token_for_name(name);
                if !out.iter().any(|t| t == &tok) {
                    out.push(tok);
                }
            }
        }
        out
    }

    /// True if `tok` matches any declared parameter spelling.
    pub fn parameter_token_matches(&self, tok: &str) -> bool {
        self.parameter_tokens().iter().any(|t| t == tok)
    }

    /// Find the `ParameterDecl` whose declared spellings include the
    /// canonical short/long *name* of `tok`.
    pub fn parameter_decl_for_token(&self, tok: &str) -> Option<&ParameterDecl> {
        self.parameters
            .iter()
            .find(|decl| decl.names.iter().any(|n| self.token_for_name(n) == tok))
    }

    /// Find the `ParameterDecl` whose token-form is in `tokens`. Used
    /// when the caller has already computed the token list and wants to
    /// look the matching declaration up cheaply.
    pub fn parameter_decl_for_token_in(&self, tokens: &[String]) -> Option<&ParameterDecl> {
        self.parameters.iter().find(|decl| {
            decl.names
                .iter()
                .any(|n| tokens.iter().any(|t| t == &self.token_for_name(n)))
        })
    }
}

/// Top-level configuration for the unified rule DSL.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Named predicate definitions.
    pub defines: Vec<Define>,

    /// Authorization rules.
    pub rules: Vec<Rule>,

    /// Security configuration.
    pub security: SecurityConfig,

    /// Validation checks.
    pub checks: Vec<Check>,

    /// Named arg-parsing style declarations from `(define-arg-style NAME
    /// PLIST)` forms. Kept separate from `defines` for now; will unify
    /// later. Last `define-arg-style` for a given name wins (with a
    /// warning).
    pub style_specs: Vec<StyleSpec>,

    /// Per-program parser declarations from `(parser PROGRAM …)` forms.
    pub parsers: Vec<Parser>,
}

impl Config {
    /// Build a `StyleRegistry` from this config's `style_specs`. Cheap
    /// (specs are small); call from `parser_for`.
    pub fn style_registry(&self) -> StyleRegistry {
        let mut reg = StyleRegistry::new();
        for spec in &self.style_specs {
            reg.push(spec.clone());
        }
        reg
    }

    /// Resolve a parser for `command`. Returns the user's `(parser …)`
    /// declaration with style resolved, or a synthetic GNU parser if
    /// no declaration matches. Style-resolution errors fall back to
    /// the synthetic parser — caller is expected to surface them via
    /// validation upstream.
    pub fn parser_for(&self, command: &str) -> ResolvedParser {
        let Some(parser) = self.parsers.iter().rev().find(|p| p.program == command) else {
            return ResolvedParser::synthetic_gnu(command);
        };
        let registry = self.style_registry();
        let style = registry
            .resolve(&parser.style_name)
            .unwrap_or_else(|_| Style::default_gnu());
        ResolvedParser {
            program: parser.program.clone(),
            style,
            flags: parser.flags.clone(),
            parameters: parser.parameters.clone(),
            positionals: parser.positionals.clone(),
            flags_mode: parser.flags_mode.clone(),
            rest: parser.rest.clone(),
        }
    }

    /// Like `parser_for`, but additionally merges into the resolved
    /// parser any parameter spellings implied by `(parameter X …)`
    /// patterns in rules whose command pattern matches `command`. This
    /// preserves the historic behaviour where rule-level `(parameter …)`
    /// implicitly registers value-bearing flags.
    pub fn parser_for_with_rules(&self, command: &str) -> ResolvedParser {
        let mut parser = self.parser_for(command);
        let existing: Vec<String> = parser
            .parameters
            .iter()
            .flat_map(|d| d.names.clone())
            .collect();
        for name in collect_implicit_parameter_names(&self.rules, command) {
            if !existing.iter().any(|n| n == &name) {
                parser.parameters.push(ParameterDecl {
                    names: vec![name],
                    treatment: ParameterTreatment::None,
                    capture: Capture::Single,
                    binding: None,
                });
            }
        }
        parser
    }
}

/// Walk every rule whose command pattern can match `command` and collect
/// the canonical names of every `(parameter …)` pattern in that rule's
/// body. Used by `Config::parser_for_with_rules` to back-fill the
/// parser with implicit value-bearing parameter declarations.
fn collect_implicit_parameter_names(rules: &[Rule], command: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for rule in rules {
        if !rule.command_effect.value.matches_command(command) {
            continue;
        }
        collect_parameter_names_in_effect(&rule.effect.value, &mut out);
    }
    out
}

fn collect_parameter_names_in_effect(effect: &Effect, out: &mut Vec<String>) {
    use crate::pattern::ArgPattern;
    match effect {
        Effect::ArgPattern(ArgPattern::Parameter { names, .. }) => {
            for name in names {
                if !out.iter().any(|n| n == name) {
                    out.push(name.clone());
                }
            }
        }
        Effect::ArgPattern(ArgPattern::Ordered {
            continuation: Some(cont),
            ..
        }) => collect_parameter_names_in_effect(cont, out),
        Effect::And { effects } | Effect::Or { effects } => {
            for child in effects {
                collect_parameter_names_in_effect(&child.value, out);
            }
        }
        Effect::Not { effect: inner } => collect_parameter_names_in_effect(&inner.value, out),
        Effect::When { effect: body, .. } | Effect::Unless { effect: body, .. } => {
            collect_parameter_names_in_effect(&body.value, out);
        }
        Effect::If {
            then_effect,
            else_effect,
            ..
        } => {
            collect_parameter_names_in_effect(&then_effect.value, out);
            collect_parameter_names_in_effect(&else_effect.value, out);
        }
        Effect::Cond { branches, fallback } => {
            for (_, body) in branches {
                collect_parameter_names_in_effect(&body.value, out);
            }
            if let Some(fb) = fallback {
                collect_parameter_names_in_effect(&fb.value, out);
            }
        }
        _ => {}
    }
}

/// Security configuration.
#[derive(Debug, Clone, Default)]
pub struct SecurityConfig {
    /// Environment variables that are safe to log.
    pub safe_env_vars: std::collections::HashSet<String>,
    /// Whether any safe-env-vars entries came from a loaded file.
    pub has_loaded_env_vars: bool,
}

/// An embedded check for config validation.
#[derive(Debug, Clone)]
pub struct Check {
    /// The command to test.
    pub command: String,

    /// The expected decision.
    pub expected: Decision,

    /// Context facts for the test.
    pub context: crate::context::ContextFacts,

    /// Source span for error reporting.
    pub span: Span,
}

impl ToDoc for Effect {
    fn to_doc(&self) -> Doc {
        match self {
            Effect::Terminal { decision, reason } => {
                let verb = match decision {
                    Decision::Allow => "allow",
                    Decision::Ask => "ask",
                    Decision::Deny => "deny",
                };
                let mut cs = vec![Doc::atom(verb)];
                if let Some(r) = reason {
                    cs.push(Doc::atom(format!("\"{r}\"")));
                }
                Doc::list(cs)
            }
            Effect::CommandPattern(_) => Doc::atom("<command-pattern>"),
            Effect::ArgPattern(_) => Doc::atom("<arg-pattern>"),
            Effect::And { .. } => Doc::atom("<and-effect>"),
            Effect::Or { .. } => Doc::atom("<or-effect>"),
            Effect::Not { .. } => Doc::atom("<not-effect>"),
            Effect::When { .. } => Doc::atom("<when-effect>"),
            Effect::Unless { .. } => Doc::atom("<unless-effect>"),
            Effect::If { .. } => Doc::atom("<if-effect>"),
            Effect::Cond { .. } => Doc::atom("<cond-effect>"),
            Effect::Authorise { binding } => {
                Doc::list(vec![Doc::atom("authorise"), Doc::atom(binding.to_string())])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::{ArgPattern, CommandPattern, MatchMode};
    use crate::span::Span;

    // ── BindingName smart-constructor tests (task 2.7) ─────────────

    #[test]
    fn binding_name_parses_with_sigil() {
        let bn = BindingName::parse("#cmd").expect("ok");
        assert_eq!(bn.as_str(), "cmd");
        assert_eq!(bn.with_sigil(), "#cmd");
        assert_eq!(format!("{bn}"), "#cmd");
    }

    #[test]
    fn binding_name_parses_bare() {
        let bn = BindingName::parse("host").expect("ok");
        assert_eq!(bn.as_str(), "host");
        assert_eq!(bn.with_sigil(), "#host");
    }

    #[test]
    fn binding_name_rejects_empty() {
        assert_eq!(BindingName::parse("").unwrap_err(), BindingNameError::Empty);
    }

    #[test]
    fn binding_name_rejects_lone_sigil() {
        assert_eq!(
            BindingName::parse("#").unwrap_err(),
            BindingNameError::LeadingSigilOnly
        );
    }

    #[test]
    fn binding_name_rejects_internal_sigil() {
        // Embedded `#` is invalid — the sigil belongs to surface syntax only.
        assert!(matches!(
            BindingName::parse("#foo#bar").unwrap_err(),
            BindingNameError::InvalidChar('#')
        ));
    }

    #[test]
    fn binding_name_rejects_whitespace() {
        assert!(matches!(
            BindingName::parse("foo bar").unwrap_err(),
            BindingNameError::InvalidChar(' ')
        ));
    }

    #[test]
    fn binding_name_rejects_colon() {
        // Bindings are not keyword paths.
        assert!(matches!(
            BindingName::parse("foo:bar").unwrap_err(),
            BindingNameError::InvalidChar(':')
        ));
    }

    #[test]
    fn binding_name_rejects_digit_start() {
        assert!(matches!(
            BindingName::parse("1foo").unwrap_err(),
            BindingNameError::InvalidStart('1')
        ));
    }

    proptest::proptest! {
        /// Section 2.7 checkpoint: any `BindingName` survives a round-trip
        /// through `Display → parse` losslessly.
        #[test]
        fn binding_name_display_roundtrip(name in "[a-zA-Z_][a-zA-Z0-9_-]{0,32}") {
            let bn = BindingName::parse(&name).expect("generator produces valid names");
            let printed = format!("{bn}");
            let reparsed = BindingName::parse(&printed)
                .expect("Display output must reparse");
            proptest::prop_assert_eq!(bn.as_str(), reparsed.as_str());
        }
    }

    #[test]
    fn binding_name_roundtrip_via_display() {
        let original = BindingName::parse("#some-name_42").unwrap();
        let printed = format!("{original}");
        let reparsed = BindingName::parse(&printed).unwrap();
        assert_eq!(original.as_str(), reparsed.as_str());
        assert_eq!(format!("{original}"), format!("{reparsed}"));
    }

    #[test]
    fn spanned_new_creates_correctly() {
        let span = Span { start: 0, end: 5 };
        let spanned = Spanned::new("test", span);
        assert_eq!(spanned.value, "test");
        assert_eq!(spanned.span, span);
    }

    #[test]
    fn spanned_map_preserves_span() {
        let span = Span { start: 0, end: 5 };
        let spanned = Spanned::new(42, span);
        let mapped = spanned.map(|n| n.to_string());
        assert_eq!(mapped.value, "42");
        assert_eq!(mapped.span, span);
    }

    #[test]
    fn effect_result_is_nil_returns_correctly() {
        assert!(EffectResult::Nil.is_nil());
        assert!(!EffectResult::Decision(Decision::Allow, None).is_nil());
    }

    #[test]
    fn effect_result_is_decision_returns_correctly() {
        assert!(EffectResult::Decision(Decision::Allow, None).is_decision());
        assert!(!EffectResult::Nil.is_decision());
    }

    #[test]
    fn effect_result_decision_returns_some() {
        assert_eq!(
            EffectResult::Decision(Decision::Ask, None).decision(),
            Some(Decision::Ask)
        );
        assert_eq!(EffectResult::Nil.decision(), None);
    }

    #[test]
    fn effect_result_reason_returns_some_for_decision() {
        assert_eq!(
            EffectResult::Decision(Decision::Allow, Some("test".into())).reason(),
            Some("test")
        );
    }

    #[test]
    fn effect_result_reason_returns_none_for_nil() {
        assert_eq!(EffectResult::Nil.reason(), None);
    }

    #[test]
    fn effect_result_reason_returns_none_for_decision_without_reason() {
        assert_eq!(EffectResult::Decision(Decision::Deny, None).reason(), None);
    }

    #[test]
    fn effect_allow_creates_correctly() {
        let effect = Effect::allow(Some("reason".into()));
        assert!(
            matches!(effect, Effect::Terminal { decision: Decision::Allow, reason: Some(r) } if r == "reason")
        );
    }

    #[test]
    fn effect_ask_creates_correctly() {
        let effect = Effect::ask(None);
        assert!(matches!(
            effect,
            Effect::Terminal {
                decision: Decision::Ask,
                reason: None
            }
        ));
    }

    #[test]
    fn effect_deny_creates_correctly() {
        let effect = Effect::deny(Some("blocked".into()));
        assert!(
            matches!(effect, Effect::Terminal { decision: Decision::Deny, reason: Some(r) } if r == "blocked")
        );
    }

    #[test]
    fn effect_command_pattern_creates_correctly() {
        let pattern = CommandPattern::Literal("git".into());
        let effect = Effect::command_pattern(pattern);
        assert!(matches!(effect, Effect::CommandPattern(CommandPattern::Literal(s)) if s == "git"));
    }

    #[test]
    fn effect_arg_pattern_creates_correctly() {
        let pattern = ArgPattern::positional(vec![]);
        let effect = Effect::arg_pattern(pattern.clone());
        assert!(
            matches!(effect, Effect::ArgPattern(p) if matches!(p, ArgPattern::Ordered { mode: MatchMode::Positional, .. }))
        );
    }

    #[test]
    fn effect_is_terminal_returns_correctly() {
        assert!(
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None
            }
            .is_terminal()
        );
        assert!(
            Effect::Terminal {
                decision: Decision::Ask,
                reason: None
            }
            .is_terminal()
        );
        assert!(
            Effect::Terminal {
                decision: Decision::Deny,
                reason: None
            }
            .is_terminal()
        );
        assert!(!Effect::CommandPattern(CommandPattern::Literal("git".into())).is_terminal());
        assert!(!Effect::ArgPattern(ArgPattern::positional(vec![])).is_terminal());
    }

    #[test]
    fn effect_is_pattern_returns_correctly() {
        assert!(Effect::CommandPattern(CommandPattern::Literal("git".into())).is_pattern());
        assert!(Effect::ArgPattern(ArgPattern::positional(vec![])).is_pattern());
        assert!(
            !Effect::Terminal {
                decision: Decision::Allow,
                reason: None
            }
            .is_pattern()
        );
        assert!(!Effect::And { effects: vec![] }.is_pattern());
    }

    #[test]
    fn effect_is_combinator_returns_correctly() {
        let span = Span { start: 0, end: 1 };
        let effect = Spanned::new(
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
            span,
        );

        assert!(Effect::And { effects: vec![] }.is_combinator());
        assert!(Effect::Or { effects: vec![] }.is_combinator());
        assert!(
            Effect::Not {
                effect: Box::new(effect.clone())
            }
            .is_combinator()
        );
        assert!(
            !Effect::Terminal {
                decision: Decision::Allow,
                reason: None
            }
            .is_combinator()
        );
        assert!(!Effect::CommandPattern(CommandPattern::Literal("git".into())).is_combinator());
    }

    #[test]
    fn effect_is_conditional_returns_correctly() {
        let span = Span { start: 0, end: 1 };
        let pred = Spanned::new(Predicate::fact_presence(":test"), span);
        let effect = Spanned::new(
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
            span,
        );

        assert!(
            Effect::When {
                predicate: pred.clone(),
                effect: Box::new(effect.clone()),
            }
            .is_conditional()
        );

        assert!(
            Effect::Unless {
                predicate: pred.clone(),
                effect: Box::new(effect.clone()),
            }
            .is_conditional()
        );

        assert!(
            Effect::If {
                predicate: pred.clone(),
                then_effect: Box::new(effect.clone()),
                else_effect: Box::new(effect.clone()),
            }
            .is_conditional()
        );

        assert!(
            Effect::Cond {
                branches: vec![],
                fallback: None,
            }
            .is_conditional()
        );

        assert!(
            !Effect::Terminal {
                decision: Decision::Allow,
                reason: None
            }
            .is_conditional()
        );
    }

    #[test]
    fn predicate_fact_presence_creates_correctly() {
        let pred = Predicate::fact_presence(":via/ssh");
        assert!(matches!(
            pred,
            Predicate::Fact(FactQuery::Presence { key })
            if key == ":via/ssh"
        ));
    }

    #[test]
    fn predicate_fact_value_creates_correctly() {
        use crate::predicates::FactPattern;
        let pred = Predicate::fact_value(":opencode/agent", "build");
        assert!(matches!(
            pred,
            Predicate::Fact(FactQuery::Value { key, pattern: FactPattern::Literal(val) })
            if key == ":opencode/agent" && val == "build"
        ));
    }

    #[test]
    fn predicate_arg_creates_correctly() {
        let pattern = ArgPattern::positional(vec![]);
        let pred = Predicate::arg(pattern);
        assert!(matches!(
            pred,
            Predicate::Arg(ArgPattern::Ordered {
                mode: MatchMode::Positional,
                ..
            })
        ));
    }

    #[test]
    fn predicate_and_with_single_returns_unwrapped() {
        let pred = Predicate::fact_presence(":test");
        let result = Predicate::and(vec![pred]);
        assert!(matches!(result, Predicate::Fact(_)));
    }

    #[test]
    fn predicate_and_with_multiple_creates_and() {
        let preds = vec![
            Predicate::fact_presence(":a"),
            Predicate::fact_presence(":b"),
        ];
        let result = Predicate::and(preds);
        assert!(matches!(result, Predicate::And(children) if children.len() == 2));
    }

    #[test]
    fn predicate_or_with_single_returns_unwrapped() {
        let pred = Predicate::fact_presence(":test");
        let result = Predicate::or(vec![pred]);
        assert!(matches!(result, Predicate::Fact(_)));
    }

    #[test]
    fn predicate_or_with_multiple_creates_or() {
        let preds = vec![
            Predicate::fact_presence(":a"),
            Predicate::fact_presence(":b"),
        ];
        let result = Predicate::or(preds);
        assert!(matches!(result, Predicate::Or(children) if children.len() == 2));
    }

    #[test]
    fn predicate_negate_creates_not() {
        let inner = Predicate::fact_presence(":test");
        let result = Predicate::negate(inner);
        assert!(
            matches!(result, Predicate::Not(boxed) if matches!(boxed.as_ref(), Predicate::Fact(_)))
        );
    }

    #[test]
    fn define_new_creates_correctly() {
        let span = Span { start: 0, end: 10 };
        let pred = Spanned::new(Predicate::fact_presence(":test"), span);
        let define = Define::new("my-pred", pred, span);

        assert_eq!(define.name, "my-pred");
        assert_eq!(define.span, span);
    }

    #[test]
    fn rule_new_creates_correctly() {
        let span = Span { start: 0, end: 20 };
        let cmd_effect = Spanned::new(
            Effect::command_pattern(CommandPattern::Literal("git".into())),
            span,
        );
        let effect = Spanned::new(Effect::ask(None), span);
        let rule = Rule::new(cmd_effect, effect, vec![], span);

        assert!(
            matches!(rule.command_effect.value, Effect::CommandPattern(CommandPattern::Literal(s)) if s == "git")
        );
        assert_eq!(rule.span, span);
    }

    #[test]
    fn security_config_default_is_empty() {
        let config = SecurityConfig::default();
        assert!(config.safe_env_vars.is_empty());
    }

    #[test]
    fn config_default_is_empty() {
        let config = Config::default();
        assert!(config.defines.is_empty());
        assert!(config.rules.is_empty());
        assert!(config.checks.is_empty());
        assert!(config.security.safe_env_vars.is_empty());
        assert!(config.parsers.is_empty());
        assert!(config.style_specs.is_empty());
    }

    #[test]
    fn effect_to_doc_allow_without_reason() {
        let doc = Effect::Terminal {
            decision: Decision::Allow,
            reason: None,
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "(allow)");
    }

    #[test]
    fn effect_to_doc_allow_with_reason() {
        let doc = Effect::Terminal {
            decision: Decision::Allow,
            reason: Some("safe command".into()),
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "(allow \"safe command\")");
    }

    #[test]
    fn effect_to_doc_ask_without_reason() {
        let doc = Effect::Terminal {
            decision: Decision::Ask,
            reason: None,
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "(ask)");
    }

    #[test]
    fn effect_to_doc_ask_with_reason() {
        let doc = Effect::Terminal {
            decision: Decision::Ask,
            reason: Some("confirm".into()),
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "(ask \"confirm\")");
    }

    #[test]
    fn effect_to_doc_deny_without_reason() {
        let doc = Effect::Terminal {
            decision: Decision::Deny,
            reason: None,
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "(deny)");
    }

    #[test]
    fn effect_to_doc_deny_with_reason() {
        let doc = Effect::Terminal {
            decision: Decision::Deny,
            reason: Some("blocked".into()),
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "(deny \"blocked\")");
    }

    #[test]
    fn effect_to_doc_command_pattern_placeholder() {
        let doc = Effect::CommandPattern(CommandPattern::Literal("git".into())).to_doc();
        assert_eq!(doc_text(&doc), "<command-pattern>");
    }

    #[test]
    fn effect_to_doc_arg_pattern_placeholder() {
        let doc = Effect::ArgPattern(ArgPattern::positional(vec![])).to_doc();
        assert_eq!(doc_text(&doc), "<arg-pattern>");
    }

    #[test]
    fn effect_to_doc_and_placeholder() {
        let doc = Effect::And { effects: vec![] }.to_doc();
        assert_eq!(doc_text(&doc), "<and-effect>");
    }

    #[test]
    fn effect_to_doc_or_placeholder() {
        let doc = Effect::Or { effects: vec![] }.to_doc();
        assert_eq!(doc_text(&doc), "<or-effect>");
    }

    #[test]
    fn effect_to_doc_not_placeholder() {
        let span = Span { start: 0, end: 1 };
        let effect = Spanned::new(
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
            span,
        );
        let doc = Effect::Not {
            effect: Box::new(effect),
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "<not-effect>");
    }

    #[test]
    fn effect_to_doc_when_placeholder() {
        let span = Span { start: 0, end: 1 };
        let pred = Spanned::new(Predicate::fact_presence(":test"), span);
        let effect = Spanned::new(
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
            span,
        );
        let doc = Effect::When {
            predicate: pred,
            effect: Box::new(effect),
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "<when-effect>");
    }

    #[test]
    fn effect_to_doc_unless_placeholder() {
        let span = Span { start: 0, end: 1 };
        let pred = Spanned::new(Predicate::fact_presence(":test"), span);
        let effect = Spanned::new(
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
            span,
        );
        let doc = Effect::Unless {
            predicate: pred,
            effect: Box::new(effect),
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "<unless-effect>");
    }

    #[test]
    fn effect_to_doc_if_placeholder() {
        let span = Span { start: 0, end: 1 };
        let pred = Spanned::new(Predicate::fact_presence(":test"), span);
        let effect = Spanned::new(
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
            span,
        );
        let doc = Effect::If {
            predicate: pred,
            then_effect: Box::new(effect.clone()),
            else_effect: Box::new(effect),
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "<if-effect>");
    }

    #[test]
    fn effect_to_doc_cond_placeholder() {
        let doc = Effect::Cond {
            branches: vec![],
            fallback: None,
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "<cond-effect>");
    }

    fn doc_text(doc: &crate::doc::Doc) -> String {
        doc.fold(&|node, _ann| match node {
            crate::doc::DocF::Atom(s) => s.clone(),
            crate::doc::DocF::List(cs) => format!("({})", cs.join(" ")),
            crate::doc::DocF::Vector(cs) => format!("[{}]", cs.join(" ")),
        })
    }
}
