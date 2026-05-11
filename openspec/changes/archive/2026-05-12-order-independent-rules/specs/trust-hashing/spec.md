## MODIFIED Requirements

### Requirement: Hash covers the canonical rule and define set

The trust hash for a program SHALL include all rules whose command effect
mentions that program and all defines referenced (directly or transitively)
by those rules. Both `PrimaryConfig` and `Loaded` rules are included.

The hash SHALL be computed over a canonical, *order-independent*
serialisation: each rule and each define is rendered into its canonical
s-expression form, the resulting strings are sorted lexically within each
group (rules and defines), and the two sorted groups are concatenated with
a separator. Source-file order, comments, whitespace, and the way rules
are partitioned across `(load …)` files SHALL NOT influence the hash.

#### Scenario: Reordering rules does not change the hash

- **WHEN** two rules for `"git"` are swapped in source order
- **THEN** the trust hash for `"git"` SHALL be unchanged

#### Scenario: Moving a rule between loaded files does not change the hash

- **GIVEN** rule R for `"git"` lives in `rules/a.lisp`
- **WHEN** R is moved verbatim into `rules/b.lisp`
- **THEN** the trust hash for `"git"` SHALL be unchanged

#### Scenario: Changing a rule's content changes the hash

- **WHEN** a rule's body is edited (e.g. its decision changes from
  `:allow` to `:deny`)
- **THEN** the trust hash for the affected program SHALL change

#### Scenario: Changing a referenced define changes the hash

- **WHEN** a `Loaded` define referenced by a `"git"` rule is modified
- **THEN** the trust hash for `"git"` SHALL change
