## Requirements

### Requirement: Special-form indentation
The pretty-serializer SHALL indent the body of special forms by 2 spaces from
the opening paren. The special forms are: `define`, `check`, `with-facts`,
`when`, `unless`, `rule`, `cond`.

#### Scenario: define body indent
- **WHEN** pretty-serializing `(define foo (or a b))`
- **AND** the body does not fit on one line
- **THEN** the output SHALL indent the body by 2 from the opening paren:
  ```
  (define foo
    (or a b))
  ```

#### Scenario: check body indent
- **WHEN** pretty-serializing a `check` form with multiple children
- **THEN** each child SHALL be indented by 2 from the opening paren:
  ```
  (check
    :ask "rmdir /foo"
    (with-facts [[:opencode/agent "build"]]
      :allow "rmdir /foo"))
  ```

#### Scenario: nested special forms
- **WHEN** a special form is nested inside another special form
- **THEN** each level SHALL indent by 2 from its own opening paren:
  ```
  (rule "rm"
    (when build-mode
      (cond
        ((positional "push") (effect :allow))
        (else (effect :ask)))))
  ```

### Requirement: Function-call indentation
The pretty-serializer SHALL align arguments of non-special forms under the first
argument. The indent position is `paren_col + 1 + head_atom_width + 1`.

For preserved children (with source trivia), the child's internal layout SHALL
be emitted verbatim from the source trivia. The parent's indent level still
governs the position of the child itself, but the child's own line breaks and
internal spacing are preserved.

#### Scenario: or form alignment
- **WHEN** pretty-serializing `(or "cat" "bat" "head" "tail" "less" "ls")`
- **AND** arguments do not fit on one line
- **THEN** subsequent arguments SHALL align under the first argument:
  ```
  (or "cat" "bat" "head"
      "tail" "less" "ls")
  ```

#### Scenario: and form alignment
- **WHEN** pretty-serializing `(and (anywhere "-r") (anywhere "/"))`
- **AND** arguments do not fit on one line
- **THEN** subsequent arguments SHALL align under the first argument:
  ```
  (and (anywhere "-r")
       (anywhere "/"))
  ```

#### Scenario: non-atom head fallback
- **WHEN** the head of a list is not a bare atom (e.g. a nested list)
- **THEN** the pretty-serializer SHALL fall back to `paren_col + 1` indent

#### Scenario: preserved child keeps packed layout in migration
- **WHEN** a rewrite rule produces a `rule` node containing a cloned `or` child
  whose source was packed across multiple lines
- **THEN** the `or` child SHALL retain its original packed line breaks
- **AND** the `rule` node SHALL use elisp-style +2 indentation for its body

### Requirement: Whole-line comment positioning
The pretty-serializer SHALL emit whole-line comments at the current indentation
level. A comment is whole-line when the `Trivia::Whitespace` entry immediately
preceding it in the trivia vector contains a newline character.

#### Scenario: whole-line comment before a sibling
- **WHEN** a rewritten node has a whole-line comment in its leading trivia
- **THEN** the comment SHALL appear on its own line, indented at the current
  indent level

#### Scenario: blank line before comment preserved
- **WHEN** the whitespace preceding a whole-line comment contains two or more
  newlines
- **THEN** the blank line(s) SHALL be preserved in the output

### Requirement: Line-trailing comment preservation
The pretty-serializer SHALL preserve the exact whitespace gap before a
line-trailing comment. A comment is line-trailing when the preceding whitespace
(if any) does not contain a newline.

#### Scenario: trailing comment spacing preserved
- **WHEN** a node has a line-trailing comment preceded by `"  "` (two spaces)
- **THEN** the output SHALL preserve the two-space gap before the comment

#### Scenario: no preceding whitespace
- **WHEN** a comment has no preceding `Trivia::Whitespace` entry
- **THEN** the comment SHALL be emitted immediately after the preceding token

### Requirement: Special-form lookup table
The classification of forms into special-form vs function-call SHALL be
determined by a static `&[&str]` lookup table in the pretty-serializer.

#### Scenario: known special forms
- **WHEN** the head atom of a list is one of `define`, `check`, `with-facts`,
  `when`, `unless`, `rule`, `cond`
- **THEN** the form SHALL use special-form indentation (+2)

#### Scenario: unknown head atom
- **WHEN** the head atom of a list is not in the special-form table
- **THEN** the form SHALL use function-call indentation (align under first arg)
