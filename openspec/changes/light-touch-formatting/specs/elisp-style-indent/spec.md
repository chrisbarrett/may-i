## MODIFIED Requirements

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
