## MODIFIED Requirements

### Requirement: Pretty-serialized CST roundtrips
In addition to the existing serialize roundtrip, pretty_serialize at any column width SHALL produce output that re-parses to a structurally equivalent CST.

#### Scenario: Pretty roundtrip at various widths
- **WHEN** a CST is pretty-serialized at width W (20..120) and re-parsed
- **THEN** the atom and list structure SHALL be preserved
