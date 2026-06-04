## 1. Engine: declaration kind in shape metadata

- [x] 1.1 Introduce `DeclKind` enum in `crates/engine/src/shape.rs` with variants `Parameter { name: String }`, `Flag { name: String }`, `Positional`, `Rest`.
- [x] 1.2 Replace `decl_name: Option<String>` on `ShapeDecl` with `decl_kind: DeclKind`. Update `ShapeEnv::from_parser` to construct the appropriate variant for each declaration source.
- [x] 1.3 Update `ShapeMismatch` in `crates/engine/src/shape_check.rs` to carry `decl_kind: DeclKind` (replacing `decl_name`).
- [x] 1.4 Update the in-crate tests (`shape.rs` and `shape_check.rs`) that read the old field; assert the new variant is correct for each declaration source.

## 2. Renderer: kind-aware hint dispatch

- [x] 2.1 In `src/shape_diag.rs`, rewrite `hint_for` to match on `(operator, found_shape, decl_kind)`. Each arm produces `Some(text)` or `None` per the `binding-shapes` spec's hint families.
- [x] 2.2 Add the new hint arms: `Positional` + `Token` + `every?/some?` → "widen the quantifier" hint; `Positional` + `CollectionToken` + `authorise` → iteration arm only; `Rest` + `Command` + `every?/some?` → "rest captures the whole tail" hint with `(authorise …)` suggestion.
- [x] 2.3 Drop the `(command …)` suggestion from the name-less `Authorise` arm so positional/rest bindings never see a parameter-only rewrite.
- [x] 2.4 Update `decl_label_for` if needed to match the new field name (still phrases the binding's user-facing shape).

## 3. Tests

- [x] 3.1 Update the existing `hints_without_a_parameter_name` test to assert the *new* positional-aware hint: `every? on Token positional` → suggests `(positional #v +)`; existing assertions on positional + authorise stay green with the iteration-only hint.
- [x] 3.2 Add a new test `positional_token_hint_widens_quantifier` covering `(every? #v PRED)` over `(positional #v *)`. Assert the rendered text contains `(positional #` and does NOT contain `(parameter`.
- [x] 3.3 Add a new test `positional_collection_authorise_omits_command_arm` covering `(authorise #v)` over `(positional #v * +)`. Assert the rendered text contains `(every? #` and does NOT contain `(command`.
- [x] 3.4 Add a new test `rest_iteration_hint_routes_to_authorise` covering `(every? #rest PRED)` over `(rest #rest)`. Assert the rendered text suggests `(authorise #rest)` and does NOT mention `(parameter`.
- [x] 3.5 Keep the existing parameter-case tests (`every_on_token_renders_list_expected_with_hint`, `authorise_on_collection_hints_iteration`, `rendered_text_never_leaks_internal_vocabulary`) green.

## 4. Verification

- [x] 4.1 Run `cargo fmt -p may-i-engine -p may-i`.
- [x] 4.2 Run `cargo test --workspace`.
- [x] 4.3 Reproduce the original demo at `/tmp/may-i-demo/01-every-on-token.lisp` and confirm the new hint reads "(positional #target +)" rather than "(parameter NAME (set #target))".
- [x] 4.4 Run `openspec validate kind-aware-shape-hints --strict`.
- [x] 4.5 Run `prek` over the working tree.
