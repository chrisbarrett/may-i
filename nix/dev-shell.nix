# Development shell: crane devShell with checks plus coverage,
# fuzzing, snapshot, and pre-commit tooling.
{ build, checks }:
let
  inherit (build) pkgs craneLib;
in
craneLib.devShell {
  inherit checks;

  packages = with pkgs; [
    ast-grep
    cargo-affected
    cargo-fuzz
    cargo-insta
    cargo-tarpaulin
    prek
    yq-go
  ];

  shellHook = ''
    prek install
  '';
}
