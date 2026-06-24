# Lightweight dev shell for script-level checks (e.g. the output-sink-boundary
# ast-grep scan). Kept separate from the crane `default` shell so CI can run
# these checks without building the Rust toolchain, while local development and
# the prek hooks use the same pinned tools.
{ build }:
let
  inherit (build) pkgs;
in
pkgs.mkShellNoCC {
  packages = with pkgs; [
    ast-grep
  ];
}
