# Per-system flake outputs, assembled from the per-concern modules in
# this directory.
inputs:
{ self', system, ... }:
let
  build = import ./build.nix { inherit inputs system; };
  inherit (build) pkgs may-i;
in
{
  formatter = pkgs.nixpkgs-fmt;

  apps.default = {
    type = "app";
    program = "${may-i}/bin/may-i";
  };
  packages.default = may-i;

  checks = import ./checks.nix { inherit inputs build; };

  devShells.default = import ./dev-shell.nix {
    inherit build;
    checks = self'.checks;
  };
}
