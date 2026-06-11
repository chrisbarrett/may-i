# Toolchain, source filtering, and the crane package build.
{ inputs, system }:
let
  pkgs = import inputs.nixpkgs {
    inherit system;
    overlays = [
      inputs.rust-overlay.overlays.default
      inputs.cargo-affected.overlays.default
    ];
  };

  rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;

  craneLib = (inputs.crane.mkLib pkgs).overrideToolchain (_: rustToolchain);

  # Include non-Rust files needed for the build
  extraFileFilter =
    path: type:
    (pkgs.lib.hasSuffix ".lisp" path)
    || (pkgs.lib.hasSuffix ".snap" path)
    || (pkgs.lib.hasSuffix ".txt" path)
    || (pkgs.lib.hasSuffix "REFERENCE.md" path);

  src = pkgs.lib.cleanSourceWith {
    src = ../.;
    filter = path: type: (extraFileFilter path type) || (craneLib.filterCargoSources path type);
  };

  commonArgs = {
    inherit src;
    strictDeps = true;
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;

  may-i = craneLib.buildPackage (
    commonArgs
    // {
      inherit cargoArtifacts;
      doCheck = false; # Run via cargo-nextest checks.
    }
  );
in
{
  inherit
    pkgs
    rustToolchain
    craneLib
    src
    commonArgs
    cargoArtifacts
    may-i
    ;
}
