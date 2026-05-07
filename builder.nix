inputs:
{ self', system, ... }:
let
  pkgs = import inputs.nixpkgs {
    inherit system;
    overlays = [
      inputs.rust-overlay.overlays.default
      inputs.cargo-affected.overlays.default
    ];
  };

  rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

  craneLib = (inputs.crane.mkLib pkgs).overrideToolchain (_: rustToolchain);

  # Include non-Rust files needed for the build
  extraFileFilter =
    path: type:
    (pkgs.lib.hasSuffix ".lisp" path)
    || (pkgs.lib.hasSuffix ".snap" path)
    || (pkgs.lib.hasSuffix ".txt" path)
    || (pkgs.lib.hasSuffix "REFERENCE.md" path);

  src = pkgs.lib.cleanSourceWith {
    src = ./.;
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
  formatter = pkgs.nixpkgs-fmt;

  apps.default = {
    type = "app";
    program = "${may-i}/bin/may-i";
  };
  packages.default = may-i;

  checks = {
    inherit may-i;

    clippy = craneLib.cargoClippy (
      commonArgs
      // {
        inherit cargoArtifacts;
        cargoClippyExtraArgs = "--all-targets -- --deny warnings";
      }
    );

    fmt = craneLib.cargoFmt { inherit src; };

    audit = craneLib.cargoAudit {
      inherit (inputs) advisory-db;
      inherit src;
    };

    nextest = craneLib.cargoNextest (
      commonArgs
      // {
        inherit cargoArtifacts;
        partitions = 1;
        partitionType = "count";
        cargoNextestPartitionsExtraArgs = "--no-tests=pass";
      }
    );
  };

  devShells.default = craneLib.devShell {
    checks = self'.checks;

    packages = with pkgs; [
      cargo-affected
      cargo-insta
      cargo-tarpaulin
      prek
    ];

    shellHook = ''
      prek install
    ''
    + pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
      # Workaround: rust-overlay symlinks rustfmt into a separate derivation
      # that lacks librustc_driver. Point dyld at the combined toolchain's lib.
      export DYLD_LIBRARY_PATH="${rustToolchain}/lib"
    '';
  };
}
