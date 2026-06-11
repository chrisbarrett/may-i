# Flake checks: package build, clippy, rustfmt, cargo-audit, nextest.
{ inputs, build }:
let
  inherit (build)
    craneLib
    src
    commonArgs
    cargoArtifacts
    may-i
    ;
in
{
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
}
