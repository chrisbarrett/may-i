{
  inputs = {
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };

    cargo-affected = {
      url = "github:chrisbarrett/cargo-affected";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";

    flake-parts.url = "github:hercules-ci/flake-parts";

    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs@{ advisory-db, flake-parts, self, ... }: flake-parts.lib.mkFlake { inherit inputs; } {
    systems = [
      "aarch64-darwin"
      "aarch64-linux"
      "x86_64-linux"
    ];

    perSystem = { self', system, ... }:
      let
        pkgs = import inputs.nixpkgs {
          inherit system;
          overlays = [
            inputs.rust-overlay.overlays.default
            inputs.cargo-affected.overlays.default
          ];
        };

        craneLib = (inputs.crane.mkLib pkgs).overrideToolchain (p:
          p.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml
        );

        # Include non-Rust files needed for the build
        extraFileFilter = path: type:
          (pkgs.lib.hasSuffix ".lisp" path) ||
          (pkgs.lib.hasSuffix ".snap" path);

        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            (extraFileFilter path type) ||
            (craneLib.filterCargoSources path type);
        };

        commonArgs = {
          inherit src;
          strictDeps = true;
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        may-i = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          doCheck = false; # Run via cargo-nextest checks.
        });
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

          clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });

          fmt = craneLib.cargoFmt { inherit src; };
          audit = craneLib.cargoAudit { inherit src advisory-db; };

          nextest = craneLib.cargoNextest (commonArgs // {
            inherit cargoArtifacts;
            partitions = 1;
            partitionType = "count";
            cargoNextestPartitionsExtraArgs = "--no-tests=pass";
          });
        };

        devShells.default = craneLib.devShell {
          checks = self'.checks;

          packages = with pkgs; [
            cargo-affected
            cargo-tarpaulin
            prek
          ];

          shellHook = ''
            prek install
          '';
        };
      };

    flake.overlays.default = final: prev: {
      may-i = self.packages.${prev.system}.default;
    };
  };
}
