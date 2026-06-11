# Development shell: crane devShell with checks plus coverage,
# fuzzing, snapshot, and pre-commit tooling.
{ build, checks }:
let
  inherit (build) pkgs craneLib rustToolchain;
in
craneLib.devShell {
  inherit checks;

  packages = with pkgs; [
    cargo-affected
    cargo-fuzz
    cargo-insta
    cargo-tarpaulin
    prek
    yq-go
  ];

  shellHook = ''
    prek install
  ''
  + pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
    # Workaround: rust-overlay symlinks rustfmt into a separate derivation
    # that lacks librustc_driver. Point dyld at the combined toolchain's lib.
    export DYLD_LIBRARY_PATH="${rustToolchain}/lib"
  '';
}
