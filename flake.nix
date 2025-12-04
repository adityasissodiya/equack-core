{
  description = "ECAC reproducible dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rust = pkgs.rust-bin.stable."1.80.0".minimal;
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            rust
            pkgs.openssl
            pkgs.pkg-config
            pkgs.rocksdb
            pkgs.protobuf
            pkgs.cargo-audit
            pkgs.cargo-deny
          ];
          RUSTFLAGS = "-C debuginfo=0 -C strip=symbols -C link-arg=-s";
        };
      });
}
