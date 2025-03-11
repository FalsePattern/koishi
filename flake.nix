{
  inputs =
    {
      nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";

      zig-overlay.url = "github:mitchellh/zig-overlay";
      zig-overlay.inputs.nixpkgs.follows = "nixpkgs";

      zls-flake.url = "github:zigtools/zls/0.14.0";
      zls-flake.inputs.nixpkgs.follows = "nixpkgs";
    };

  outputs = { self, nixpkgs, zig-overlay, zls-flake }: let
    inherit (nixpkgs) lib;

    # flake-utils polyfill
    eachSystem = systems: fn:
      lib.foldl' (
        acc: system:
          lib.recursiveUpdate
          acc
          (lib.mapAttrs (_: value: {${system} = value;}) (fn system))
      ) {}
      systems;

    systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
  in eachSystem systems (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        zig = zig-overlay.packages.${system}."0.14.0";
        zls = zls-flake.packages.${system}.zls;
      in
      rec {
        formatter = pkgs.nixpkgs-fmt;
        devShells.default = pkgs.mkShell {
          packages = [
            zig
            zls
          ];
        };
      }
    );
}
