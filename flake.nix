{
  description = "A Nix flake for building and running Zig projects";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Replace with your project name
        projectName = "my-zig-project";

        # Your Zig build configuration
        zigBuild = pkgs.stdenv.mkDerivation {
          pname = projectName;
          version = "0.1.0";

          src = ./.;

          nativeBuildInputs = [ pkgs.zig ];

          buildPhase = ''
            zig build -Drelease-safe=true
          '';

          installPhase = ''
            mkdir -p $out/bin
            cp zig-out/bin/${projectName} $out/bin/
          '';

          meta = with pkgs; {
            description = "";
            project_name = projectName;
            license = license.mit;
          };
        };
      in {
        packages.default = zigBuild;

        devShells.default = pkgs.mkShell {
          name = "zig-dev-shell";
          buildInputs = with pkgs; [
            zig
            zls     # Zig Language Server
            gdb     # Optional: debugging
            pkg-config
          ];

          shellHook = ''
            export PS1="(${projectName}) \$ "
          '';
        };

        # Optional: Run with `nix run`
        apps.default = flake-utils.lib.mkApp {
          drv = zigBuild;
          name = projectName;
        };
      });
}

