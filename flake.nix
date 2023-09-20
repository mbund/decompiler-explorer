{
  description = "Decompiler Explorer";

  inputs.flake-utils.url = "github:numtide/flake-utils";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};

      pyhidra = pkgs.python3Packages.buildPythonPackage rec {
        pname = "pyhidra";
        version = "0.5.2";
        src = pkgs.fetchPypi {
          inherit pname version;
          sha256 = "sha256-7oVXMHhj9gv0Znpd8QakPojet9cEkB+FFJq+UDLBRDM=";
        };
        doCheck = false;
      };

      ghidra-stubs = pkgs.python3Packages.buildPythonPackage rec {
        pname = "ghidra-stubs";
        version = "10.3.3.1.0.4";
        src = pkgs.fetchPypi {
          inherit pname version;
          sha256 = "sha256-sGdeBrWcIaYNZyiAGLMl10ZwpQC4G15Ia338MenvrV8=";
        };
        doCheck = false;
      };
    in {
      packages = {
        decompiler-explorer = pkgs.callPackage ./package.nix {};
        default = self.packages.${system}.decompiler-explorer;
      };

      devShells.default = pkgs.mkShell {
        packages = with pkgs; [
          entr
          ghidra
          openjdk
          (python3.withPackages (ps:
            with ps; [
              watchfiles
              jpype1
              pyhidra
              ghidra-stubs
            ]))
        ];
        GHIDRA_INSTALL_DIR = "${pkgs.ghidra}/lib/ghidra";
      };
    });
}
