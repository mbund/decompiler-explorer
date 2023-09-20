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
    in {
      # packages = {
      #   decompiler-explorer = pkgs.buildPythonPackage rec {
      #     pname = "decompiler-explorer";
      #     version = "0.1.0";
      #     src = ./.;
      #     doCheck = false;
      #   };
      #   default = self.packages.${system}.decompiler-explorer;
      # };

      devShells.default = pkgs.mkShell {
        packages = with pkgs; [
          entr

          ghidra
          openjdk
          (python3.withPackages (ps:
            with ps; [
              watchfiles
              jpype1
              (buildPythonPackage rec {
                pname = "pyhidra";
                version = "0.5.2";
                src = fetchPypi {
                  inherit pname version;
                  sha256 = "sha256-7oVXMHhj9gv0Znpd8QakPojet9cEkB+FFJq+UDLBRDM=";
                };
                doCheck = false;
              })
              (buildPythonPackage rec {
                pname = "ghidra-stubs";
                version = "10.3.3.1.0.4";
                src = fetchPypi {
                  inherit pname version;
                  sha256 = "sha256-sGdeBrWcIaYNZyiAGLMl10ZwpQC4G15Ia338MenvrV8=";
                };
                doCheck = false;
              })
            ]))
        ];
        GHIDRA_INSTALL_DIR = "${pkgs.ghidra}/lib/ghidra";
      };
    });
}
