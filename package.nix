{
  lib,
  python3Packages,
  ghidra,
  openjdk,
}:
python3Packages.buildPythonApplication rec {
  pname = "decompiler-explorer";
  version = "1.0.0";
  format = "pyproject";

  src = ./.;

  buildInputs = with python3Packages; [
    ghidra
  ];

  nativeBuildInputs = with python3Packages; [
    setuptools
  ];

  propagatedBuildInputs = with python3Packages; [
    openjdk
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
  ];

  preFixup = ''
    makeWrapperArgs+=(
      --set GHIDRA_INSTALL_DIR "${ghidra}/lib/ghidra"
    )
  '';

  meta = with lib; {
    description = "Watch for changes in a binary and output a C-like decompilation";
    homepage = "https://github.com/mbund/decompiler-explorer";
    license = licenses.gpl3Only;
    platforms = platforms.unix;
    maintainers = with maintainers; [mbund];
  };
}
