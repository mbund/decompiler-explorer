import argparse
from pathlib import Path
import multiprocessing
from time import sleep
from typing import TYPE_CHECKING
from watchfiles import watch

import pyhidra

THREAD_COUNT = multiprocessing.cpu_count()

# needed for ghidra python vscode autocomplete
if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


def analyze(flat_api: "ghidra.program.flatapi.FlatProgramAPI"):
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.listing import Function
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.app.script import GhidraScriptUtil

    program: "ghidra.program.model.listing.Program" = flat_api.getCurrentProgram()
    flat_api.analyzeAll(program)

    all_funcs: list[Function] = []
    for f in program.functionManager.getFunctions(True):
        all_funcs.append(f)

    monitor = ConsoleTaskMonitor()

    funcs = [func for func in all_funcs if func.getName() in ["main", "myFunction"]]
    sources = []
    for func in funcs:
        decompiler = DecompInterface()
        decompiler.openProgram(program)
        decomp = decompiler.decompileFunction(func, 1, monitor)
        c: str = decomp.getDecompiledFunction().getC()
        sources.append(c.strip())

    with open("output.gc", "w") as f:
        f.write("\n\n".join(sources).replace("\n{", "{") + "\n")


def main():
    parser = argparse.ArgumentParser(description="Decompiler explorer")

    parser.add_argument("bin", help="Path to binary used for analysis")
    parser.add_argument(
        "-o",
        "--output-path",
        help="Location for all decompilations",
        default=".decompilations",
    )
    parser.add_argument(
        "-v", "--verbose", help="Verbose output", default=False, action="store_true"
    )

    args = parser.parse_args()

    verbose: bool = args.verbose

    bin_path = Path(args.bin)
    project_location = Path(".ghidra_projects")
    output_path = Path(args.output_path) / bin_path.name
    output_path.mkdir(exist_ok=True, parents=True)

    pyhidra.start(verbose)

    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import Program
    from ghidra.base.project import GhidraProject
    from ghidra.base.project import GhidraProject
    from ghidra.app.script import GhidraScriptUtil
    from java.io import IOException

    from pyhidra.launcher import PyhidraLauncher, HeadlessPyhidraLauncher

    if not PyhidraLauncher.has_launched():
        HeadlessPyhidraLauncher().start()

    project_name = bin_path.name

    project_location = project_location / project_name
    project_location.mkdir(exist_ok=True, parents=True)

    try:
        project = GhidraProject.openProject(project_location, project_name, True)
    except IOException:
        project = GhidraProject.createProject(project_location, project_name, False)

    GhidraScriptUtil.acquireBundleHostReference()

    def importAndAnalyze():
        program = project.importProgram(bin_path)
        flat_api = FlatProgramAPI(program)
        analyze(flat_api)

    importAndAnalyze()
    for _ in watch("./examples/program", force_polling=True):
        importAndAnalyze()

    GhidraScriptUtil.releaseBundleHostReference()
    project.close()


if __name__ == "__main__":
    main()
