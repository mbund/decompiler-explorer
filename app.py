from typing import TYPE_CHECKING
from datetime import datetime
from watchfiles import watch
from pathlib import Path
import multiprocessing
import argparse
import pyhidra
import signal
import sys

THREAD_COUNT = multiprocessing.cpu_count()

# needed for ghidra python vscode autocomplete
if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


def main():
    parser = argparse.ArgumentParser(description="Decompiler explorer")

    parser.add_argument("bin", help="Path to binary used for analysis")
    parser.add_argument(
        "-o",
        "--output",
        help="Location for all decompilations",
        default="output.gc",
    )
    parser.add_argument(
        "-v", "--verbose", help="Verbose output", default=False, action="store_true"
    )
    parser.add_argument(
        "-n",
        "--functions",
        help="Function names to decompile",
        nargs="+",
        default=["main"],
    )

    args = parser.parse_args()

    functionNames: list[str] = args.functions
    verbose: bool = args.verbose
    bin_path = Path(args.bin)
    output_path = Path(args.output)
    project_location = Path(".ghidra_projects")

    print(f"Will watch binary {bin_path.absolute()}")
    print(f"Will output C-like ghidra decompilation to {output_path.absolute()}")
    print(f"Will output functions [{', '.join(functionNames)}]")

    print("Starting pyhidra")

    pyhidra.start(verbose)

    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import Program
    from ghidra.program.model.listing import Function
    from ghidra.base.project import GhidraProject
    from ghidra.base.project import GhidraProject
    from ghidra.app.decompiler import DecompInterface
    from ghidra.app.script import GhidraScriptUtil
    from ghidra.util.task import ConsoleTaskMonitor
    from java.io import IOException

    from pyhidra.launcher import PyhidraLauncher, HeadlessPyhidraLauncher

    if not PyhidraLauncher.has_launched():
        HeadlessPyhidraLauncher().start()

    project_name = bin_path.name
    project_location = project_location / project_name
    project_location.mkdir(exist_ok=True, parents=True)

    print("Opening ghidra project")

    try:
        project = GhidraProject.openProject(project_location, project_name, True)
    except IOException:
        project = GhidraProject.createProject(project_location, project_name, False)

    GhidraScriptUtil.acquireBundleHostReference()

    def clean(exit_code):
        print("Closing project")
        GhidraScriptUtil.releaseBundleHostReference()
        project.close()
        sys.exit(exit_code)

    def exit_signal(signal, frame):
        print()
        clean(0)

    signal.signal(signal.SIGINT, exit_signal)

    def analyze():
        program: Program = project.importProgram(bin_path)
        flat_api = FlatProgramAPI(program)
        flat_api.analyzeAll(program)

        all_funcs: list[Function] = []
        for f in program.functionManager.getFunctions(True):
            all_funcs.append(f)

        monitor = ConsoleTaskMonitor()

        # check that all functionNames exist in all_funcs
        for name in functionNames:
            if name not in [func.getName() for func in all_funcs]:
                print(
                    f"Function {name} not found in binary. Existing functions are [{', '.join([func.getName() for func in all_funcs])}]"
                )
                clean(1)

        funcs = [func for func in all_funcs if func.getName() in functionNames]
        sources = []
        for func in funcs:
            decompiler = DecompInterface()
            decompiler.openProgram(program)
            decomp = decompiler.decompileFunction(func, 1, monitor)
            c: str = decomp.getDecompiledFunction().getC()
            sources.append(c.strip())

        with open(output_path, "w") as f:
            f.write("\n\n".join(sources).replace("\n{", "{") + "\n")

    print(f"{datetime.now().strftime('%H:%M:%S')} Analyzing {bin_path.absolute()}")
    analyze()
    for _ in watch(bin_path, force_polling=True, poll_delay_ms=100):
        print(f"{datetime.now().strftime('%H:%M:%S')} Analyzing {bin_path.absolute()}")
        analyze()

    clean(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
