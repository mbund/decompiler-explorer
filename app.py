import argparse
from pathlib import Path
import multiprocessing
import concurrent.futures
from time import sleep, time
from typing import Union, Tuple, TYPE_CHECKING
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import pyhidra

THREAD_COUNT = multiprocessing.cpu_count()

# needed for ghidra python vscode autocomplete
if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


def setup_decompliers(
    p1: "ghidra.program.model.listing.Program",
) -> dict[int, "ghidra.app.decompiler.DecompInterface"]:
    """
    Setup decompliers to use during diff bins. Each one must be initialized with a program.
    """
    from ghidra.app.decompiler import DecompInterface

    decompilers = {}

    for i in range(THREAD_COUNT):
        decompilers.setdefault(i, DecompInterface())
        decompilers[i].openProgram(p1)

    print(f"Setup {THREAD_COUNT} decompliers")

    return decompilers


def decompile_func(
    func: "ghidra.program.model.listing.Function",
    monitor,
    decompilers: dict[int, "ghidra.app.decompiler.DecompInterface"],
    thread_id: int = 0,
    TIMEOUT: int = 1,
) -> list:
    """
    Decompile function and return [funcname, decompilation]
    """
    decomp = (
        decompilers[thread_id]
        .decompileFunction(func, TIMEOUT, monitor)
        .getDecompiledFunction()
    )
    code = decomp.getC() if decomp else ""

    return [f"{func.getName()}-{func.iD}", code]


def analyze(flat_api: "ghidra.program.flatapi.FlatProgramAPI"):
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.listing import Function
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.app.script import GhidraScriptUtil

    program: "ghidra.program.model.listing.Program" = flat_api.getCurrentProgram()
    # decompilers = setup_decompliers(program)
    # if GhidraProgramUtilities.shouldAskToAnalyze(program):
    GhidraScriptUtil.acquireBundleHostReference()
    flat_api.analyzeAll(program)
    GhidraScriptUtil.releaseBundleHostReference()

    all_funcs: list[Function] = []
    for f in program.functionManager.getFunctions(True):
        all_funcs.append(f)

    monitor = ConsoleTaskMonitor()

    for func in all_funcs:
        if func.getName() != "main":
            continue
        decompiler = DecompInterface()
        decompiler.openProgram(program)
        decomp = decompiler.decompileFunction(func, 1, monitor)
        c = decomp.getDecompiledFunction().getC()
        print(c)
        # decompile_func(func, monitor, decompilers)


class FileModifiedHandler(FileSystemEventHandler):
    def __init__(self, binary_path: Path, project: "ghidra.base.project.GhidraProject"):
        super().__init__()
        self.binary_path = binary_path
        self.project = project

    def on_modified(self, event):
        if not event.is_directory:
            from ghidra.program.flatapi import FlatProgramAPI

            program = self.project.importProgram(self.binary_path)
            flat_api = FlatProgramAPI(program)
            analyze(flat_api)


def main():
    parser = argparse.ArgumentParser(description="Decompiler explorer")

    parser.add_argument("bin", help="Path to binary used for analysis")
    parser.add_argument(
        "-o",
        "--output-path",
        help="Location for all decompilations",
        default=".decompilations",
    )

    args = parser.parse_args()

    print(args)

    bin_path = Path(args.bin)
    project_location = Path(".ghidra_projects")
    output_path = Path(args.output_path) / bin_path.name
    output_path.mkdir(exist_ok=True, parents=True)

    pyhidra.start(True)

    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.base.project import GhidraProject
    from ghidra.program.model.listing import Program

    # project_location = project_location / bin_path.name
    # project = GhidraProject.openProject(project_location, bin_path.name, True)
    # program = project.openProgram("/", bin_path.name, False)
    # program = project.importProgram(bin_path)
    # project.save(program)
    # project.close()

    # return

    from pyhidra.launcher import PyhidraLauncher, HeadlessPyhidraLauncher

    if not PyhidraLauncher.has_launched():
        HeadlessPyhidraLauncher().start()

    project_name = bin_path.name
    binary_path = bin_path

    from ghidra.base.project import GhidraProject
    from ghidra.program.model.listing import Program
    from java.io import IOException

    if binary_path is not None:
        binary_path = Path(binary_path)
    if project_location:
        project_location = Path(project_location)
    else:
        project_location = binary_path.parent
    if not project_name:
        project_name = f"{binary_path.name}_ghidra"
    project_location = project_location / project_name
    project_location.mkdir(exist_ok=True, parents=True)

    # Open/Create project
    program: "Program" = None
    try:
        project = GhidraProject.openProject(project_location, project_name, True)
        if binary_path is not None:
            if project.getRootFolder().getFile(binary_path.name):
                program = project.openProgram("/", binary_path.name, False)
    except IOException:
        project = GhidraProject.createProject(project_location, project_name, False)

    # program = project.importProgram(binary_path)
    # if binary_path is not None and program is None:
    # project.saveAs(program, "/", program.getName(), True)

    from ghidra.app.script import GhidraScriptUtil

    GhidraScriptUtil.acquireBundleHostReference()

    observer = Observer()

    for i in range(10):
        program = project.importProgram(binary_path)
        flat_api = FlatProgramAPI(program)
        analyze(flat_api)
        sleep(10)

    GhidraScriptUtil.releaseBundleHostReference()
    # project.saveAs(program, "/", program.getName(), True)
    # project.save(program)
    project.close()

    # with pyhidra.open_program(
    #     bin_path,
    #     project_location=project_location,
    #     project_name=bin_path.name,
    #     analyze=False,
    # ) as flat_api:
    #     from ghidra.program.util import GhidraProgramUtilities
    #     from ghidra.app.script import GhidraScriptUtil

    #     program: "ghidra.program.model.listing.Program" = flat_api.getCurrentProgram()
    #     decompilers = setup_decompliers(program)
    #     if GhidraProgramUtilities.shouldAskToAnalyze(program):
    #         GhidraScriptUtil.acquireBundleHostReference()
    #         flat_api.analyzeAll(program)
    #         GhidraScriptUtil.releaseBundleHostReference()

    #     all_funcs = []

    #     for f in program.functionManager.getFunctions(True):
    #         if f.getName().startswith("FUN_"):
    #             # skip FUN for demo
    #             continue

    #         all_funcs.append(f)

    #     print(f"Decompiling {len(all_funcs)} functions using {THREAD_COUNT} threads")

    #     completed = 0
    #     decompilations = []
    #     start = time()
    #     with concurrent.futures.ThreadPoolExecutor(
    #         max_workers=THREAD_COUNT
    #     ) as executor:
    #         futures = (
    #             executor.submit(
    #                 decompile_func, func, monitor, decompilers, thread_id % THREAD_COUNT
    #             )
    #             for thread_id, func in enumerate(all_funcs)
    #         )
    #         for future in concurrent.futures.as_completed(futures):
    #             decompilations.append(future.result())
    #             completed += 1
    #             if (completed % 100) == 0:
    #                 print(
    #                     f"Completed {completed} and {int(completed/len(all_funcs)*100)}%"
    #                 )

    #     print(
    #         f"Decompiled {completed} functions for {program.name} in {time() - start}"
    #     )

    #     start = time()
    #     with concurrent.futures.ThreadPoolExecutor(
    #         max_workers=THREAD_COUNT
    #     ) as executor:
    #         futures = (
    #             executor.submit((output_path / name).write_text, decomp)
    #             for name, decomp in decompilations
    #         )
    #         for future in concurrent.futures.as_completed(futures):
    #             decompilations.append(future.result())

    #     print(
    #         f"Wrote {completed} decompilations for {program.name} to {output_path} in {time() - start}"
    #     )


if __name__ == "__main__":
    main()
