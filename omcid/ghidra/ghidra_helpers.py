"""
Shared utilities for all Ghidra/pyghidra scripts targeting the stock v7.5.1 omcid binary.

Usage:
    from ghidra_helpers import ensure_started, open_program, decompile_function

    ensure_started()
    with open_program() as (project, program):
        # program is ready, all annotations visible
        code = decompile_function(program, 0x00432bd0)
        print(code)
"""
import os
import sys
import contextlib
import subprocess

# ── Constants ──────────────────────────────────────────────────────────────────
GHIDRA_INSTALL = os.path.expanduser("~/ghidra_12.0.3_PUBLIC")
PROJECT_DIR = os.path.expanduser("~/ghidra_projects")
PROJECT_NAME = "omcid_v751"
BINARY = os.path.expanduser("~/dev-orig/opt/lantiq/bin/omcid")
PROGRAM_NAME = "omcid"          # name inside the Ghidra project
PROGRAM_PATH = "/" + PROGRAM_NAME
BASE_ADDR = 0x400000


def ensure_started():
    """Start the pyghidra/JVM if not already running."""
    os.environ["GHIDRA_INSTALL_DIR"] = GHIDRA_INSTALL
    import pyghidra
    if not pyghidra.started():
        pyghidra.start()


@contextlib.contextmanager
def open_program(write=False):
    """
    Open the canonical Ghidra project and yield (project, program).

    If the project doesn't exist yet, raises FileNotFoundError — run
    create_project.py first.

    Args:
        write: If True, wraps the body in a transaction so annotations
               can be saved.  The program is saved on clean exit.
    """
    from pyghidra import api

    project = api.open_project(PROJECT_DIR, PROJECT_NAME)
    try:
        with api.program_context(project, PROGRAM_PATH) as program:
            if write:
                with api.transaction(program, "script"):
                    yield project, program
                # save after transaction completes
                program.getDomainFile().save(api.task_monitor())
            else:
                yield project, program
    finally:
        project.close()


def get_addr(program, va):
    """Convert an integer VA to a Ghidra Address."""
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(va)


def get_func_at(program, va):
    """Get the function containing the given VA."""
    addr = get_addr(program, va)
    return program.getFunctionManager().getFunctionContaining(addr)


def get_func_by_name(program, name):
    """Get a function by its name (first match)."""
    fm = program.getFunctionManager()
    it = fm.getFunctions(True)
    while it.hasNext():
        f = it.next()
        if f.getName() == name:
            return f
    return None


def decompile_function(program, func_or_va, timeout=120):
    """
    Decompile a function and return its C code as a string.

    Args:
        func_or_va: Either a Ghidra Function object or an integer VA.
        timeout: Decompilation timeout in seconds.

    Returns:
        str: The decompiled C code, or None on failure.
    """
    from ghidra.app.decompiler import DecompInterface
    from pyghidra import api

    if isinstance(func_or_va, int):
        func = get_func_at(program, func_or_va)
        if func is None:
            print(f"  No function at 0x{func_or_va:08x}", file=sys.stderr)
            return None
    else:
        func = func_or_va

    decomp = DecompInterface()
    decomp.openProgram(program)
    try:
        result = decomp.decompileFunction(func, timeout, api.task_monitor())
        if result and result.decompileCompleted():
            df = result.getDecompiledFunction()
            if df:
                return df.getC()
        if result:
            print(f"  Decompile failed: {result.getErrorMessage()}", file=sys.stderr)
        return None
    finally:
        decomp.dispose()


def find_literal_pool_refs(program, target_va):
    """
    Find functions that reference a given VA through literal pool pointers.

    MIPS16e loads 32-bit addresses through literal pools (PC-relative loads
    from data words embedded near the code). Ghidra labels these as
    PTR_s_xxx. The chain is: code → literal pool entry → target VA.

    Returns list of (func, ref_addr) tuples.
    """
    from pyghidra import api
    mem = program.getMemory()
    ref_mgr = program.getReferenceManager()
    listing = program.getListing()
    space = program.getAddressFactory().getDefaultAddressSpace()

    # Scan all initialized memory for 4-byte pointers to target_va
    results = []
    for block in mem.getBlocks():
        if not block.isInitialized():
            continue
        bstart = block.getStart().getOffset()
        bsize = block.getSize()
        for i in range(0, bsize - 3, 4):
            try:
                val = mem.getInt(space.getAddress(bstart + i)) & 0xFFFFFFFF
                if val == target_va:
                    ptr_addr = space.getAddress(bstart + i)
                    # Find code that references this literal pool entry
                    refs = ref_mgr.getReferencesTo(ptr_addr)
                    for ref in refs:
                        func = listing.getFunctionContaining(ref.getFromAddress())
                        if func:
                            results.append((func, ref.getFromAddress()))
            except Exception:
                pass
    return results


def extract_string_offsets():
    """
    Extract all __FUNCTION__-style string offsets from the stock binary.

    Returns dict of {string_value: file_offset}.
    """
    result = subprocess.run(
        ['strings', '-t', 'x', BINARY],
        capture_output=True, text=True
    )
    offsets = {}
    for line in result.stdout.strip().split('\n'):
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            try:
                off = int(parts[0], 16)
                s = parts[1]
                offsets[s] = off
            except ValueError:
                pass
    return offsets
