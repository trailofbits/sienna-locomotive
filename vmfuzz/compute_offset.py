""" Module handling !exploitable (without GUI interaction)
    !exploitable dll (MSEC.dll) has to be installed in
    DEBUG_PATH\\winext
    Example:
    C:\\Program Files\\Windows Kits\\10\\Debuggers\\x86\\winext"
    or
    C:\\Program Files\\Windows Kits\\10\\Debuggers\\x64\\winext"
    """

import subprocess
import os

SIZEOFCALL = 5

WINGDB_PATH = ""

# WINGDB_SCRIPT needs the path containing \\ and r
# example: WINGDB_SCRIPT = r"C:\\Users\\tob\\script.py"
WINGDB_SCRIPT = r""

# cdb.exe: user mode debuger with command line interface
DEBUG = "cdb.exe"


def print_resultats(res):
    """
    Print resultats (sorted by modules) (debug function)
    Args:
        res (list) resultats to print
    """
    sorted_res = sorted(res, key=lambda x: x[1])
    for func, mod, off in sorted_res:
        print "Func " + func + " found in module " + mod + " at off " + hex(off)

def make_wingdb_cmd(module, function):
    """
    Create a wingdb cmd:
        - Add a break at module!function
        - Call the WINGDB_SCRIPT script when the breakpoint is met
    Args:
        module (string): targeted module
        function (string): targeted function
    Returns:
        the command as a string
    """
    return r'bp ' + module + '!' + function + r' "!py ' + WINGDB_SCRIPT + ' ' + function + r';gc;";'

def run(path_program, program_name, parameters):
    """
    Run the offset computing
    Args:
        path_program (string): path the to the program
        program_name (string): name of the program
        parameters (string list): parameters of the script
    Returns:
        list of triplets: (function, module, offset)
    """
    wingdb_cmd = ".load winext/pykd.pyd;"
    wingdb_cmd = wingdb_cmd + make_wingdb_cmd("kernel32", "CreateFileW")
    wingdb_cmd = wingdb_cmd + make_wingdb_cmd("kernel32", "CreateFileA")
    wingdb_cmd = wingdb_cmd + make_wingdb_cmd("msvcrt", "fopen")
    wingdb_cmd = wingdb_cmd + make_wingdb_cmd("MSVCR100", "fopen")

    wingdb_cmd = wingdb_cmd + "gc;q"
    cmd = [WINGDB_PATH + DEBUG, "-c", wingdb_cmd,
           os.path.join(path_program, program_name)] + parameters
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    resultats = []
    for line in iter(proc.stdout.readline, b''):
        if line.startswith("FOUND:"):
            line = line.rstrip().split(" ")
            func_name, mod, off = line[2], line[4], int(line[6], 16)
            resultats.append((func_name, mod, off))
    resultats_set = set(resultats)
    return resultats_set
