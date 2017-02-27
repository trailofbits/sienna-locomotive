""" Module handling the offset computation using wingdb
    """

import subprocess
import os

WINGDB_PATH = ""

# WINGDB_SCRIPT needs the path containing \\ and r
# example: WINGDB_SCRIPT = r"C:\\Users\\tob\\script.py"
WINGDB_SCRIPT = r""

# cdb.exe: user mode debuger with command line interface
DEBUG = "cdb.exe"


def winafl_proposition(res):
    """
    Sort results and return a list of proposition to be used with winafl
    Args:
        res : resultats to sorted
    Returns:
        list of couple (offset,module)
    """
    res = [(x[2], x[1], x[3]) for x in res]
    res = set(res)
    res = [(x, y) for (x, y, _) in sorted(res, key=lambda x: x[2])]
    res_uniq = []
    # remove duplicates
    [res_uniq.append(x) for x in res if x not in res_uniq]
    return res_uniq


def print_resultats(res):
    """
    Print resultats (sorted by modules) (debug function)
    Args:
        res (list) resultats to print
    """
    sorted_res = sorted(res, key=lambda x: (x[5], x[3]))
    for func, mod, off, depth, filename, uniq_id in sorted_res:
        print "Func " + func + " found in module " + mod +\
              " at off " + hex(off) + " (depth " + str(depth) + ") (" +\
              filename + ") " + uniq_id


def filter_resultats_by_filename(res, txt):
    """
    Print resultats (sorted by modules) (debug function)
    Args:
        res (list) resultats to print
    """
    return [x for x in res if txt in x[4]]


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
        list of triplets: (function, module, offset, depth)
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
            func_name, mod, off, depth, filename, uniq_id = line[2], line[
                4], int(line[6], 16), int(line[8]), line[10], line[12]
            resultats.append((func_name, mod, off, depth, filename, uniq_id))
    resultats_set = set(resultats)
    return resultats_set
