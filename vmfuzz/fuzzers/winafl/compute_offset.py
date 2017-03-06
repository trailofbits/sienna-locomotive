""" Module handling the offset computation using wingdb (without autoit)
    """

import subprocess
import os
from threading import Thread

import utils.autoit_lib as autoit_lib

WINGDB_PATH = ""

# WINGDB_SCRIPT needs the path containing \\ and r
# example: WINGDB_SCRIPT = r"C:\\Users\\tob\\script.py"
WINGDB_SCRIPT = r""

# cdb.exe: user mode debuger with command line interface
DEBUG = "cdb.exe"

AUTOIT_BIN = ""


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
            line = line.rstrip().split("#")
            func_name, mod, off, depth, filename, uniq_id = line[2], line[
                4], int(line[6], 16), int(line[8]), line[10], line[12]
            resultats.append((func_name, mod, off, depth, filename, uniq_id))
    resultats_set = set(resultats)
    return resultats_set


def launch_autoit(autoit_script, program_name, fuzz_file):
    """
    Launch the autoit script
    Args:
        autoit_script (string): path the to script
        path_program (string): path the to the program
        fuzz_file (string): path to the input to be passed as argument 
    Note: it kills the program when autoit is finished
    """
    cmd_auto_it = [AUTOIT_BIN, autoit_script, fuzz_file]
    proc_auto_it = subprocess.Popen(cmd_auto_it)
    proc_auto_it.wait()

   # be sure that autoit is not running anymore
    cmd_kill_program = "Taskkill /IM " + program_name + " /F"
    proc = subprocess.Popen(cmd_kill_program)
    proc.wait()


def run_autoit(autoit_script, path_program, program_name, fuzz_file):
    """
    Run the offset computing with an autoit script
    Args:
        autoit_script (string): path the to script
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
           os.path.join(path_program, program_name)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE)

    autoit_script = autoit_lib.get_autoit_path(autoit_script, "offset")
    t_autoit = Thread(target=launch_autoit, args=(
        autoit_script, program_name, fuzz_file,))
    t_autoit.start()

    resultats = []
    for line in iter(proc.stdout.readline, b''):
        if line.startswith("FOUND:"):
            line = line.rstrip().split("#")
            func_name, mod, off, depth, filename, uniq_id = line[2], line[
                4], int(line[6], 16), int(line[8]), line[10], line[12]
            resultats.append((func_name, mod, off, depth, filename, uniq_id))
    resultats_set = set(resultats)

    # be sure that autoit is not running anymore
    cmd_kill_autoit = "Taskkill /IM AutoIT3.exe /F"
    proc = subprocess.Popen(cmd_kill_autoit)
    proc.wait()

    return resultats_set
