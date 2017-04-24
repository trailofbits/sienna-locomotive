""" Module handling the offset computation using windbg (without autoit)
    """

import subprocess
import os
from threading import Thread
import time

import autoit.autoit as autoit
import autoit.autoit_lib as autoit_lib
import utils.run_process as run_process
import utils.logs as logging

WINDBG_PATH32 = ""
WINDBG_PATH64 = ""

WINDBG_SCRIPT = r""

# cdb.exe: user mode debuger with command line interface
DEBUG = "cdb.exe"


def init(config_system):
    """
    Initialize the constants used by the module

    Args:
        config_system (dict): The system configuration
    """

    global WINDBG_SCRIPT
    global WINDBG_PATH32
    global WINDBG_PATH64

    autoit.init(config_system)

    WINDBG_PATH32 = os.path.join(config_system['path_windbg'],
                                 'x86')
    WINDBG_PATH64 = os.path.join(config_system['path_windbg'],
                                 'x64')
    WINDBG_SCRIPT = os.path.join(
        config_system['path_vmfuzz'],
        r"fuzzers\winafl\compute_offset_windbg.py")

    # Replace needed because windbg interprete \\ as \
    WINDBG_SCRIPT = WINDBG_SCRIPT.replace("\\", "\\\\")


def parse_line_result_script(line):
    """
    Parse a resulft of the wingdb script

    Args:
        line (string): line to be parse
    Returns:
        (string, string, int, string, string, string, string):
        func_name, mod, off, depth, filename, coverage, uniq_id
    """
    line = line.rstrip().split("#")
    func_name, mod, off, depth, filename, coverage, uniq_id = line[2], line[
        4], line[6], int(line[8]), line[10], line[12], line[14]
    return func_name, mod, off, depth, filename, coverage, uniq_id


def winafl_proposition(res):
    """
    Sort results and return a list of proposition to be used with winafl

    Args:
        res : resultats to sorted
    Returns:
        (string list) list: list of targets
    """
    # ((mod, off), [mod_cod] )
    res = [((x[1], x[2]), list(set(x[5].split('%')))) for x in res]
    res_dict = {}
    # use a dict on mod,off to remove dupplicate
    # merge mod_cov if they share the same (mod,off)
    for (k, v) in res:
        if k in res_dict:
            res_dict[k] = list(set(res_dict[k] + v))
        else:
            res_dict[k] = v
    # transform to a list of dict
    res = [{'module': mod, 'offset': off, 'cov_modules': cov_mod}
           for ((mod, off), cov_mod)
           in res_dict.iteritems()]
    return res


def make_windbg_cmd(arch, module, function, fuzz_file):
    """
    Create a windbg cmd:
        - Add a break at module!function
        - Call the WINDBG_SCRIPT script when the breakpoint is met

    Args:
        arch (string): architecture of the program (x86 or x64)
        module (string): targeted module
        function (string): targeted function
        fuzz_file (string): path to the input to be passed as argument
    Returns:
        string: the command
    """

    # Replace needed because windbg interprete \\ as \
    fuzz_file = fuzz_file.replace("\\", "\\\\")
    script = WINDBG_SCRIPT
    cmd = r'bp ' + module + '!' + function + r' "!py ' + \
        script + ' ' + function + ' ' + fuzz_file + ' ' + arch + r';gc;";'
    return cmd


def run(arch, path_program, program_name, parameters, fuzz_file):
    """
    Run the offset computing

    Args:
        arch (string): architecture of the program (x86 or x64)
        path_program (string): path the to the program
        program_name (string): name of the program
        parameters (string list): parameters of the script
        fuzz_file (string): path to the input to be passed as argument
    Returns:
        list of triplets: (function, module, offset, depth)
    Note:
        fuzz_file needs to be provided,\
        even if its already in the parameters list
    """
    windbg_cmd = ".load winext/pykd.pyd;"
    windbg_cmd = windbg_cmd + \
        make_windbg_cmd(arch, "kernel32", "CreateFileW", fuzz_file)
    windbg_cmd = windbg_cmd + \
        make_windbg_cmd(arch, "kernel32", "CreateFileA", fuzz_file)
    windbg_cmd = windbg_cmd + \
        make_windbg_cmd(arch, "msvcrt", "fopen", fuzz_file)
    windbg_cmd = windbg_cmd + \
        make_windbg_cmd(arch, "MSVCR100", "fopen", fuzz_file)

    windbg_cmd = windbg_cmd + "gc;q"

    if arch == "x86":
        windbg_bin = os.path.join(WINDBG_PATH32, DEBUG)
    elif arch == "x64":
        windbg_bin = os.path.join(WINDBG_PATH64, DEBUG)
    else:
        logging.error("Arch not supported " + arch)
        exit(0)
    # -2 needed to open console application in new windows
    cmd = [windbg_bin, "-2", "-c", windbg_cmd,
           os.path.join(path_program, program_name)] + parameters
    logging.debug('Windbg: '+str(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    resultats = []
    for line in iter(proc.stdout.readline, b''):
        logging.debug(line)
        if line.startswith("FOUND:"):
            resultats.append(parse_line_result_script(line))
    resultats_set = set(resultats)
    return resultats_set


def launch_autoit(autoit_script, program_name, fuzz_file):
    """
    Launch the autoit script

    Args:
        autoit_script (string): path the to script
        path_program (string): path the to the program
        fuzz_file (string): path to the input to be passed as argument
    Note:
        it kills the program when autoit is finished
    """
    # Small sleep seems needed to avoid windbg to close? Reason
    # TODO JF: find the proper explanation
    time.sleep(5)
    autoit.run_and_wait(autoit_script, [fuzz_file])

    run_process.kill_process(program_name)


def run_autoit(arch, autoit_script, path_program, program_name, fuzz_file):
    """
    Run the offset computing with an autoit script

    Args:
        arch (string): architecture of the program (x86 or x64)
        autoit_script (string): path the to script
        path_program (string): path the to the program
        program_name (string): name of the program
        fuzz_file (string): path to the input to be passed as argument
    Returns:
        list of triplets: (function, module, offset, depth)
    """
    windbg_cmd = ".load winext/pykd.pyd;"
    windbg_cmd = windbg_cmd + \
        make_windbg_cmd(arch, "kernel32", "CreateFileW", fuzz_file)
    windbg_cmd = windbg_cmd + \
        make_windbg_cmd(arch, "kernel32", "CreateFileA", fuzz_file)
    windbg_cmd = windbg_cmd + \
        make_windbg_cmd(arch, "msvcrt", "fopen", fuzz_file)
    windbg_cmd = windbg_cmd + \
        make_windbg_cmd(arch, "MSVCR100", "fopen", fuzz_file)

    windbg_cmd = windbg_cmd + "gc;q"

    if arch == "x86":
        windbg_bin = os.path.join(WINDBG_PATH32, DEBUG)
    elif arch == "x64":
        windbg_bin = os.path.join(WINDBG_PATH64, DEBUG)
    else:
        logging.error("Arch not supported " + arch)
        exit(0)

    cmd = [windbg_bin, "-c", windbg_cmd,
           os.path.join(path_program, program_name)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE)

    autoit_script = autoit_lib.get_autoit_path(autoit_script, "offset")
    t_autoit = Thread(target=launch_autoit, args=(
        autoit_script, program_name, fuzz_file,))

    t_autoit.start()

    resultats = []
    for line in iter(proc.stdout.readline, b''):
        logging.debug(line)
        if line.startswith("FOUND:"):
            resultats.append(parse_line_result_script(line))
    resultats_set = set(resultats)

    # be sure that autoit is not running anymore
    run_process.kill_process("AutoIt3.exe")

    return resultats_set
