"""
    Module handling winafl
"""
import subprocess
import time
import os
import datetime
import threading
import logging

import compute_offset
import winafl_constants
import utils.autoit_lib as autoit_lib
import utils.file_manipulation as file_manipulation


def init(config_system):
    """
    Initialize the constantss used by the module
    Args:
        The system configuration as a dict
    """
    winafl_constants.AUTOIT_BIN = config_system['path_autoit_bin']
    winafl_constants.WINAFL_PATH = config_system['path_winafl']
    winafl_constants.WINAFL_BIN = config_system['winafl_bin']
    winafl_constants.DYNAMORIO_PATH = config_system['path_dynamorio']
    winafl_constants.DRRUN = config_system['path_drrun_bin']
    winafl_constants.WINAFLDLL = config_system['path_winafl_dll']
    winafl_constants.WINAFL_WORKING_DIR = config_system[
        'path_winafl_working_dir']
    winafl_constants.WINAFL_DEFAULT_TIMEOUT = config_system[
        'winafl_default_timeout']
    winafl_constants.WINAFL_LAST_PATH_TIMEOUT = config_system[
        'winafl_last_path_timeout']
    winafl_constants.WINAFL_FUZZING_ITERATION = config_system[
        'winafl_fuzzing_iteration']
    winafl_constants.WINAFL_AUTOIT_STOP = config_system[
        'path_autoit_stop_winafl']

    compute_offset.WINGDB_PATH = config_system['path_wingdb_dir']
    compute_offset.WINGDB_SCRIPT = config_system['path_wingdb_script']
    compute_offset.AUTOIT_BIN = config_system['path_autoit_bin']

    autoit_lib.AUTOIT_LIB_DIRECTORY = config_system['path_autoit_lib']
    autoit_lib.AUTOIT_WORKING_DIRECTORY = config_system['path_autoit_working_dir']



def generate_drrun_cmd(config, running_cmd):
    """
    Generate drrun.exe command line
    Args:
        config (dict): configuration
        running_cmd (list string)
    Returns:
        drrun.exe cmd (list string)
    """
    drrun_cmd = [
        winafl_constants.DRRUN,
        "-c",
        winafl_constants.WINAFLDLL,
        "-debug",
        "-target_module",
        config['module'],
        '-target_offset',
        config['offset'],
        '-fuzz_iterations',
        '10',
        '-nargs',
        config['nargs'],
        '--'
    ]
    return drrun_cmd + running_cmd


def generate_winafl_cmd(config, running_cmd):
    """
    Generate winafl command line
    Args:
        config (dict): configuration
        running_cmd (list string)
    Returns:
        winafl cmd (list string)
    """
    winafl_cmd = [
        winafl_constants.WINAFL_PATH + winafl_constants.WINAFL_BIN,
        '-i',
        config['in_dir'],
        '-o',
        config['out_dir'],
        '-D',
        winafl_constants.DYNAMORIO_PATH,
        '-t',
        str(config['timeout']),
        '-f',
        config['file'],
        '--',
        '-coverage_module',
        config['module'],
        '-target_module',
        config['module'],
        '-target_offset',
        config['offset'],
        '-nargs',
        config['nargs'],
        '-fuzz_iterations',
        config['fuzz_iterations'],
        '--'
    ]
    running_cmd = ["@@" if config['file'] in x else x for x in running_cmd]
    return winafl_cmd + running_cmd


def pp_cmd(cmd):
    """
    Convert a list of string to a string
    Args:
        cmd (list of string)
    Returns:
        cmd as a string
    """
    return ' '.join(cmd)


def run_drrun(config, running_cmd):
    """
    Run drrun.exe (debug function)
    Args:
        config (dict): configuration
        running_cmd (list string)

    Log stdout in log_out file, stderr in log_err file
    """
    cmd = generate_drrun_cmd(config, running_cmd)
    log_out = open("log_out", 'w')
    log_err = open("log_err", 'w')
    proc = subprocess.Popen(cmd, shell=True,
                            stdout=log_out, stderr=log_err,
                            cwd=config['working_dir'])
    proc.wait()


def run_winafl(config_winafl, running_cmd):
    """
    Run winafl
    Args:
        config_winafl (dict): winafl configuration
        running_cmd (list string)
    Returns: 0 if error, 1 if success
    TODO JF: To be improved: using timeout and detecting if process still running
    """

    cmd = generate_winafl_cmd(config_winafl, running_cmd)
    logging.debug(pp_cmd(cmd))
    proc = subprocess.Popen(pp_cmd(cmd), cwd=config_winafl['working_dir'])
    time.sleep(60)
    if proc.poll() is None:
        logging.info("Winafl running!")
        return 1
    else:
        logging.info("Winafl not running")
        return 0


def launch_autoit(path_autoit_script, fuzz_file, stop):
    """
    Launches auto recursively (untill stop is set)
    Args:
        path_autoit_script (string): path to the autoit to execute
        fuzz_file (string): the input passed as argument to the autoit script
        stop (Thead.event): event allowing to stop the loop
    """
    while not stop.is_set():
        cmd_auto_it = [winafl_constants.AUTOIT_BIN,
                       path_autoit_script, fuzz_file]
        logging.debug("Cmd autoit "+str(cmd_auto_it))
        proc_auto_it = subprocess.Popen(cmd_auto_it)
        proc_auto_it.wait()


def run_winafl_autoit(config_winafl, path_autoit_script, program_name, running_cmd, fuzz_file):
    """
    Run winafl
    Args:
        config_winafl (dict): winafl configuration
        running_cmd (list string)
    Returns: 0 if error, 1 if success
    TODO JF: To be improved: using timeout and detecting if process still running
    """

    cmd = generate_winafl_cmd(config_winafl, running_cmd)
    proc = subprocess.Popen(pp_cmd(cmd), cwd=config_winafl['working_dir'])

    path_autoit_script = autoit_lib.get_autoit_path(
        path_autoit_script, "winafl")

    t_autoit_stop = threading.Event()
    t_autoit = threading.Thread(target=launch_autoit, args=(
        path_autoit_script, fuzz_file, t_autoit_stop,))
    t_autoit.start()

    time.sleep(60)
    if proc.poll() is None:
        logging.info("Winafl running!")
        return (1, t_autoit_stop)
    else:
        logging.info("Winafl not running")

        t_autoit_stop.set()

        cmd_kill_program = "Taskkill /IM " + program_name + " /F"
        proc = subprocess.Popen(cmd_kill_program)
        proc.wait()

        cmd_kill_program = "Taskkill /IM AutoIt3.exe /F"
        proc = subprocess.Popen(cmd_kill_program)
        proc.wait()
        return (0, t_autoit_stop)


def parsing_stat(file_name):
    """
    Parsing winafl fuzzer_stats file
    Args:
        file_name (string): path to the fuzzer_stats file
    Returns:
        dict with the content of the file
        iF the fuzzer_stats does not exist, returns an empty dict
    """
    if not os.path.exists(file_name):
        return {}
    f_fuzzer_stats = open(file_name, "r")
    fuzzer_stats = f_fuzzer_stats.read()
    f_fuzzer_stats.close()
    fuzzer_stats = fuzzer_stats.split('\n')
    # for each line: "xxx :threading yyyy" becomes (xxx,yyy)
    fuzzer_stats = [(x[0:x.find(':')].rstrip(), x[x.find(':') + 2:])
                    for x in fuzzer_stats]
    fuzzer_stats = dict(fuzzer_stats)
    return fuzzer_stats


def get_last_crash_sec(fuzzer_stats):
    """
    Return the time (in sec) between now and the last crash
    Args:
        fuzerer_stats (dict)
    Returns
        The time in seconds between now and the last crash
    """
    last_crash = int(fuzzer_stats['last_crash'])
    if last_crash == 0:
        return 0
    now = datetime.datetime.utcnow()
    # convert timestamp from windows
    last_crash = datetime.datetime(1601, 1, 1) + \
        datetime.timedelta(0, last_crash)
    return (now - last_crash).total_seconds()


def get_last_path_sec(fuzzer_stats):
    """
    Return the time (in sec) between now and the last path discover
    Args:
        fuzerer_stats (dict)
    Returns
        The time in seconds between now and the last path discover
    """
    last_path = int(fuzzer_stats['last_path'])
    now = datetime.datetime.utcnow()
    # convert timestamp from windows
    last_path = datetime.datetime(1601, 1, 1) + \
        datetime.timedelta(0, last_path)
    return (now - last_path).total_seconds()


def get_number_crashes(fuzzer_stats):
    """
    Returns the number of crashes found
    Args:
        fuzerer_stats (dict)
    Returns:
        The number of crashes (int)
    """
    return int(fuzzer_stats['uniq_crashes'])


def check_winafl(out_dir):
    """
    Loop until winafl does not found new paths
    Args:
        out_dir (string): path to the out directory of winafl
    Every WINAFL_LAST_PATH_TIMEOUT, it checks if a new path was disccovered recently
    """
    while True:
        time.sleep(60 * winafl_constants.WINAFL_LAST_PATH_TIMEOUT)
        fuzzer_stats = parsing_stat(out_dir + "\\fuzzer_stats")
        if not fuzzer_stats:
            break
        last_path_sec = get_last_path_sec(fuzzer_stats)
        logging.info("Last path generated: " + str(last_path_sec) +
                     " secs (" + (str(last_path_sec / 60) + " mins)"))
        if last_path_sec > 60 * winafl_constants.WINAFL_LAST_PATH_TIMEOUT:
            break


def kill_timeout(program_name, timeout):
    time.sleep(timeout)
    cmd_kill_program = "Taskkill /IM " + program_name + " /F"
    proc = subprocess.Popen(cmd_kill_program)
    proc.wait()


def move_generated_inputs(config_winafl, file_format):
    """
    Move generated files
    Args:   
        config_winafl (dict): the winafl configuration
        file_format (string) the file format
    Names of the moved files contains:
        - "-C" for crashes 
        - "-H" for hangs
        - "-N" for normals
    """
    dst_dir = os.path.join(winafl_constants.WINAFL_WORKING_DIR, config_winafl['in_dir'])
    in_dir = os.path.join(winafl_constants.WINAFL_WORKING_DIR, config_winafl['out_dir'])
    file_manipulation.move_generated_inputs(
        os.path.join(in_dir, "crashes"), dst_dir, "-C" + file_format)
    file_manipulation.move_generated_inputs(
        os.path.join(in_dir, "hangs"), dst_dir, "-H" + file_format)
    file_manipulation.move_generated_inputs(
        os.path.join(in_dir, "queue"), dst_dir, "-N" + file_format)


def launch_fuzzing(config):
    """
    Automated winafl launching
    Args:
        The user configuration as a dict

    On a program:
        - compute the set of possible (offset,module)
        - Launches on each (offset,module) winafl
        - Run winafl until no new path has been found recently
    """
    logging.info("Starting automated winafl")
    if 'running_time' not in config:
        timeout = str(winafl_constants.WINAFL_DEFAULT_TIMEOUT)
    else:
        timeout = config['running_time'] * 2000
    if config['using_autoit']:
        timeout = timeout + "+"

    in_dir = "in_" + config['program_name'][:-4]  # remove the extension
    out_dir = "out_" + config['program_name'][:-4]

    seed_offset_name = "seed" + config['file_format']
    seed_offset_path = os.path.join(winafl_constants.WINAFL_WORKING_DIR, in_dir, seed_offset_name)

    config_winafl = {'in_dir': in_dir,
                     'out_dir': out_dir,
                     "timeout": timeout,
                     "file": seed_offset_name,
                     "module": "",
                     "offset": "",
                     "fuzz_iterations": str(winafl_constants.WINAFL_FUZZING_ITERATION),
                     "working_dir":  winafl_constants.WINAFL_WORKING_DIR,
                     "nargs": "5"}

    running_cmd = ['"' + config['path_program'] +
                   config["program_name"] + '"'] + config['parameters']

    if config['using_autoit']:
        possible_offsets = compute_offset.run_autoit(config['path_autoit_script'],
                                                     config['path_program'],
                                                     config['program_name'],
                                                     seed_offset_path)
    else:
        if not config['auto_close']:
            t_kill = threading.Thread(target=kill_timeout, args=(
                config['program_name'], config['running_time'] * 2 + 25,))
            t_kill.start()

        possible_offsets = compute_offset.run(config['path_program'],
                                              config['program_name'],
                                              config['parameters'] + [seed_offset_path])
    possible_offsets = compute_offset.filter_resultats_by_filename(
        possible_offsets, seed_offset_name)
    logging.info("After filter " + str(possible_offsets))
    prop_winafl = compute_offset.winafl_proposition(possible_offsets)
#    prop_winafl.reverse()
    logging.info("Winafl number of propositions: " + str(len(prop_winafl)))
    logging.info(str(prop_winafl))
    for off, mod in prop_winafl:
        logging.info("Try " + hex(off) + " at mod " + mod)
        config_winafl['offset'] = hex(off)
        config_winafl['module'] = mod
        config_winafl['out_dir'] = out_dir + "_" + mod + "_" + hex(off)
        cmd = generate_winafl_cmd(config_winafl, running_cmd)
        logging.info("Cmd: " + pp_cmd(cmd))

        path_file_to_fuzz = os.path.join(winafl_constants.WINAFL_WORKING_DIR, config_winafl['file'])

        if config['using_autoit']:
            (ret, t_autoit_stop) = run_winafl_autoit(config_winafl,
                                                     config[
                                                         'path_autoit_script'],
                                                     config['program_name'],
                                                     running_cmd,
                                                     path_file_to_fuzz)
        else:
            ret = run_winafl(config_winafl, running_cmd + [path_file_to_fuzz])

        if ret == 1:
            check_winafl(winafl_constants.WINAFL_WORKING_DIR +
                         config_winafl['out_dir'])
            if config['using_autoit']:
                t_autoit_stop.set()

        cmd_kill_program = "Taskkill /IM AutoIt3.exe /F"
        proc = subprocess.Popen(cmd_kill_program)
        proc.wait()

        cmd_kill_winafl = "Taskkill /IM " + winafl_constants.WINAFL_BIN + " /F"
        proc = subprocess.Popen(cmd_kill_winafl)
        proc.wait()

        cmd_auto_it = [winafl_constants.AUTOIT_BIN,
                       winafl_constants.WINAFL_AUTOIT_STOP]
        proc_auto_it = subprocess.Popen(cmd_auto_it)
        proc_auto_it.wait()

        cmd_kill_program = "Taskkill /IM " + config['program_name'] + ".exe /F"
        proc = subprocess.Popen(cmd_kill_program)
        proc.wait()

        move_generated_inputs(config_winafl, config['file_format'])

    logging.info('All modules tested')
