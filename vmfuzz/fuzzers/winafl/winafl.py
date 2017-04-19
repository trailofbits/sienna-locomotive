"""
    Module handling winafl
"""
import subprocess
import time
import os
import threading
import shutil
import logging

import fuzzers.winafl.compute_offset as compute_offset
import fuzzers.winafl.winafl_constants as winafl_constants
import fuzzers.winafl.stats as winafl_stats
import autoit.autoit as autoit
import autoit.autoit_lib as autoit_lib
import utils.file_manipulation as file_manipulation
import utils.run_process as run_process
import utils.database as database


def init(config_system):
    """
    Initialize the module

    Args:
        config_system (dict): The system configuration
    """
    winafl_constants.WINAFL_PATH_CMIN = os.path.join(
        config_system['path_winafl'], "winafl-cmin.py")
    winafl_constants.WINAFL_PATH32 = os.path.join(
        config_system['path_winafl'], "bin32")
    winafl_constants.WINAFL_PATH64 = os.path.join(
        config_system['path_winafl'], "bin64")
    winafl_constants.DYNAMORIO_PATH32 = os.path.join(
        config_system['path_dynamorio'], "bin32")
    winafl_constants.DYNAMORIO_PATH64 = os.path.join(
        config_system['path_dynamorio'], "bin64")

    winafl_constants.WINAFL_WORKING_DIR = config_system[
        'path_winafl_working_dir']

    winafl_constants.WINAFL_AUTOIT_STOP = os.path.join(config_system[
        'path_vmfuzz'], r"autoit_lib\exit_winafl.au3")

    compute_offset.init(config_system)

    autoit_lib.AUTOIT_LIB_DIRECTORY = os.path.join(
        config_system['path_vmfuzz'], "autoit_lib")

    autoit_lib.AUTOIT_WORKING_DIRECTORY = config_system[
        'path_autoit_working_dir']


def get_in_dir(config):
    """
    Return the input directory

    Args:
        config (dict): the user configuration
    Returns:
        string; the input directory
    Notes:
        in_program_name
    """
    return "in_" + config['program_name'][:-4]  # remove the extension


def get_in_dir_seed(config):
    """
    Return the input seed directory

    Args:
        config (dict): the user configuration
    Returns:
        string; the input directory
    Notes:
        in_program_name_seed
    """
    # remove the extension and add "_seed"
    return "in_" + config['program_name'][:-4] + "_seed"


def move_winafl_dll(config):
    """
    Winafl needs winafl.dll in the current directory.

    Args:
        config (dict): user configuration
    Note:
        Use arch and working_dir fields of the config_winafl to copy \
        right version of winafl.dll (x86 or x64)
    """
    if config['arch'] == "x86":
        src_dll = os.path.join(winafl_constants.WINAFL_PATH32,
                               winafl_constants.WINAFL_DLL)
        src_showmap = os.path.join(winafl_constants.WINAFL_PATH32,
                                   winafl_constants.WINAFL_SHOWMAP)
    elif config['arch'] == "x64":
        src_dll = os.path.join(winafl_constants.WINAFL_PATH64,
                               winafl_constants.WINAFL_DLL)
        src_showmap = os.path.join(winafl_constants.WINAFL_PATH64,
                                   winafl_constants.WINAFL_SHOWMAP)
    else:
        logging.error("Architecture not supported " + config['arch'])
        exit(0)
    dst = winafl_constants.WINAFL_WORKING_DIR
    shutil.copy(src_dll, dst)
    shutil.copy(src_showmap, dst)


def init_directories(config):
    """
    Initialize directories

    Args:
        config (dict): The user configuration
    """

    if '_id' in config:
        winafl_constants.WINAFL_WORKING_DIR = os.path.join(
            winafl_constants.WINAFL_WORKING_DIR, config['_id'])

    file_manipulation.create_dir(winafl_constants.WINAFL_WORKING_DIR)

    move_winafl_dll(config)
    if 'input_dir' in config:
        in_dir = get_in_dir(config)
        in_dir_seed = get_in_dir_seed(config)
        file_manipulation.move_dir(config['input_dir'], os.path.join(
            winafl_constants.WINAFL_WORKING_DIR, in_dir))

        file_manipulation.create_dir(os.path.join(
            winafl_constants.WINAFL_WORKING_DIR, in_dir_seed))

        src = os.path.join(config['input_dir'], "seed" + config['file_format'])
        dst = os.path.join(winafl_constants.WINAFL_WORKING_DIR,
                           in_dir_seed, "seed" + config['file_format'])
        shutil.copy(src, dst)


def generate_drrun_cmd(config, running_cmd):
    """
    Generate drrun.exe command line

    Args:
        config (dict): The user configuration
        running_cmd (list string): the running command
    Returns:
        list string: drrun.exe cmd
    """
    if config['arch'] == "x86":
        winafl_path_dll = os.path.join(
            winafl_constants.WINAFL_PATH32, winafl_constants.WINAFL_DLL)
        path_dynamorio = winafl_constants.DYNAMORIO_PATH32
    elif config['arch'] == "x64":
        winafl_path_dll = os.path.join(
            winafl_constants.WINAFL_PATH64, winafl_constants.WINAFL_DLL)
        path_dynamorio = winafl_constants.DYNAMORIO_PATH64

    drrun_cmd = [
        os.path.join(path_dynamorio, winafl_constants.DRRUN_BIN),
        "-c",
        winafl_path_dll,
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


def generate_winafl_cmd(config_winafl, running_cmd):
    """
    Generate winafl command line

    Args:
        config_winafl (dict): The winafl configuration
        running_cmd (list string): the running command
    Returns:
        list string: winafl cmd
    """
    if config_winafl['arch'] == "x86":
        winafl_path_bin = os.path.join(
            winafl_constants.WINAFL_PATH32, winafl_constants.WINAFL_BIN)
        path_dynamorio = winafl_constants.DYNAMORIO_PATH32
    elif config_winafl['arch'] == "x64":
        winafl_path_bin = os.path.join(
            winafl_constants.WINAFL_PATH64, winafl_constants.WINAFL_BIN)
        path_dynamorio = winafl_constants.DYNAMORIO_PATH64
    else:
        logging.error("Unkwon archictecture " + config_winafl['arch'])
    logging.debug(winafl_path_bin)

    coverage_module = []
    for cov_mod in config_winafl['cov_modules']:
        coverage_module.append('-coverage_module')
        coverage_module.append(cov_mod)

    if not coverage_module:
        logging.error("No modules to be covered? (" +
                      str(config_winafl['cov_modules']) + ")")

    winafl_cmd = [
        winafl_path_bin,
        '-i',
        config_winafl['in_dir'],
        '-o',
        config_winafl['out_dir'],
        '-D',
        path_dynamorio,
        '-t',
        str(config_winafl['timeout']),
        '-f',
        config_winafl['file'],
        '--']
    winafl_cmd = winafl_cmd + coverage_module
    winafl_cmd = winafl_cmd + ['-target_module',
                               config_winafl['module'],
                               '-target_offset',
                               config_winafl['offset'],
                               '-nargs',
                               config_winafl['nargs'],
                               '-fuzz_iterations',
                               config_winafl['fuzz_iterations'],
                               '--'
                              ]
    running_cmd = ["@@" if config_winafl['file']
                   in x else x for x in running_cmd]
    return winafl_cmd + running_cmd


def pp_cmd(cmd):
    """
    Convert a list of string to a string

    Args:
        cmd (list of string)
    Returns:
        string: cmd as a string
    """
    return ' '.join(cmd)


def run_drrun(config, running_cmd):
    """
    Run drrun.exe (debug function)

    Args:
        config (dict): configuration
        running_cmd (list string)
    Note:
        Log stdout in log_out file, stderr in log_err file
    """
    cmd = generate_drrun_cmd(config, running_cmd)
    log_out = open("log_out", 'w')
    log_err = open("log_err", 'w')
    proc = subprocess.Popen(cmd, shell=True,
                            stdout=log_out, stderr=log_err,
                            cwd=config['working_dir'])
    proc.wait()


def run_winafl_without_autoit(config_winafl, running_cmd):
    """
    Run winafl

    Args:
        config_winafl (dict): winafl configuration
        running_cmd (list string)
    Returns:
        (int, proc): 0 if error, 1 if success and the winafl process
    Note:
        Check every 10 secondes for 1 min if the process is running
    """

    ## Need winafl.dll in the wokring directory (x86 or x64)
    #move_winafl_dll(config_winafl)

    cmd = generate_winafl_cmd(config_winafl, running_cmd)
    logging.debug("Winafl working dir; " + config_winafl['working_dir'])
    cmd_drrun = generate_drrun_cmd(config_winafl, running_cmd)
    logging.debug("drrun cmd: " + pp_cmd(cmd_drrun))

    logging.debug("winafl cmd: " + pp_cmd(cmd))

    config_winafl['winafl_starting_time'] = time.time()
    proc = subprocess.Popen(pp_cmd(
        cmd), creationflags=subprocess.CREATE_NEW_CONSOLE, cwd=config_winafl['working_dir'])

    # let winafl runs for one min
    for _ in range(0, 6):
        time.sleep(10)
        logging.debug("On run")
        if proc.poll() is not None:
            logging.debug("process stoped?")
            return (0, proc)
    logging.debug("process running")
    return (1, proc)


def launch_autoit(path_autoit_script, fuzz_file, stop):
    """
    Launches auto recursively (untill stop is set)

    Args:
        path_autoit_script (string): path to the autoit to execute
        fuzz_file (string): the input passed as argument to the autoit script
        stop (Thead.event): event allowing to stop the loop
    """
    while not stop.is_set():
        autoit.run_and_wait(path_autoit_script, [fuzz_file])

        # check if the main thread is still active
        for thread in threading.enumerate():
            if thread.name == "MainThread":
                if not thread.is_alive():
                    return


def run_winafl_autoit(config_winafl, path_autoit_script, program_name, running_cmd, fuzz_file):
    """
    Run winafl

    Args:
        config_winafl (dict): winafl configuration
        path_autoit_script (string) : path to the autoit script
        program_name (string): the program name
        running_cmd (list string): the runnign command
        fuzz_file (string): path to the file to fuzz
    Returns:
        (ret, t, proc):
            ret : 0 if error, 1 if success\n
            t: used to stop the loop on the autoit script\n
            proc: the winafl process
    Note:
        Check every 10 secondes for 1 min if the process is running
    """

    ## Need winafl.dll in the wokring directory (x86 or x64)
    #move_winafl_dll(config_winafl)

    cmd_drrun = generate_drrun_cmd(config_winafl, running_cmd)
    logging.debug("drrun cmd: " + pp_cmd(cmd_drrun))
    cmd = generate_winafl_cmd(config_winafl, running_cmd)
    logging.debug("winafl cmd: " + pp_cmd(cmd))

    config_winafl['winafl_starting_time'] = time.time()
    proc = subprocess.Popen(pp_cmd(
        cmd), creationflags=subprocess.CREATE_NEW_CONSOLE, cwd=config_winafl['working_dir'])

    path_autoit_script = autoit_lib.get_autoit_path(
        path_autoit_script, "winafl")

    t_autoit_stop = threading.Event()
    t_autoit = threading.Thread(target=launch_autoit, args=(
        path_autoit_script, fuzz_file, t_autoit_stop,))
    t_autoit.daemon = True
    t_autoit.start()

    # let winafl runs for one min
    for _ in range(0, 6):
        time.sleep(10)
        if proc.poll() is not None:
            t_autoit_stop.set()
            run_process.kill_process(program_name)
            run_process.kill_process("AutoIt3.exe")
            return (0, t_autoit_stop, proc)
    return (1, t_autoit_stop, proc)


def generate_target(config_winafl):
    """
    Generate a target from a config
    Args:
        config_winafl (dict): The winafl configuration
    Returns:
        (dict): the target
    """

    ret = {'cov_modules': config_winafl['cov_modules'],
           'offset': config_winafl['offset'],
           'module': config_winafl['module']
          }
    return ret


def generate_stats(fuzzer_stats, config_winafl):
    """
    Generate the data to be sent to the webapp

    Args:
        fuzzer_stats (dict): The fuzzer_stats dict
        config_winafl (dict): The winafl configuration
    Returns:
        dict: data to be sent to the webapp
    """
    target = generate_target(config_winafl)
    data = {
        'fuzzers': "winafl",
        'stats': {'last_update': fuzzer_stats['last_update'],
                  'execs_done': fuzzer_stats['execs_done'],
                  'execs_per_sec': fuzzer_stats['execs_per_sec'],
                  'paths_total': fuzzer_stats['paths_total'],
                  'unique_crashes': fuzzer_stats['unique_crashes'],
                  'unique_hangs': fuzzer_stats['unique_hangs'],
                  'last_crash': fuzzer_stats['last_crash'],
                  'execs_done': fuzzer_stats['execs_done'],
                  'target': target
                 }
    }
    return data

def check_running_time(config_winafl):
    """
    Check the running time of the winafl process
    Args:
        config_winafl (dict): The winafl configuration
    Returns:
        bool: True if the running time > winafl_max_time
    """

    if 'winafl_max_time' in config_winafl:
        diff_time = time.time() - config_winafl['winafl_starting_time']
        if diff_time > config_winafl['winafl_max_time']:
            return True
    return False

def winafl_send_stats(config, config_winafl, fuzzer_stats, last_update):
    """
    Send the stats to the webapp
    Args:
        config (dict): The user configuration
        config_winafl (dict): The winafl configuration
        fuzzer_stats (dict): The fuzzer_stats dict
        last_update (int): The last timesamp
    Note:
        The data is sent as a dict {'stats' : stats}

    """

    # curr_pos is used to avoid reading the whole plot_data file
    data = generate_stats(fuzzer_stats, config_winafl)
    new_update = data['stats']['last_update']
    if new_update > last_update:
        data_send = {'stats': data}
        database.send_stats(config, data_send)
    return new_update

def process_winafl(config, config_winafl, winafl_proc):
    """
    Loop until winafl does not found new paths. Send stats to the webapp

    Args:
        config (dict): The user configuration
        config_winafl (dict): The winafl configuration
        winafl_proc (proc): the winafl process
    Returns:
        int: the return value
    Note:
        The return value can be:
            - 0: Error (no fuzzer_stats file)
            - 1: One winafl iteration
            - 2: At least two winafl iteration

        Every last_path_timeout, it checks if a new path was disccovered recently

    """
    out_dir = os.path.join(
        winafl_constants.WINAFL_WORKING_DIR, config_winafl['out_dir'])
    last_path_timeout = config_winafl['last_path_timeout']

    fuzzer_stats = winafl_stats.get_stat(out_dir)
    if fuzzer_stats:
        iteration = 0
        last_update = fuzzer_stats['last_update']
        while True:
            time.sleep(10)

            # If there is a limit in the winafl running time
            if check_running_time(config_winafl):
                kill_all(config)
                return 3


            # If the process has stopeed
            if winafl_proc.poll() is not None:
                logging.debug("process stoped?")
                return 0

            # In case of crash or hangs
            run_process.kill_process("WerFault.exe")

            # Check how long since the last path was found
            # First check if the fuzzer_stas files exist
            fuzzer_stats = winafl_stats.get_stat(out_dir)
            if not fuzzer_stats:
                logging.debug("No fuzzer_stats file found " + out_dir +
                              " after " + str(iteration) + " iterations")
                return 0

            # Send stat to the web app
            # TODO JF add better procedure to check if recon
            if "recon" not in out_dir:
                last_update = winafl_send_stats(config, config_winafl, fuzzer_stats, last_update)


            last_path_sec = winafl_stats.get_last_path_sec(fuzzer_stats)

            logging.info("Last path generated: " + str(last_path_sec) +
                         " secs (" + (str(last_path_sec / 60) + " mins)"))
            if last_path_sec > 60 * last_path_timeout:
                break

            iteration = iteration + 1  # TODO JF sensible to overflow

        if iteration == 0:
            return 1
        else:
            return 2
    else:
        logging.debug(
            "No fuzzer_stats file found in " + out_dir)
        return 0


def move_generated_inputs(config_winafl, file_format):
    """
    Move generated files

    Args:
        config_winafl (dict): the winafl configuration
        file_format (string) the file format
    """
    dst_dir = os.path.join(config_winafl['crash_dir'])
    in_dir = os.path.join(
        winafl_constants.WINAFL_WORKING_DIR, config_winafl['out_dir'])
    file_manipulation.move_generated_inputs(
        os.path.join(in_dir, "crashes"), dst_dir, "-C" + file_format)
    file_manipulation.move_generated_inputs(
        os.path.join(in_dir, "hangs"), dst_dir, "-H" + file_format)

    dst_dir = os.path.join(
        winafl_constants.WINAFL_WORKING_DIR, config_winafl['in_dir'])
    file_manipulation.move_generated_inputs(
        os.path.join(in_dir, "queue"), dst_dir, "-generated-" + file_format)


def move_crashes(config_winafl, file_format):
    """
    Move crashes

    Args:
        config_winafl (dict): the winafl configuration
        file_format (string) the file format
    """
    dst_dir = os.path.join(config_winafl['crash_dir'])
    in_dir = os.path.join(
        winafl_constants.WINAFL_WORKING_DIR, config_winafl['out_dir'])
    file_manipulation.move_generated_inputs(
        os.path.join(in_dir, "crashes"), dst_dir, "-crash" + file_format)


def generate_config_winafl(config):
    """
    Generate winafl configuration

    Args:
        config (dict): The user configuration
    Returns:
        The winafl configuration as a dict
    """
    if 'running_time' not in config:
        timeout = str(config['winafl_default_timeout'])
    else:
        timeout = config['running_time'] * 2000
        timeout = str(timeout)

    timeout = timeout + "+"

    in_dir = get_in_dir(config)
    out_dir = "out_" + config['program_name'][:-4]

    seed_winafl_name = "seed" + config['file_format']

    config_winafl = {'in_dir': in_dir,
                     'out_dir_ori': out_dir,
                     "timeout": timeout,
                     "file": seed_winafl_name,
                     "module": "",
                     "offset": "",
                     "fuzz_iterations": str(config['winafl_fuzzing_iteration']),
                     "working_dir":  winafl_constants.WINAFL_WORKING_DIR,
                     "nargs": "5",
                     "arch": config['arch'],
                     "last_path_timeout": config['winafl_last_path_timeout'],
                     "crash_dir": config['crash_dir']}

    return config_winafl


def compute_targets(config):
    """
    Compute the possible (offset,module) targets

    Args:
        config (dict): The user configuration
    Returns:
        List of (offset,module)
    """
    in_dir = get_in_dir_seed(config)
    seed_offset_name = "seed" + config['file_format']
    seed_offset_path = os.path.join(
        winafl_constants.WINAFL_WORKING_DIR, in_dir, seed_offset_name)

    if config['using_autoit']:
        possible_offsets = compute_offset.run_autoit(config['arch'],
                                                     config[
                                                         'path_autoit_script'],
                                                     config['path_program'],
                                                     config['program_name'],
                                                     seed_offset_path)
    else:
        if not config['auto_close']:
            t_kill = threading.Thread(target=run_process.kill_process_after_timeout,
                                      args=(config['program_name'],
                                            config['running_time'] * 2 + 25,))
            t_kill.start()

        parameters = file_manipulation.generate_parameters(
            config['parameters'], seed_offset_path)
        possible_offsets = compute_offset.run(config['arch'],
                                              config['path_program'],
                                              config['program_name'],
                                              parameters,
                                              seed_offset_name)

    targets = compute_offset.winafl_proposition(possible_offsets)
    logging.info("Winafl number of propositions: " + str(len(targets)))
    logging.info(str(targets))
    return targets


def generate_running_cmd(config):
    """
    Generate the runnign cmd

    Args:
        config (dict): The user configuration
    Returns:
        The running command (string)
    Note:
        The running command does not contains the input file.
        If you are using autoit, it is given to the autoit script
        If not, you need to add it in the running command
    """
    parameters = file_manipulation.generate_parameters(
        config['parameters'], "seed" + config['file_format'])

    running_cmd = ['"' + os.path.join(config['path_program'],
                                      config["program_name"]) + '"'] + parameters
    return running_cmd


def generate_path_file_to_fuzz(config_winafl):
    """
    Generate the path to the file to fuzz

    Args:
        The winafl configuration as a dict
    Returns:
        The path
    """
    path_file_to_fuzz = os.path.join(
        winafl_constants.WINAFL_WORKING_DIR, config_winafl['file'])
    return path_file_to_fuzz


def update_target_on_winafl_config(config_winafl, target):
    """
    Update a winafl with a target

    Args:
        The winafl configuration as a dict
        target (string list): the target (offset,module)
    Returns:
        The winafl configuration updated
    Note:
        one target = (module, offset, module_cov1, module_cov2, ..)
    """

    mod = target['module']
    off = target['offset']
    mod_cov = target['cov_modules']
    logging.info("Target is " + off + " at mod " + mod)
    config_winafl['offset'] = off
    config_winafl['module'] = mod
    config_winafl['cov_modules'] = mod_cov
    config_winafl['out_dir'] = config_winafl[
        'out_dir_ori'] + "_" + mod + "_" + off


def kill_all(config):
    """
    Kill all processes related to winafl

    Args:
        config (dict): The user configuration
    """
    if config['using_autoit']:
        run_process.kill_process("AutoIt3.exe")
    run_process.kill_process(winafl_constants.WINAFL_BIN)
    run_process.kill_process(config['program_name'])
    run_process.kill_process("WerFault.exe")
    # Use autoit to close windows opened during the close of winafl
    autoit.run_and_wait(winafl_constants.WINAFL_AUTOIT_STOP, [])


def run_winafl(config, config_winafl, running_cmd, path_file_to_fuzz):
    """
    Run winafl
    Args:
        config_winafl (dict): user configuration
        config_winafl (dict): winafl configuration
        running_cmd (list string): the running command
        path_file_to_fuzz (string): the path to the file to fuzz
    Returns:
        0 : 0 winafl iteration
        1 : one winafl iteration
        2 : at least two winafl iteration
    Note:
        Returns when winafl is finished (error or no path recently discovered)
        A winafl iteration = WINAFL_LAST_PATH_TIMEOUT
        With autoit, path_autoit_script is given to the autoit script
        Without, is it given added to the running command
    """
    if config['using_autoit']:
        (ret, t_autoit_stop, winafl_proc) = run_winafl_autoit(config_winafl,
                                                              config[
                                                                  'path_autoit_script'],
                                                              config[
                                                                  'program_name'],
                                                              running_cmd,
                                                              path_file_to_fuzz)
    else:
        (ret, winafl_proc) = run_winafl_without_autoit(config_winafl, running_cmd)
    logging.debug("Return value " + str(ret))
    if ret == 1:
        logging.debug("Winafl started")
        ret = process_winafl(config, config_winafl, winafl_proc)
        if config['using_autoit']:
            t_autoit_stop.set()
    return ret


def launch_fuzzing(config):
    """
    Automated winafl launching
    Args:
        config (dict): The user configuration
    Note:
        On a program:
            - compute the set of possible (offset,module)
            - Launches on each (offset,module) winafl
            - Run winafl until no new path has been found recently
    """
    logging.info("Starting automated winafl")

    targets = compute_targets(config)

    config_winafl = generate_config_winafl(config)
    running_cmd = generate_running_cmd(config)
    path_file_to_fuzz = generate_path_file_to_fuzz(config_winafl)

    for target in targets:
        update_target_on_winafl_config(config_winafl, target)
        run_winafl(config, config_winafl, running_cmd, path_file_to_fuzz)
        kill_all(config)
        move_generated_inputs(config_winafl, config['file_format'])

    logging.info('All modules tested')
