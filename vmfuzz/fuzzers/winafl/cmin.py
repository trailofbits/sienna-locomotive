""" Module handling the corpus minimization """

import logging
import os
import sys
import shutil
import threading
import fuzzers.winafl.winafl_constants as winafl_constants
import fuzzers.winafl.winafl as winafl
import autoit.autoit as autoit
import autoit.autoit_lib as autoit_lib

def generate_cmin_cmd(config_winafl, running_cmd):
    """
    Generate cmin command line

    Args:
        config (dict): The user configuration
        running_cmd (list string): the running command
    Returns:
        list string: drrun.exe cmd
    """

    if config_winafl['arch'] == "x86":
        path_dynamorio = winafl_constants.DYNAMORIO_PATH32
    elif config_winafl['arch'] == "x64":
        path_dynamorio = winafl_constants.DYNAMORIO_PATH64
    else:
        logging.error("Unkwon archictecture " + config_winafl['arch'])

    coverage_module = []
    for cov_mod in config_winafl['modules_cov']:
        coverage_module.append('-coverage_module')
        coverage_module.append(cov_mod)

    if not coverage_module:
        logging.error("No modules to be covered? (" +
                      str(config_winafl['modules_cov']) + ")")

    cmin_cmd = [
        sys.executable,
        winafl_constants.WINAFL_PATH_CMIN,
        '-i',
        config_winafl['in_dir'],
        '-o',
        config_winafl['out_dir'],
        '-D',
        path_dynamorio, '-v']
    cmin_cmd = cmin_cmd + coverage_module
    cmin_cmd = cmin_cmd + ['-target_module',
                           config_winafl['module'],
                           '-target_offset',
                           config_winafl['offset'],
                           '-nargs',
                           config_winafl['nargs'],
                           '--'
                          ]
    running_cmd = ["@@" if config_winafl['file']
                   in x else x for x in running_cmd]
    return cmin_cmd + running_cmd


def run_cmin_without_autoit(config_winafl, running_cmd):
    """
    Run cmin

    Args:
        config_winafl (dict): the winafl configuration
        running_cmd (list sdtring)
    """
    cmd = generate_cmin_cmd(config_winafl, running_cmd)

    # Os.Popen would be better, but it doesnt work property with cmin
    # TODO JF: find how to change this
    prev_dir = os.getcwd()
    os.chdir(config_winafl['working_dir'])
    os.system(winafl.pp_cmd(cmd))
    os.chdir(prev_dir)
#    proc = subprocess.Popen(cmd, shell=True,
#                            cwd=config_winafl['working_dir'])
#    proc.wait()


def run_cmin_autoit(config_winafl, path_autoit_script, program_name, running_cmd, fuzz_file):
    """
    Run cmin

    Args:
        config_winafl (dict): winafl configuration
        path_autoit_script (string) : path to the autoit script
        program_name (string): the program name
        running_cmd (list string): the runnign command
        fuzz_file (string): path to the file to fuzz
    """

    logging.error('Not yet implemented')

    cmd = generate_cmin_cmd(config_winafl, running_cmd)

    # Os.Popen would be better, but it doesnt work property with cmin
    # TODO JF: find how to change this
    prev_dir = os.getcwd()
    os.chdir(config_winafl['working_dir'])
    os.system(winafl.pp_cmd(cmd))
    os.chdir(prev_dir)

    path_autoit_script = autoit_lib.get_autoit_path(
        path_autoit_script, "winafl")

    t_autoit_stop = threading.Event()
    t_autoit = threading.Thread(target=winafl.launch_autoit, args=(
        path_autoit_script, fuzz_file, t_autoit_stop,))
    t_autoit.start()


def generate_config_cmin(config):
    """
    Generate cmin configuration

    Args:
        config (dict): The user configuration
    Returns:
        The cmin configuration as a dict
    """

    in_dir = winafl.get_in_dir(config)

    seed_winafl_name = "seed" + config['file_format']

    config_cmin = {"in_dir": in_dir,
                   "out_dir_ori": in_dir + "_cmin",
                   "file": seed_winafl_name,
                   "module": "",
                   "offset": "",
                   "working_dir":  winafl_constants.WINAFL_WORKING_DIR,
                   "nargs": "5",
                   "arch": config['arch'],
                  }

    return config_cmin


def update_target_on_cmin_config(config_cmin, target):
    """
    Update a winafl with a target

    Args:
        The cmin configuration as a dict
        target (string list): the target (offset,module)
    Returns:
        The cmin configuration updated
    """

    mod = target['module']
    off = target['offset']
    mod_cov = target['cov_modules']
    logging.info("Target is " + off + " at mod " + mod)
    config_cmin['offset'] = off
    config_cmin['module'] = mod
    config_cmin['modules_cov'] = mod_cov
    config_cmin['out_dir'] = config_cmin[
        'out_dir_ori'] + "_" + mod + "_" + off


def cmin_on_targets(config, targets):
    """ test
    """
    if 'timestamp' in config:
        winafl_constants.WINAFL_WORKING_DIR = os.path.join(
            winafl_constants.WINAFL_WORKING_DIR, config['timestamp'])

    config_cmin = generate_config_cmin(config)
    running_cmd = winafl.generate_running_cmd(config)

    out_dir_ori = os.path.join(
        winafl_constants.WINAFL_WORKING_DIR, config_cmin['out_dir_ori'])
    if not os.path.exists(out_dir_ori):
        os.makedirs(out_dir_ori)

    for target in targets:
        logging.info("Cmin on " + str(target))
        update_target_on_cmin_config(config_cmin, target)
        run_cmin_without_autoit(config_cmin, running_cmd)

        out_dir = os.path.join(
            winafl_constants.WINAFL_WORKING_DIR, config_cmin['out_dir'])
        files = os.listdir(out_dir)
        for f in files:
            shutil.move(os.path.join(out_dir, f),
                        os.path.join(out_dir_ori, f))

        winafl.kill_all(config)

    logging.info("End of corpus minization")
