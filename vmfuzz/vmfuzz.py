""" Main module, it loops between the fuzzer and the autoit script """
import argparse
import os
#import multiprocessing
import threading
import time
import logging

import fuzzers.radamsa.radamsa as radamsa
import fuzzers.winafl.winafl as winafl
import fuzzers.winafl.recon as winafl_recon
import fuzzers.winafl.cmin as winafl_cmin
import autoit.autoit as autoit
import autoit.autoit_lib as autoit_lib
import utils.parsing_config as parsing_config
import utils.database as database
import exploitability.exploitable as exploitable


def init_log(log_level):
    """
    Initialize the logging

    Args:
        log_level(int): the logging level
    Note:
        0 = Debug \n
        1 = Info \n
        2 = Warning \n
        3 = Error
    """


    if log_level == 0:
        logging.basicConfig(filename="vmfuzz.log",
                            filemode='w', level=logging.DEBUG)
    elif log_level == 1:
        logging.basicConfig(filename="vmfuzz.log",
                            filemode='w', level=logging.INFO)
    elif log_level == 2:
        logging.basicConfig(filename="vmfuzz.log",
                            filemode='w', level=logging.WARNING)
    elif log_level == 3:
        logging.basicConfig(filename="vmfuzz.log",
                            filemode='w', level=logging.ERROR)


def init_system(config_system):
    """
    Initialize the system constants

    Args:
        config_system (dict): the system configuration
    """
    autoit.init(config_system)
    exploitable.init(config_system)
    database.init(config_system)

    autoit_lib.AUTOIT_LIB_DIRECTORY = os.path.join(
        config_system['path_vmfuzz'], "autoit_lib")
    autoit_lib.AUTOIT_WORKING_DIRECTORY = config_system[
        'path_autoit_working_dir']

    fuzzers = config_system['fuzzers']
    if 'radamsa' in fuzzers:
        radamsa.init(config_system)
    if 'winafl' in fuzzers:
        winafl.init(config_system)


def user_check(config):
    """
    Check user information

    Note:
        TODO JF: To be improved
    """

    if config['run_type'] in ['all', 'radamsa', 'winafl', 'winafl_run_targets',
                              'winafl_get_targets', 'winafl_get_targets_recon_mode']:
        if not os.path.exists(config['crash_dir']):
            logging.info('Crash_dir created')
            os.makedirs(config['crash_dir'])


def init(config_system, config_program, config_run, log_level):
    """
    Initialize Vmfuzz

        log_level (int): Logging level: 0 debug 1 info, 2 warning, 3 error
    Returns:
        (dict,dict): the user and system configuration dict
    Notes:
        The user configuration is the program and run configuration merged
    """

    init_log(log_level)

    parsing_config.check_system_config(config_system)
    parsing_config.check_program_config(config_program)
    parsing_config.check_run_config(config_run)

    config = dict(config_program.items() + config_run.items())
    config['_program_id'] = config_program['_id']
    config['_run_id'] = config_run['_id']

    init_system(config_system)

    if config_program['using_autoit']:
        autoit_lib.init_autoit(config_program)

    path_input_crashes = config_system['path_input_crashes']
    config_run['input_dir'] = os.path.join(path_input_crashes, config_run['input_dir'])
    config_run['crash_dir'] = os.path.join(path_input_crashes, config_run['crash_dir'])

    if config_run['run_type'] in ['all', 'radamsa', 'winafl', 'winafl_run_targets',
                                  'winafl_get_targets', 'winafl_get_targets_recon_mode']:
        if "winafl" in config_system['fuzzers']:
            winafl.init_directories(config)
        if "radamsa" in config_system['fuzzers']:
            radamsa.init_directories(config)

    user_check(config)

    return (config, config_system)


def launch_fuzz(config, t_fuzz_stopped):
    """
    Launch the fuzzing
    Args:
        config (dict): user configuration
        t_fuzz_stopped (threading.Event): Event use to stop the fuzzing
    """
    if config['run_type'] == 'all':
        has_target = 'targets' in config
        if has_target:
            has_target = config['targets'] != []
        if not has_target:
            targets = winafl_recon.launch_recon(config, t_fuzz_stopped)
            database.send_targets(config, targets)
            winafl_recon.save_targets(
                targets, config['program_name'] + "-targets.yaml")
        else:
            targets = config['targets']
        if t_fuzz_stopped.is_set():
            return
        winafl_recon.winafl_on_targets(config, targets, t_fuzz_stopped)
        logging.info("Winafl done, start radamsa")
        if t_fuzz_stopped.is_set():
            return
        print 'End'
#        radamsa.launch_fuzzing(config, t_fuzz_stopped)

    elif config['run_type'] == 'radamsa':
        radamsa.launch_fuzzing(config, t_fuzz_stopped)

    elif config['run_type'] == 'winafl':
        targets = winafl_recon.launch_recon(config, t_fuzz_stopped)
        database.send_targets(config, targets)
        winafl_recon.save_targets(
            targets, config['program_name'] + "-targets.yaml")
        if t_fuzz_stopped.is_set():
            return
        winafl_recon.winafl_on_targets(config, targets, t_fuzz_stopped)

    elif config['run_type'] == 'winafl_run_targets':
        winafl_recon.winafl_on_targets(config, config['targets'], t_fuzz_stopped)

    elif config['run_type'] == 'winafl_cmin_targets':
        winafl_cmin.cmin_on_targets(config, config['targets'])

    elif config['run_type'] == 'winafl_get_targets':
        logging.error('Not yet implemented')
    elif config['run_type'] == 'winafl_get_targets_recon_mode':
        targets = winafl_recon.launch_recon(config, t_fuzz_stopped)
        database.send_targets(config, targets)
        winafl_recon.save_targets(targets, config['program_name']+"-targets.yaml")

    elif config['run_type'] == 'exploitable':
        print "Start exploitable"
        exploitable.launch_exploitable(config)
        print "Stop exploitable"
        
    t_fuzz_stopped.set()

    return


def fuzz(config_system, config_program, config_run, log_level=0):
    """
    Run winafl from the web app
    Args:
        config_system (dict): system configuration
        program_system (dict): program configuration
        config_run (dict): run configuration
        log_level (int): (optional) Logging level: 0 debug (default), 1 info, 2 warning, 3 error
    """

    config, config_system = init(
        config_system, config_program, config_run, log_level)

    t_fuzz_stopped = threading.Event()

    t_fuzz = threading.Thread(target=launch_fuzz, args=(
        config, t_fuzz_stopped,))
    t_fuzz.daemon = True
    t_fuzz.start()

    database.send_status(config, 'STARTED')
    
    starting_time = time.time()
    while not t_fuzz_stopped.is_set():
        time.sleep(10)
        if database.ask_status(config) not in ['STARTING', 'STARTED', 'RUNNING']:
            print "End of fuzzing"
            t_fuzz_stopped.set()
        if 'fuzz_time' in config:
            if time.time() - starting_time > config['fuzz_time'] * 60:
                print 'Fuzzing time reached'
                t_fuzz_stopped.set()
            else:
                print str(config['fuzz_time'])
                print str(time.time() - starting_time)

    winafl.kill_all(config)
    return


def main(config_system_file, config_program_file, config_run_file, log_level):
    """
    Main function

    Args:
        config_sytem_file (string): the system configuration file
        config_program_file (string): the config configuration file
        config_run_file (string): the run configuration file
        log_level (int): Logging level: 0 debug 1 info, 2 warning, 3 error
    Note:
        Launch winafl and radamsa
        Use the recon mode for winafl
    """

    config_system, config_program, config_run = parsing_config.parse_all_configs(
        config_system_file, config_program_file, config_run_file)

    fuzz(config_system, config_program, config_run, log_level)

if __name__ == "__main__":
    parser_cmd = argparse.ArgumentParser(
        description='Trail of bits fuzzing system.')
    parser_cmd.add_argument('-cp', '--config_program', help='Yaml configuration file',
                            required=False, default="program.yaml")
    parser_cmd.add_argument('-cs', '--config_system', help='Yaml configuration file',
                            required=False, default="system.yaml")
    parser_cmd.add_argument('-cr', '--config_run', help='Yaml configuration file',
                            required=False, default="run.yaml")
    parser_cmd.add_argument('-l', '--log_level', type=int,
                            help='Logging level: 0 debug 1 info, 2 warning, 3 error',
                            required=False, default=0)
    args_vmfuzz = vars(parser_cmd.parse_args())

    main(args_vmfuzz['config_system'], args_vmfuzz[
        'config_program'], args_vmfuzz['config_run'], args_vmfuzz['log_level', ])
