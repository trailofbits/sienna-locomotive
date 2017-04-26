""" Main module, it loops between the fuzzer and the autoit script """
import argparse
import os
import threading
import time

import fuzzers.radamsa.radamsa as radamsa
import fuzzers.winafl.winafl as winafl
import fuzzers.winafl.recon as winafl_recon
import autoit.autoit as autoit
import autoit.autoit_lib as autoit_lib
import utils.parsing_config as parsing_config
import utils.database as database
import utils.file_manipulation as file_manipulation
import utils.logs as logging
import exploitability.exploitable as exploitable


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


def init_crash_dir(config):
    """
    Init the crash directory if it does not exist

    Args:
        config (dict): the user configuration
    """

    if config['run_type'] in ['all', 'radamsa', 'winafl',
                              'winafl_run_targets',
                              'winafl_get_targets',
                              'winafl_get_targets_recon_mode']:
        file_manipulation.create_dir(config['crash_dir'])


def init(config_system, config_program, config_run, log_level):
    """
    Initialize Vmfuzz

    Args:
        config_system (dict): system configuration
        config_program (dict): program configuration
        config_run (dict): run configuration
        log_level (int): Logging level: 0 debug 1 info, 2 warning, 3 error
    Returns:
        (dict,dict): the user and system configuration dict
    Note:
        The user configuration is the program and run configuration merged\
        into the so-called user configuration
    """

    # Use of a special config for the init, as it used before all the checks
    config_init = dict(config_program.items() + config_run.items())
    config_init['_program_id'] = config_program['_id']
    config_init['_run_id'] = config_run['_id']
    logging.init_log(config_init, log_level)

    parsing_config.check_system_config(config_system)
    parsing_config.check_program_config(config_program)
    parsing_config.check_run_config(config_run)

    path_input_crashes = config_system['path_input_crashes']
    config_run['input_dir'] = os.path.join(path_input_crashes,
                                           config_run['input_dir'])
    config_run['crash_dir'] = os.path.join(path_input_crashes,
                                           config_run['crash_dir'])

    # Merge config_run and config_program
    config = dict(config_program.items() + config_run.items())
    config['_program_id'] = config_program['_id']
    config['_run_id'] = config_run['_id']

    init_system(config_system)

    if config_program['using_autoit']:
        autoit_lib.init_autoit(config_program)

    if config_run['run_type'] in ['all', 'radamsa', 'winafl',
                                  'winafl_run_targets',
                                  'winafl_get_targets',
                                  'winafl_get_targets_recon_mode']:
        if "winafl" in config_system['fuzzers']:
            winafl.init_directories(config)
        if "radamsa" in config_system['fuzzers']:
            radamsa.init_directories(config)

    init_crash_dir(config)

    return (config, config_system)


def launch_fuzz(config, config_system, t_fuzz_stopped):
    """
    Launch the fuzzing

    Args:
        config (dict): the user configuration
        config_system (dict): the system configuration
        t_fuzz_stopped (threading.Event): Event use to stop the fuzzing
    """
    if config['run_type'] == 'all':
        if "winafl" in  config_system['fuzzers']:
            has_target = 'targets' in config
            if has_target:
                has_target = config['targets'] != []
            if not has_target:
                print "Not target, launch recon"
                targets = winafl_recon.launch_recon(config, t_fuzz_stopped)
                database.send_targets(config, targets)
                winafl_recon.save_targets(
                    targets, config['program_name'] + "-targets.yaml")
            else:
                targets = config['targets']
            if t_fuzz_stopped.is_set():
                return
            print "Launch winafl on "+str(len(targets))+" targets"
            winafl_recon.winafl_on_targets(config, targets, t_fuzz_stopped)
            if t_fuzz_stopped.is_set():
                return
            print 'Winaf end'
            logging.info("Winafl done, start radamsa")
        if "radamsa" in  config_system['fuzzers']:
            print 'Radamsa start'
            radamsa.launch_fuzzing(config, t_fuzz_stopped)
            print 'Radamsa end'

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
        winafl_recon.winafl_on_targets(config,
                                       config['targets'],
                                       t_fuzz_stopped)

    elif config['run_type'] == 'winafl_get_targets':
        logging.error('Not yet implemented')
    elif config['run_type'] == 'winafl_get_targets_recon_mode':
        targets = winafl_recon.launch_recon(config, t_fuzz_stopped)
        database.send_targets(config, targets)
        winafl_recon.save_targets(targets,
                                  config['program_name'] + "-targets.yaml")

    elif config['run_type'] == 'exploitable':
        print "Start exploitable"
        exploitable.launch_exploitable(config)
        print "Stop exploitable"

    t_fuzz_stopped.set()

    return


def launch_fuzz_wrapper(config, config_system, t_fuzz_stopped):
    """
    Wrapper of launch_fuzz

    Args:
        config (dict): the user configuration
        config_system (dict): the system configuration
        t_fuzz_stopped (threading.Event): Event use to stop the fuzzing
    Note:
        Catch all exceptions of launch_fuzz and report them to the webapp
    """
    try:
        launch_fuzz(config, config_system, t_fuzz_stopped)
    except Exception as e:
        logging.error('PLEASE REPORT BUG: '+str(e))


def fuzz(config_system, config_program, config_run, log_level=0):
    """
    Run winafl from the web app

    Args:
        config_system (dict): system configuration
        program_system (dict): program configuration
        config_run (dict): run configuration
        log_level (int): (optional)
    Note:
        Logging level:\
        0 debug (default), 1 info, 2 warning, 3 error
    """
    print "Start vmfuzz"
    config, config_system = init(
        config_system, config_program, config_run, log_level)

    t_fuzz_stopped = threading.Event()

    t_fuzz = threading.Thread(target=launch_fuzz_wrapper, args=(
        config, config_system, t_fuzz_stopped,))
    t_fuzz.daemon = True
    t_fuzz.start()

    print("Start run " +
          str(config['_run_id']) +
          "/" + str(config['_worker_id']))

    # TODO JF: to be changed to a more cleaner way to deal with !exploitable
    if config['run_type'] != 'exploitable':
        database.send_status(config, 'RUNNING')
    else:
        database.send_exploitable_status(config, 'RUNNING')

    starting_time = time.time()
    while not t_fuzz_stopped.is_set():
        time.sleep(10)
        status = database.ask_status(config)
        if status not in ['STARTING', 'STARTED', 'RUNNING']:
            print "End of fuzzing"
            print "Status received: "+str(status)
            t_fuzz_stopped.set()
        if 'fuzz_time' in config:
            if time.time() - starting_time > config['fuzz_time'] * 60:
                print 'Fuzzing time reached'
                t_fuzz_stopped.set()
            else:
                print str(config['fuzz_time'])
                print str(time.time() - starting_time)

    winafl.kill_all(config)
    # TODO JF: to be changed to a more cleaner way to deal with !exploitable
    if config['run_type'] != 'exploitable':
        database.send_status(config, 'FINISHED')
    else:
        database.send_exploitable_status(config, 'FINISHED')
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
        Launch winafl and radamsa.\n
        Use the recon mode for winafl
    """

    configs = parsing_config.parse_all_configs(
        config_system_file,
        config_program_file,
        config_run_file)
    config_system, config_program, config_run = configs

    fuzz(config_system, config_program, config_run, log_level)


if __name__ == "__main__":
    parser_cmd = argparse.ArgumentParser(
        description='Trail of bits fuzzing system.')
    parser_cmd.add_argument('-cp', '--config_program',
                            help='Yaml configuration file',
                            required=False,
                            default="program.yaml")
    parser_cmd.add_argument('-cs', '--config_system',
                            help='Yaml configuration file',
                            required=False,
                            default="system.yaml")
    parser_cmd.add_argument('-cr', '--config_run',
                            help='Yaml configuration file',
                            required=False,
                            default="run.yaml")
    parser_cmd.add_argument('-l', '--log_level', type=int,
                            help='Logging level:\
                                 0 debug 1 info, 2 warning, 3 error',
                            required=False, default=0)
    args_vmfuzz = vars(parser_cmd.parse_args())

    main(args_vmfuzz['config_system'],
         args_vmfuzz['config_program'],
         args_vmfuzz['config_run'],
         args_vmfuzz['log_level', ])
