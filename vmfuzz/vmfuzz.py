""" Main module, it loops between the fuzzer and the autoit script """
import argparse
import os
import logging

import fuzzers.radamsa.radamsa as radamsa
import fuzzers.winafl.winafl as winafl
import fuzzers.winafl.recon as winafl_recon
import autoit
import utils.parsing_config as parsing_config
import utils.autoit_lib as autoit_lib
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
    autoit.AUTOIT_BIN = config_system['path_autoit_bin']
    autoit_lib.AUTOIT_LIB_DIRECTORY = os.path.join(
        config_system['path_vmfuzz'], "autoit_lib")
    autoit_lib.AUTOIT_WORKING_DIRECTORY = config_system[
        'path_autoit_working_dir']
    exploitable.WINGDB_PATH = config_system['path_windbg_dir']
    exploitable.AUTOIT_BIN = config_system['path_autoit_bin']

    fuzzers = config_system['fuzzers']
    if 'radamsa' in fuzzers:
        radamsa.init(config_system)
    if 'winafl' in fuzzers:
        winafl.init(config_system)



def init(config_file, config_system_file, log_level):
    """
    Initialize Vmfuzz

    Args:
        config_file (string): the user configuration file
        config_system_file (string): the user configuration file
        log_level (int): Logging level: 0 debug 1 info, 2 warning, 3 error
    Returns:
        (dict,dict): the user and system configuration dict
    """

    init_log(log_level)

    config = parsing_config.parse_config(config_file)
    parsing_config.check_user_config(config)
    config_system = parsing_config.parse_config(config_system_file)
    parsing_config.check_system_config(config_system)
    init_system(config_system)

    if config['using_autoit']:
        autoit_lib.init_autoit(config)

    if "winafl" in config_system['fuzzers']:
        winafl.init_directories(config)
    if "radamsa" in config_system['fuzzers']:
        radamsa.init_directories(config)

    return (config, config_system)


def winafl_launch_recon(config_file, config_system_file, log_level, target_file):
    """
    Recon mode
    The recon mode compute the offsets, try each one \n
    for 5 mins and export the one working with winafl

    Args:
        config_file: the user configuration file
        config_sytem_file: the system configuration file
        log_level (int): Logging level: 0 debug 1 info, 2 warning, 3 error
        target_file: output file
    Note:
        targets are stored in plain text as :
        0x0,module1
        0x1,module2
    """

    config, config_system = init(config_file, config_system_file, log_level)
    interesting_targets = winafl_recon.launch_recon(config)
    winafl_recon.save_targets(interesting_targets, target_file)


def fuzz_winafl_one_target(config_file, config_system_file, log_level, offset, module):
    """
    Launch winafl on one target

    Args:
        config_file: the user configuration file
        config_sytem_file: the system configuration file
        log_level (int): Logging level: 0 debug 1 info, 2 warning, 3 error
        offset (int): offset targeted
        module (string): module targeted
    """
    config, config_system = init(config_file, config_system_file, log_level)

    if "winafl" in config_system['fuzzers']:
        config_winafl = winafl.generate_config_winafl(config)
        running_cmd = winafl.generate_running_cmd(config)
        path_file_to_fuzz = winafl.generate_path_file_to_fuzz(config_winafl)
        target = (offset, module)
        winafl.update_target_on_winafl_config(config_winafl, target)
        winafl.run_winafl(config, config_winafl,
                          running_cmd, path_file_to_fuzz)
        winafl.kill_all(config)


def fuzz_winafl_targets(config_file, config_system_file, log_level, target_file):
    """
    Launch winafl on a set of targets

    Args:
        config_file: the user configuration file
        config_sytem_file: the system configuration file
        log_level (int): Logging level: 0 debug 1 info, 2 warning, 3 error
        target_file: output file
    Note:
        targets are read in plain text as :
        0x0,module1
        0x1,module2
    """
    config, config_system = init(config_file, config_system_file, log_level)

    if "winafl" in config_system['fuzzers']:
        targets = winafl_recon.get_targets(target_file)
        winafl_recon.winafl_on_targets(config, targets)

def fuzz_winafl(config_file, config_system_file, log_level):
    """
    Launch winafl

    Args:
        config_file: the user configuration file
        config_sytem_file: the system configuration file
        log_level (int): Logging level: 0 debug 1 info, 2 warning, 3 error
    Note:
        Offsets are computed automatically
    """
    config, config_system = init(config_file, config_system_file, log_level)

    if "winafl" in config_system['fuzzers']:
        winafl.launch_fuzzing(config)


def fuzz_radamsa(config_file, config_system_file, log_level):
    """
    Launch radamsa

    Args:
        config_file: the user configuration file
        config_sytem_file: the system configuration file
        log_level (int): Logging level: 0 debug 1 info, 2 warning, 3 error
    """
    config, config_system = init(config_file, config_system_file, log_level)

    if "radamsa" in config_system['fuzzers']:
        radamsa.launch_fuzzing(config)


def main(config_file, config_system_file, log_level):
    """
    Main function

    Args:
        config_file: the user configuration file
        config_sytem_file: the system configuration file
        log_level (int): Logging level: 0 debug 1 info, 2 warning, 3 error
    Note:
        Launch winafl and radamsa
        Use the recon mode for winafl
    """

    config, config_system = init(config_file, config_system_file, log_level)

    if "winafl" in config_system['fuzzers']:
        targets = winafl_recon.launch_recon(config)
        winafl_recon.save_targets(targets, config['program_name']+".targets")
        winafl_recon.winafl_on_targets(config, targets)

    if "radamsa" in config_system['fuzzers']:
        radamsa.launch_fuzzing(config)

if __name__ == "__main__":
    parser_cmd = argparse.ArgumentParser(
        description='Trail of bits fuzzing system.')
    parser_cmd.add_argument('-c', '--config', help='Yaml configuration file',
                            required=False, default="config.yaml")
    parser_cmd.add_argument('-cs', '--config_system', help='Yaml configuration file',
                            required=False, default="system.yaml")
    parser_cmd.add_argument('-l', '--log_level', type=int,
                            help='Logging level: 0 debug 1 info, 2 warning, 3 error',
                            required=False, default=0)
    args_vmfuzz = vars(parser_cmd.parse_args())

    main(args_vmfuzz['config'], args_vmfuzz[
        'config_system'], args_vmfuzz['log_level', ])
