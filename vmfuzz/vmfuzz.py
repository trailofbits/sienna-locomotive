""" Main module, it loops between the fuzzer and the autoit script """
import argparse
import logging

import fuzzers.radamsa.radamsa as radamsa
import fuzzers.winafl.winafl as winafl
import autoit
import utils.parsing_config as parsing_config
import utils.autoit_lib as autoit_lib
import exploitability.exploitable as exploitable


def init_system(config_system):
    """
    Initialize VMfuzz
    Args:
        The system configurations as a dict
    """
    autoit.AUTOIT_BIN = config_system['path_autoit_bin']
    autoit_lib.AUTOIT_LIB_DIRECTORY = config_system['path_autoit_lib']
    autoit_lib.AUTOIT_WORKING_DIRECTORY = config_system['path_autoit_working_dir']
    exploitable.WINGDB_PATH = config_system['path_wingdb_dir']
    exploitable.AUTOIT_BIN = config_system['path_autoit_bin']

    fuzzers = config_system['fuzzers']
    if 'radamsa' in fuzzers:
        radamsa.init(config_system)
    if 'winafl' in fuzzers:
        winafl.init(config_system)


def main(config_file, config_system_file, log_level):
    """
    Main function
    Args:
        config_file: the user configuration file
        config_sytem_file: the system configuration file
        log_level (int): Logging level: 0 debug 1 info, 2 warning, 3 error
    """
    config = parsing_config.parse_config(config_file)

    parsing_config.check_user_config(config)

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

    config_system = parsing_config.parse_config(config_system_file)
    parsing_config.check_system_config(config_system)
    init_system(config_system)
    if config['using_autoit']:
        autoit_lib.init_autoit(config)

    if "winafl" in config_system['fuzzers']:
        winafl.launch_fuzzing(config)

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

    main(args_vmfuzz['config'], args_vmfuzz['config_system'], args_vmfuzz['log_level', ])
