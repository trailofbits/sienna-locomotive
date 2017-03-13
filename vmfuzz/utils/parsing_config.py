""" Module handling the parsing of the configuration files """
import logging
import yaml


def parse_config(config_file):
    """
    Parse the configuration file
    Args:
        config_file (string): Name of the yaml configuration file
    Returns!
        The configuration as a dict
    """
    f_desc = open(config_file, 'r')
    config = yaml.load(f_desc)
    f_desc.close()
    return config


def check_user_config(config):
    """
    Check the user configuration
    Args:
        The configuration as a dict
    """
    ## Check configuration file
    # Check for using_autoit field
    if 'using_autoit' not in config:
        logging.error("Bad configuration file: missing using_autoit field")
        exit()

    # If the path to the program and its name are present
    if 'path_program' not in config or 'program_name' not in config:
        logging.error(
            "Bad configuration file: missing program name or path")
        exit()

    # Check for seed_pattern field
    if 'seed_pattern' not in config:
        logging.error("Bad configuration file: missing seed_pattern")
        exit()

    # Check for file_format field
    if 'file_format' not in config:
        logging.error("Bad configuration file: missing format_file")
        exit()

    # If program does not have parameters
    if 'parameters' not in config:
        config['parameters'] = []

    # If autoit is used
    if config['using_autoit']:
        if 'path_autoit_script' not in config:
            logging.error(
                "Bad configuration file: missing path_autoit_script field")
            exit()
    # If autoit not used
    else:
        if 'auto_close' not in config:
            logging.error("Bad configuration file: missing auto_close field")
            exit()
        # The running_time 
        if 'running_time' not in config:
            logging.error(
                "Bad configuration file: missing running_time field")
            exit()



def check_system_config(system_config):
    """
    Check the system configuration
    Args:
        The configuration as a dict
    """
    if "fuzzers" not in system_config:
        logging.error("Bad system configuration file: missing fuzzers field")
        exit()
    if 'path_autoit_bin' not in system_config:
        logging.error(
            "Bad system configuration file: missing path_autoit_bin field")
        exit()
    if 'path_windbg_dir' not in system_config:
        logging.error(
            "Bad system configuration file: missing path_windbg_dir field")
        exit()
    if 'path_autoit_lib' not in system_config:
        logging.error(
            "Bad system configuration file: missing path_autoit_lib field")
        exit()
    if 'path_autoit_working_dir' not in system_config:
        logging.error(
            "Bad system configuration file: missing path_autoit_working_dir field")
        exit()



    fuzzers = system_config['fuzzers']

    if 'radamsa' in fuzzers:
        if 'path_radamsa_bin' not in system_config:
            logging.error(
                "Bad system configuration file: missing path_radamsa_bin field")
            exit()
        if 'radamsa_number_files_to_create' not in system_config:
            logging.error(
                "Bad system configuration file: missing radamsa_number_files_to_create field")
            exit()
        if 'path_radamsa_working_dir' not in system_config:
            logging.error(
                "Bad system configuration file: missing path_radamsa_working_dir field")
            exit()

    if "winafl" in fuzzers:
        if 'path_winafl' not in system_config:
            logging.error(
                "Bad system configuration file: missing path_winafl field")
            exit()
        if 'winafl_bin' not in system_config:
            logging.error(
                "Bad system configuration file: missing winafl_bin field")
            exit()
        if 'path_dynamorio' not in system_config:
            logging.error(
                "Bad system configuration file: missing path_dynamorio field")
            exit()
        if 'path_drrun_bin' not in system_config:
            logging.error(
                "Bad system configuration file: missing path_drrun_bin field")
            exit()
        if 'path_winafl_dll' not in system_config:
            logging.error(
                "Bad system configuration file: missing path_winafl_dll field")
            exit()
        if 'path_winafl_working_dir' not in system_config:
            logging.error(
                "Bad system configuration file: missing path_winafl_working_dir field")
            exit()
        if 'winafl_default_timeout' not in system_config:
            logging.error(
                "Bad system configuration file: missing winafl_default_timeout field")
            exit()
        if 'winafl_last_path_timeout' not in system_config:
            logging.error(
                "Bad system configuration file: missing winafl_last_path_timeout field")
            exit()
        if 'winafl_fuzzing_iteration' not in system_config:
            logging.error(
                "Bad system configuration file: missing winafl_fuzzing_iteration field")
            exit()
        if 'path_autoit_stop_winafl' not in system_config:
            logging.error(
                "Bad system configuration file: missing path_autoit_stop_winafl field")
            exit()
        if 'path_windbg_script' not in system_config:
            logging.error(
                "Bad system configuration file: missing path_windbg_script field")
            exit()
