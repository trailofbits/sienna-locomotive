""" Module handling the parsing of the configuration files """
import logging
import yaml


def parse_config(config_file):
    """
    Parse the configuration file

    Args:
        config_file (string): Name of the yaml configuration file
    Returns:
        dict: The configuration
    """
    f_desc = open(config_file, 'r')
    config = yaml.load(f_desc)
    f_desc.close()
    return config

def parse_all_configs(config_system_file, config_program_file, config_run_file):
    """
    Parse the configurations files

    Args:
        config_system_file (string): the system configuration file
        config_program_file (string): the program configuration file
        config_run_file (string): the run configuration file
    Returns:
        (dict,dict,ditc): the configurations parsed
    """
    config_system = parse_config(config_system_file)
    config_program = parse_config(config_program_file)
    config_run = parse_config(config_run_file)
    return config_system, config_program, config_run


def check_run_config(run_config):
    """
    Check the run configuration

    Args:
        config (dict): The run configuration
    """
    if 'type' not in run_config:
        logging.error(
            "bad run configuration file: missing type field")
        exit()

    if run_config['type'] not in ['all', 'radamsa', 'winafl',
                                  'winafl_run_targets', 'winafl_get_targets',
                                  'winafl_get_targets_recon_mode']:
        logging.error(
            "bad run configuration file: unknown type of run")
        exit()

    if 'input_dir' not in run_config:
        logging.error(
            "bad run configuration file: missing input_dir field")
        exit()

    if 'crash_dir' not in run_config:
        logging.error(
            "bad run configuration file: missing crash_dir field")
        exit()

    if run_config['type'] in ['all', 'radamsa']:
        if 'radamsa_number_files_to_create' not in run_config:
            logging.info("no radamsa_number_files_to_create field; using default (100)")
            run_config['radamsa_number_files_to_create'] = 100

    if run_config['type'] in ['all', 'winafl', 'winafl_run_targets',
                              'winafl_get_targets', 'winafl_get_targets_recon_mode']:
        if 'winafl_default_timeout' not in run_config:
            logging.info("no winafl_default_timeout field; using default (40000)")
            run_config['winafl_default_timeout'] = 40000
        if 'winafl_last_path_timeout' not in run_config:
            logging.info("no winafl_last_path_timeout field; using default (45)")
            run_config['winafl_last_path_timeout'] = 45
        if 'winafl_fuzzing_iteration' not in run_config:
            logging.info("no winafl_fuzzing_iteration field; using default (100000)")
            run_config['winafl_fuzzing_iteration'] = 100000
    if run_config['type'] in ['winafl_get_targets']:
        if 'targets' not in run_config:
            logging.error(
                "bad run configuration file: missing targets field")
            exit()


def check_program_config(config):
    """
    Check the program configuration

    Args:
        program_config (dict): The program configuration
    """
    ## Check configuration file
    if 'arch' not in config:
        logging.error("Bad configuration file: missing arch field")
        exit()
    if config['arch'] != 'x86' and config['arch'] != 'x64':
        logging.error(
            "Bad configuration file: bad architecture (only x86 and x64 supported)")
        exit()
    # Check for using_autoit field
    if 'using_autoit' not in config:
        logging.error("Bad configuration file: missing using_autoit field")
        exit()

    # If the path to the program and its name are present
    if 'path_program' not in config or 'program_name' not in config:
        logging.error(
            "Bad configuration file: missing program name or path")
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
        system_config (dict): The system configuration
    """

    if 'path_autoit' not in system_config:
        logging.error(
            "Bad system configuration file: missing path_autoit field")
        exit()
    if 'path_windbg' not in system_config:
        logging.error(
            "Bad system configuration file: missing path_windbg field")
        exit()
    if 'path_radamsa' not in system_config:
        logging.error(
            "Bad system configuration file: missing path_radamsa field")
        exit()
    if 'path_dynamorio' not in system_config:
        logging.error(
            "Bad system configuration file: missing path_dynamorio field")
        exit()
    if 'path_winafl' not in system_config:
        logging.error(
            "Bad system configuration file: missing path_winafl field")
        exit()
    if "path_vmfuzz" not in system_config:
        logging.error(
            "Bad system configuration file: missing path_vmfuzz field")
        exit()

    if "fuzzers" not in system_config:
        logging.error("Bad system configuration file: missing fuzzers field")
        exit()

    if 'path_autoit_working_dir' not in system_config:
        logging.error(
            "Bad system configuration file: missing path_autoit_working_dir field")
        exit()

    if 'path_winafl_working_dir' not in system_config:
        logging.error(
            "bad system configuration file: missing path_winafl_working_dir field")
        exit()

    if 'path_radamsa_working_dir' not in system_config:
        logging.error(
            "bad system configuration file: missing path_radamsa_working_dir field")
        exit()
