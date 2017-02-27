""" Main module, it loops between the fuzzer and the autoit script """
import os
import hashlib
import argparse
import logging
import yaml

import fuzzers.radamsa.radamsa as radamsa
import autoit
import utils.run_process as run_process
import exploitability.exploitable_standalone as exploitable_standalone


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


def check_config(config):
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

    # If autoit used
    if config['using_autoit']:
        if 'path_autoit_script' not in config:
            logging.error(
                "Bad configuration file: missing path_autoit_script field")
            exit()
    # If autoit not used
    else:
        if 'path_program' not in config or 'program_name' not in config:
            logging.error(
                "Bad configuration file: missing program name or path")
            exit()
        if 'auto_close' not in config:
            logging.error("Bad configuration file: missing auto_close field")
            exit()
        # If program does not close itself
        if not config['auto_close']:
            if 'running_time' not in config:
                logging.error(
                    "Bad configuration file: missing running_time field")
                exit()
        # If program close itelf no need to running time
        else:
            config['running_time'] = 0
        # If program does not have parameters
        if 'parameters' not in config:
            config['parameters'] = []
    # Check for seed_pattern field
    if 'seed_pattern' not in config:
        logging.error("Bad configuration file: missing seed_pattern")
        exit()

    # Check for file_format field
    if 'file_format' not in config:
        logging.error("Bad configuration file: missing format_file")
        exit()


def init(config, config_system):
    """
    Initialize VMfuzz
    Args:
        The user and system configurations as two dict
    """
    radamsa.RADAMSA_BIN = config_system['path_radamsa_bin']
    exploitable_standalone.WINGDB_PATH = config_system['path_wingdb_dir']
    if config['using_autoit']:
        autoit.AUTOIT_BIN = config_system['path_autoit_bin']


def compute_md5(file_name, block_size=2**20):
    """
    Compute the md5 of a file
    Args:
        file_name (string): Name of the fil
        block_size (int): Size of the block (to compute md5 on large file)
    """
    f_desc = open(file_name, "rb")
    md5 = hashlib.md5()
    while True:
        data = f_desc.read(block_size)
        if not data:
            break
        md5.update(data)
    f_desc.close()
    return md5.hexdigest()


def launch_fuzzing(config, number_files_to_create,
                   working_directory):
    """
    Launch the fuzzing
    Args:
        config: the configuration as a dict
        number_files_to_create (int): number of file to generate per iteration
        working_directory (string): working directory for inputs files
    """
    # Hash tab: hash -> input file
    previous_inputs = {}
    # Couple: (file_name, classification)
    crashes = []
    while True:
        logging.info("Generating new files")
        new_files = radamsa.fuzz_files(config['seed_pattern'], "fuzz",
                                       number_files_to_create,
                                       config['file_format'],
                                       working_directory)
        for new_file in new_files:
            logging.info("Run " + new_file)
            md5_val = compute_md5(working_directory + new_file)
            if md5_val in previous_inputs:
                logging.info("Input already saw")
                continue
            previous_inputs[md5_val] = new_file
            if config['using_autoit']:
                crashed = autoit.run(config['path_autoit_script'], [
                    working_directory + new_file])
            else:
                crashed = run_process.run(config['path_program'],
                                          config['program_name'],
                                          config['parameters'] +
                                          [working_directory + new_file],
                                          config['auto_close'],
                                          config['running_time'])
            if crashed:
                logging.info("Crash detected")

                if config['using_autoit']:
                    classification = "NOT IMPLEMENTED"
                else:
                    classification = exploitable_standalone.run(config['path_program'],
                                                                config[
                                                                    'program_name'],
                                                                config[
                                                                    'parameters'] +
                                                                [working_directory + new_file])
                logging.info("Classification: " + classification)
                new_name = "crash-" + str(len(crashes))
                try:
                    os.rename(working_directory + new_file,
                              working_directory + new_name)
                except OSError:
                    logging.error("Error for renaming file")
                crashes.append((new_name, classification))


def main(config_file, config_system_file, working_directory, log_level):
    """
    Main function
    Args:
        config_file: the user configuration file
        config_sytem_file: the system configuration file
        working_directory (string): working directory for inputs files
        log_level (int): Logging level: 0 debug 1 info, 2 warning, 3 error
    """
    config = parse_config(config_file)

    check_config(config)

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

    config_system = parse_config(config_system_file)

    init(config, config_system)

    launch_fuzzing(config, 2, working_directory)

if __name__ == "__main__":
    parser_cmd = argparse.ArgumentParser(
        description='Trail of bits fuzzing system.')
    parser_cmd.add_argument('-c', '--config', help='Yaml configuration file',
                            required=False, default="config.yaml")
    parser_cmd.add_argument('-cs', '--config_system', help='Yaml configuration file',
                            required=False, default="system.yaml")
    parser_cmd.add_argument('-w', '--working_directory', help='Working directory',
                            required=False, default="")
    parser_cmd.add_argument('-l', '--log_level', type=int,
                            help='Logging level: 0 debug 1 info, 2 warning, 3 error',
                            required=False, default=0)
    args_vmfuzz = vars(parser_cmd.parse_args())

    main(args_vmfuzz['config'], args_vmfuzz['config_system'],
         args_vmfuzz['working_directory'], args_vmfuzz['log_level', ])
