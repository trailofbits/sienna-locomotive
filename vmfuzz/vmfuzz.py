""" Main module, it loops between the fuzzer and the autoit script """
import os
import hashlib
import argparse
import logging
import yaml

import radamsa
import autoit
import run_process


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

    # Check for seed_pattern field
    if 'seed_pattern' not in config:
        logging.error("Bad configuration file: missing seed_pattern")
        exit()

    # Check for file_format field
    if 'file_format' not in config:
        logging.error("Bad configuration file: missing format_file")
        exit()

    return config


def init(config):
    """
    Initialize the CRS
    Args:
        The configuration as a dict
    """
    radamsa.RADAMSA_BIN = config['path_radamsa']
    if config['using_autoit']:
        autoit.AUTOIT_BIN = config['path_autoit']
        autoit.AUTOIT_SCRIPT = config['path_autoit_script']


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
    previous_inputs = {}
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
                crashed = autoit.run(autoit.AUTOIT_SCRIPT, [
                    working_directory + new_file])
            else:
                crashed = run_process.run(config['path_program'],
                                          config['program_name'],
                                          [working_directory + new_file],
                                          config['auto_close'],
                                          config['running_time'])
            if crashed:
                logging.info("Crash detected")
                new_name = "crash-" + str(len(crashes))
                try:
                    os.rename(working_directory + new_file,
                              working_directory + new_name)
                except OSError:
                    logging.error("Error for renaming file")
                crashes.append(new_name)


def main(config_file, working_directory, log_level):
    """
    Main function
    Args:
        config: the configuration file
        working_directory (string): working directory for inputs files
        log_level (int): Logging level: 0 debug 1 info, 2 warning, 3 error
    """
    config = parse_config(config_file)

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

    init(config)

    launch_fuzzing(config, 10, working_directory)

if __name__ == "__main__":
    parser_cmd = argparse.ArgumentParser(
        description='Trail of bits fuzzing system.')
    parser_cmd.add_argument('-c', '--config', help='Yaml configuration file',
                            required=False, default="config.yaml")
    parser_cmd.add_argument('-w', '--working_directory', help='Working directory',
                            required=False, default="")
    parser_cmd.add_argument('-l', '--log_level', type=int,
                            help='Logging level: 0 debug 1 info, 2 warning, 3 error',
                            required=False, default=0)
    args_vmfuzz = vars(parser_cmd.parse_args())

    main(args_vmfuzz['config'], args_vmfuzz[
        'working_directory'], args_vmfuzz['log_level', ])
