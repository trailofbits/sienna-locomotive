""" Module handling Radamsa """
import os
import subprocess
import logging
import autoit.autoit as autoit
import utils.run_process as run_process
import utils.file_manipulation as file_manipulation
import exploitability.exploitable as exploitable
import fuzzers.radamsa.radamsa_constants as radamsa_constants


def init(config_system):
    """
    Initialize the constantss used by the module

    Args:
        config_system (dict): The system configuration
    """

    radamsa_constants.RADAMSA_BIN = os.path.join(config_system['path_radamsa'], "radamsa.exe")

    radamsa_constants.WORKING_DIRECTORY = config_system['path_radamsa_working_dir']

    file_manipulation.create_dir(radamsa_constants.WORKING_DIRECTORY)

    autoit.init(config_system)

    exploitable.WINGDB_PATH = config_system['path_windbg']
    exploitable.AUTOIT_BIN = autoit.AUTOIT_BIN


def init_directories(config):
    """
    Initialize directories

    Args:
        config (dict): The user configuration
    """
    if 'timestamp' in config:
        radamsa_constants.WORKING_DIRECTORY = os.path.join(
            radamsa_constants.WORKING_DIRECTORY, config['timestamp'])

    if 'input_dir' in config:
        file_manipulation.move_dir(
            config['input_dir'], radamsa_constants.WORKING_DIRECTORY)


def fuzz_files(pattern_in, name_out, format_file, number_files_to_create):
    """
    Launch radamsa

    Args:
        pattern_in (string): pattern of input files used by radamsa
        name_out (string): pattern of mutated files
        format_file (string): file format of the generated inputs
        number_files_to_create (int): number of files to create at each round
    Returns:
        string list: Files created
    """
    # radasma does not handle well windows directory syntax
    # so we change the current directory
    if radamsa_constants.WORKING_DIRECTORY != "":
        prev_dir = os.getcwd()
        os.chdir(radamsa_constants.WORKING_DIRECTORY)
    cmd = [radamsa_constants.RADAMSA_BIN, "-o", name_out + "-%n" + format_file, "-n",
           str(number_files_to_create), pattern_in]
    subprocess.call(cmd)
    # restore previous directory
    if radamsa_constants.WORKING_DIRECTORY != "":
        os.chdir(prev_dir)
    range_files = range(1, 1 + number_files_to_create)
    return [name_out + "-" + str(x) + format_file for x in range_files]


def launch_fuzzing(config):
    """
    Launch the fuzzing

    Args:
        config (dict): the user configuration
    """
    # Hash tab: hash -> input file
    previous_inputs = {}
    # Couple: (file_name, classification)
    crashes = []
    while True:
        logging.info("Generating new files")
        new_files = fuzz_files(config['seed_pattern'], "fuzz",
                               config['file_format'], config['number_files_to_create'])
        for new_file in new_files:
            logging.info("Run " + new_file)
            md5_val = file_manipulation.compute_md5(os.path.join(
                radamsa_constants.WORKING_DIRECTORY, new_file))
            if md5_val in previous_inputs:
                logging.info("Input already saw")
                continue
            previous_inputs[md5_val] = new_file
            if config['using_autoit']:
                crashed = autoit.run(config['path_autoit_script'], [os.path.join(
                    radamsa_constants.WORKING_DIRECTORY, new_file)])
            else:
                crashed = run_process.run(config['path_program'],
                                          config['program_name'],
                                          config['parameters'] +
                                          [os.path.join(
                                              radamsa_constants.WORKING_DIRECTORY, new_file)],
                                          config['auto_close'],
                                          config['running_time'])
            if crashed:
                logging.info("Crash detected")

                if config['using_autoit']:
                    params = config['parameters'] + \
                        [os.path.join(
                            radamsa_constants.WORKING_DIRECTORY, new_file)]
                    classification = exploitable.run_autoit(config['path_autoit_script'],
                                                            config[
                                                                'path_program'],
                                                            config[
                                                                'program_name'],
                                                            params)
                else:
                    params = [os.path.join(
                        radamsa_constants.WORKING_DIRECTORY, new_file)]
                    classification = exploitable.run(config['path_program'],
                                                     config['program_name'],
                                                     config['parameters'] +
                                                     params)
                logging.info("Classification: " + classification)
                new_name = "crash-" + str(len(crashes)) + config['file_format']
                try:
                    os.rename(os.path.join(radamsa_constants.WORKING_DIRECTORY, new_file),
                              os.path.join(radamsa_constants.WORKING_DIRECTORY, new_name))
                except OSError:
                    os.remove(os.path.join(
                        radamsa_constants.WORKING_DIRECTORY, new_name))
                    os.rename(os.path.join(radamsa_constants.WORKING_DIRECTORY, new_file),
                              os.path.join(radamsa_constants.WORKING_DIRECTORY, new_name))
                crashes.append((new_name, classification))
