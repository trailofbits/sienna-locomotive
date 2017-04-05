""" Module handling Radamsa """
import os
import subprocess
import shutil
import uuid
import logging
import autoit.autoit as autoit
import autoit.autoit_lib as autoit_lib
import utils.run_process as run_process
import utils.file_manipulation as file_manipulation
import fuzzers.radamsa.radamsa_constants as radamsa_constants


def init(config_system):
    """
    Initialize the constantss used by the module

    Args:
        config_system (dict): The system configuration
    """

    radamsa_constants.RADAMSA_BIN = os.path.join(
        config_system['path_radamsa'], "radamsa.exe")

    radamsa_constants.WORKING_DIRECTORY = config_system[
        'path_radamsa_working_dir']

    file_manipulation.create_dir(radamsa_constants.WORKING_DIRECTORY)

    autoit.init(config_system)

    autoit_lib.AUTOIT_LIB_DIRECTORY = os.path.join(
        config_system['path_vmfuzz'], "autoit_lib")

    autoit_lib.AUTOIT_WORKING_DIRECTORY = config_system[
        'path_autoit_working_dir']


def init_directories(config):
    """
    Initialize directories

    Args:
        config (dict): The user configuration
    """
    if '_id' in config:
        radamsa_constants.WORKING_DIRECTORY = os.path.join(
            radamsa_constants.WORKING_DIRECTORY, config['_id'])

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


def launch_fuzzing(config, t_fuzz_stopped):
    """
    Launch the fuzzing

    Args:
        config (dict): the user configuration
        t_fuzz_stopped (threading.Event): Event use to stop the fuzzing
    """

    # Hash tab: hash -> input file
    previous_inputs = {}
    # Couple: (file_name, classification)
    crashes = []
    while not t_fuzz_stopped.is_set():
        logging.info("Generating new files")
        if 'radamsa_seed_pattern' in config:
            seed_pattern = config['radamsa_seed_pattern']
        else:
            seed_pattern = "*" + config['file_format']
        new_files = fuzz_files(seed_pattern, "fuzz",
                               config['file_format'], config['radamsa_number_files_to_create'])
        for new_file in new_files:
            if t_fuzz_stopped.is_set():
                break
            logging.info("Run " + new_file)
            md5_val = file_manipulation.compute_md5(os.path.join(
                radamsa_constants.WORKING_DIRECTORY, new_file))
            if md5_val in previous_inputs:
                logging.info("Input already saw")
                continue
            previous_inputs[md5_val] = new_file
            parameters = file_manipulation.generate_parameters(
                config['parameters'],
                os.path.join(radamsa_constants.WORKING_DIRECTORY, new_file))
            if config['using_autoit']:
                path_autoit_script = autoit_lib.get_autoit_path(
                    config['path_autoit_script'], "")

                crashed = autoit.run_and_check(path_autoit_script, [os.path.join(
                    radamsa_constants.WORKING_DIRECTORY, new_file)])
            else:
                crashed = run_process.run(config['path_program'],
                                          config['program_name'],
                                          parameters,
                                          config['auto_close'],
                                          config['running_time'])
            if crashed:
                logging.info("Crash detected")
                new_name = "crash-" + str(uuid.uuid4()) + config['file_format']
                src = os.path.join(radamsa_constants.WORKING_DIRECTORY, new_file)
                dst = os.path.join(config['crash_dir'], new_name)
                shutil.copyfile(src, dst)
                crashes.append((new_name, classification))
