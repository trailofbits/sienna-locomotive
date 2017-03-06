""" Module handling Radamsa """
import os
import subprocess
import logging
import hashlib
import autoit as autoit
import utils.run_process as run_process
import exploitability.exploitable as exploitable
import radamsa_constants


def init(config_system):
    """
    Initialize the constantss used by the module
    Args:
        The system configuration as a dict
    """

    radamsa_constants.RADAMSA_BIN = config_system['path_radamsa_bin']
    radamsa_constants.NUMBER_FILES_TO_CREATE = config_system[
        'radamsa_number_files_to_create']
    radamsa_constants.WORKING_DIRECTORY = config_system[
        'path_radamsa_working_directory']


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


def fuzz_files(pattern_in, name_out, format_file):
    """
    Launch radamsa
    Args:
        pattern_in: pattern of inputs file used by radamsa
        format_file: file format of the generated inputs
    Returns:
        string list: Files created
    """
    # radasma does not handle well windows directory syntax
    # so we change the current directory
    if radamsa_constants.WORKING_DIRECTORY != "":
        prev_dir = os.getcwd()
        os.chdir(radamsa_constants.WORKING_DIRECTORY)
    cmd = [radamsa_constants.RADAMSA_BIN, "-o", name_out + "-%n" + format_file, "-n",
           str(radamsa_constants.NUMBER_FILES_TO_CREATE), pattern_in]
    print cmd
    subprocess.call(cmd)
    # restore previous directory
    if radamsa_constants.WORKING_DIRECTORY != "":
        os.chdir(prev_dir)
    range_files = range(1, 1 + radamsa_constants.NUMBER_FILES_TO_CREATE)
    return [name_out + "-" + str(x) + format_file for x in range_files]


def launch_fuzzing(config):
    """
    Launch the fuzzing
    Args:
        config: the configuration as a dict
    """
    # Hash tab: hash -> input file
    previous_inputs = {}
    # Couple: (file_name, classification)
    crashes = []
    while True:
        logging.info("Generating new files")
        new_files = fuzz_files(config['seed_pattern'], "fuzz",
                               config['file_format'])
        for new_file in new_files:
            logging.info("Run " + new_file)
            md5_val = compute_md5(
                radamsa_constants.WORKING_DIRECTORY + new_file)
            if md5_val in previous_inputs:
                logging.info("Input already saw")
                continue
            previous_inputs[md5_val] = new_file
            if config['using_autoit']:
                crashed = autoit.run(config['path_autoit_script'], [
                    radamsa_constants.WORKING_DIRECTORY + new_file])
            else:
                crashed = run_process.run(config['path_program'],
                                          config['program_name'],
                                          config['parameters'] +
                                          [radamsa_constants.WORKING_DIRECTORY + new_file],
                                          config['auto_close'],
                                          config['running_time'])
            if crashed:
                logging.info("Crash detected")

                if config['using_autoit']:
                    params = config['parameters'] + \
                        [radamsa_constants.WORKING_DIRECTORY + new_file]
                    classification = exploitable.run_autoit(config['path_autoit_script'],
                                                            config[
                                                                'path_program'],
                                                            config[
                                                                'program_name'],
                                                            params)
                else:
                    params = [radamsa_constants.WORKING_DIRECTORY + new_file]
                    classification = exploitable.run(config['path_program'],
                                                     config['program_name'],
                                                     config['parameters'] +
                                                     params)
                logging.info("Classification: " + classification)
                new_name = "crash-" + str(len(crashes)) + config['file_format']
                try:
                    os.rename(radamsa_constants.WORKING_DIRECTORY + new_file,
                              radamsa_constants.WORKING_DIRECTORY + new_name)
                except OSError:
                    os.remove(radamsa_constants.WORKING_DIRECTORY + new_name)
                    os.rename(radamsa_constants.WORKING_DIRECTORY + new_file,
                              radamsa_constants.WORKING_DIRECTORY + new_name)
                crashes.append((new_name, classification))
