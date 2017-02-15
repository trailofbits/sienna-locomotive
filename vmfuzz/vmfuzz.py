""" Main module, it loops between the fuzzer and the autoit script """
import os
import hashlib
import argparse
import logging
import yaml

import radamsa
import autoit

def init(config_file):
    """
    Initialize the CRS
    Args:
        config_file (string): Name of the yaml configuration file
    """
    f_desc = open(config_file, 'r')
    config = yaml.load(f_desc)
    radamsa.RADAMSA_BIN = config['path_radamsa']
    autoit.AUTOIT_BIN = config['path_autoit']
    autoit.AUTOIT_SCRIPT = config['path_autoit_script']
    f_desc.close()

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

def launch_fuzzing(pattern_in, number_files_to_create, format_file, working_directory):
    """
    Launch the fuzzing
    Args:
        pattern_in: pattern of inputs file used by radamsa
        number_files_to_create (int): number of file to generate per iteration
        format_file: file format of the generated inputs
        working_directory: working directory for inputs files
    """
    previous_inputs = {}
    crashes = []
    while True:
        logging.info("Generating new files")
        new_files = radamsa.fuzz_files(pattern_in, "fuzz", number_files_to_create, format_file)
        for new_file in new_files:
            logging.info("Run "+new_file)
            md5_val = compute_md5(working_directory+new_file)
            if md5_val in previous_inputs:
                logging.info("Input already saw")
                break
            previous_inputs[md5_val] = new_file
            crashed = autoit.run(autoit.AUTOIT_SCRIPT, [working_directory+new_file])
            if crashed:
                logging.info("Crash detected")
                new_name = "crash-"+str(len(crashes))
                try:
                    os.rename(working_directory+new_file, working_directory+new_name)
                except OSError:
                    logging.error("Error for renaming file")
                crashes.append(new_name)

def main():
    """
    Main function
    """
    parser_cmd = argparse.ArgumentParser(description='Trail of bits fuzzing system.')
    parser_cmd.add_argument('-c', '--config', help='Yaml configuration file', \
                        required=False, default="config.yaml")
    parser_cmd.add_argument('-w', '--working_directory', help='Working directory', \
                        required=False, default="")
    parser_cmd.add_argument('-l', '--log_level', type=int,\
                        help='Logging level: 0 debug 1 info, 2 warning, 3 error', \
                        required=False, default=0)
    args_vmfuzz = vars(parser_cmd.parse_args())

    if args_vmfuzz['log_level'] == 0:
        logging.basicConfig(filename="vmfuzz.log", filemode='w', level=logging.DEBUG)
    elif args_vmfuzz['log_level'] == 1:
        logging.basicConfig(filename="vmfuzz.log", filemode='w', level=logging.INFO)
    elif args_vmfuzz['log_level'] == 2:
        logging.basicConfig(filename="vmfuzz.log", filemode='w', level=logging.WARNING)
    elif args_vmfuzz['log_level'] == 3:
        logging.basicConfig(filename="vmfuzz.log", filemode='w', level=logging.ERROR)

    init(args_vmfuzz['config'])

    launch_fuzzing("*.pdf", 10, ".pdf", args_vmfuzz['working_directory'])

if  __name__ == "__main__":
    main()


