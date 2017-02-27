""" Module handling Radamsa """
import os
import subprocess

RADAMSA_BIN = r"C:\cygwin\bin\radamsa.exe"


def fuzz_files(pattern_in, name_out, number_files_to_create, format_file,
               working_directory):
    """
    Launch radamsa
    Args:
        pattern_in: pattern of inputs file used by radamsa
        number_files_to_create (int): number of file to generate per iteration
        format_file: file format of the generated inputs
        working_directory (string): the working directory
    Returns:
        string list: Files created
    """
    # radasma does not handle well windows directory syntax
    # so we change the current directory
    if working_directory != "":
        prev_dir = os.getcwd()
        os.chdir(working_directory)
    cmd = [RADAMSA_BIN, "-o", name_out + "-%n" + format_file, "-n",
           str(number_files_to_create), pattern_in]
    subprocess.call(cmd)
    # restore previous directory
    if working_directory != "":
        os.chdir(prev_dir)
    return [name_out + "-" + str(x) + format_file for x in range(1, 1 + number_files_to_create)]
