""" Module handling Radamsa """
import subprocess

RADAMSA_BIN = r"C:\cygwin\bin\radamsa.exe"

def fuzz_files(pattern_in, name_out, number_files_to_create, format_file):
    """
    Launch radamsa
    Args:
        pattern_in: pattern of inputs file used by radamsa
        number_files_to_create (int): number of file to generate per iteration
        format_file: file format of the generated inputs
    Returns:
        string list: Files created
    """
    cmd = [RADAMSA_BIN, "-o", name_out+"-%n"+format_file, "-n", \
          str(number_files_to_create), pattern_in]
    subprocess.call(cmd)
    return [name_out+"-"+str(x)+format_file for x in range(1, 1+number_files_to_create)]

