""" Module handling AutoIt """
""" The AutoIt script must return "no error" if the execution sucessed"""
import subprocess

AUTOIT_BIN = r"C:\Program Files\AutoIt3\AutoIt3.exe"

def run(autoit_script, parameters):
    """
    Run autoit scrit
    Args:
        autoit_script (string): path the to script
        parameters (string list): parameters of the script
    Returns:
        bool: True if crash detected, False otherwise
    """
    cmd = [AUTOIT_BIN, autoit_script]+parameters
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    proc.wait()
    if proc.stdout.readline() == "no error":
        return False
    return True


