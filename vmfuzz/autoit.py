""" Module handling AutoIt
    The AutoIt script must return "no error" if the execution sucessed"""
import subprocess

import crash_detection

AUTOIT_BIN = ""


def run(autoit_script, parameters):
    """
    Run autoit scrit
    Args:
        autoit_script (string): path the to script
        parameters (string list): parameters of the script
    Returns:
        bool: True if crash detected, False otherwise

    To detect crashes:
        - If autoIt script detects a script it return "error"
        - If not, check if WerFault.exe process if running
    """
    cmd = [AUTOIT_BIN, autoit_script] + parameters
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    proc.wait()
    if proc.stdout.readline() != "no error":
        return True
    if crash_detection.check_wrfault():
        return True
    return False
