""" Module handling AutoIt
    The AutoIt script must return 0 if the execution sucessed"""

import subprocess
import os
import logging
import exploitability.crash_detection as crash_detection

AUTOIT_BIN = ""

def init(config_system):
    """
    Initialize the module

    Args:
        config_system (dict): The system configuration
    """

    global AUTOIT_BIN
    AUTOIT_BIN = os.path.join(config_system['path_autoit'], "AutoIt3.exe")

def run(autoit_script, parameters):
    """
    Run autoit scrit 

    Args:
        autoit_script (string): path to the script
        parameters (string list): parameters of the script
    Note:
        The function returns as soon that the script is launched
    """
    cmd = [AUTOIT_BIN, autoit_script] + parameters
    logging.debug("Run autoit: "+str(cmd))
    subprocess.Popen(cmd, stdout=subprocess.PIPE)

def run_and_wait(autoit_script, parameters):
    """
    Run autoit scrit and wait its end

    Args:
        autoit_script (string): path to the script
        parameters (string list): parameters of the script
    """
    cmd = [AUTOIT_BIN, autoit_script] + parameters
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    proc.wait()

def run_and_check(autoit_script, parameters):
    """
    Run autoit scrit and check if a crash occured

    Args:
        autoit_script (string): path to the script
        parameters (string list): parameters of the script
    Returns:
        bool: True if crash detected, False otherwise
    To detect crashes:
        - Check if WerFault.exe process if running
        - If not, check the return value of the autoit script (0: no error)
    """
    cmd = [AUTOIT_BIN, autoit_script] + parameters
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    ret_code = proc.wait()
    print ret_code
    if crash_detection.check_wrfault():
        return True
    if ret_code != 0:
        return True
    return False


