""" Module handling AutoIt
    The AutoIt script must return 0 if the execution sucessed"""
import subprocess
import exploitability.crash_detection as crash_detection

AUTOIT_BIN = ""


def run(autoit_script, parameters):
    """
    Run autoit scrit
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


