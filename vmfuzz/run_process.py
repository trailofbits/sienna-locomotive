""" Module handling the run of process
    The AutoIt script must return "no error" if the execution sucessed"""
import subprocess
import time

import crash_detection


def run(path_program, program_name, parameters, auto_close, running_time):
    """
    Run autoit scrit
    Args:
        path_program (string): path the to the program
        program_name (string): name of the program
        parameters (string list): parameters of the script
        auto_close (bool): the program closes itself
        running_time (int): waiting time in seconds (if auto_close = True)
    Returns:
        bool: True if crash detected, False otherwise

    To detect crashes:
        
        - If not, check if WerFault.exe process if running
    """
    cmd = [path_program + program_name] + parameters
    print cmd
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    if auto_close:
        print "Not yet implemented"
        exit()
    else:
        time.sleep(running_time)
        if not crash_detection.detect_process_running(program_name):
            return True
        if crash_detection.check_wrfault():
            return True
        return False


