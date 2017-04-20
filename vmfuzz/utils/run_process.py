""" Module handling the run of process """
import subprocess
import time
import os

import exploitability.crash_detection as crash_detection


def kill_process(process):
    """
    Kill a processus

    Args:
        process (string): name of the processus
    """
    cmd_kill = "Taskkill /IM "+process+" /F"
    proc = subprocess.Popen(cmd_kill, stdout=subprocess.PIPE)
    proc.wait()


def kill_process_after_timeout(process, timeout):
    """
    Kill a process after a timeout

    Args:
        process (string): name of the processus
        timeout (int): timeout in seconds
    """
    time.sleep(timeout)
    cmd_kill = "Taskkill /IM " + process + " /F"
    proc = subprocess.Popen(cmd_kill)
    proc.wait()


def run(path_program, program_name, parameters, auto_close, running_time):
    """
    Run the program

    Args:
        path_program (string): path the to the program
        program_name (string): name of the program
        parameters (string list): parameters of the script
        auto_close (bool): the program closes itself
        running_time (int): waiting time in seconds (if auto_close = True)
    Returns:
        bool: True if crash detected, False otherwise
    """
    cmd = [os.path.join(path_program, program_name)] + parameters
    subprocess.Popen(cmd, stdout=subprocess.PIPE)
    if auto_close:
        if crash_detection.check_wrfault():
            kill_process(program_name)
            return True
        return False
    else:
        time.sleep(running_time)
        if not crash_detection.detect_process_running(program_name):
            return True
        if crash_detection.check_wrfault():
            kill_process(program_name)
            return True
        kill_process(program_name)
        return False
