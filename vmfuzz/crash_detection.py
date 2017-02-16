""" Module handling the crashes detection
    Tested on Windows Seven """
import subprocess


def detect_process_running(process):
    """
    Detect if the process is still running
    Args:
        process (string): Name of the process
    Returns:
        bool: True if the process is running, False otherwise
    """
    # Check if the process is running
    cmd_werfault = "tasklist /FI \"IMAGENAME eq " + process + "\""
    proc = subprocess.Popen(cmd_werfault, stdout=subprocess.PIPE)
    proc.wait()
    for line in iter(proc.stdout.readline, ''):
        if process in line:
            return True
    return False


def check_wrfault():
    """
    Detect crash by checking the presence of WerFault.exe process
    Returns:
        bool: True if a crash is detected, False otherwise
    """
    is_running = detect_process_running("WerFault.exe")
    # If the WerFault is running, kill it and return True
    if is_running:
        cmd_kill_werfault = "Taskkill /IM WerFault.exe /F"
        proc = subprocess.Popen(cmd_kill_werfault, stdout=subprocess.PIPE)
        proc.wait()
        return True
    return False
