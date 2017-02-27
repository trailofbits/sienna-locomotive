"""
    Module handling winafl
"""
import subprocess
import time

WINAFL_PATH = ""
WINAFL_BIN = ""
DYNAMORIO_PATH = ""

DRRUN = ""
WINAFLDLL = ""

def generate_drrun_cmd(config, running_cmd):
    """
    Generate drrun.exe command line
    Args:
        config (dict): configuration
        running_cmd (list string)
    Returns:
        drrun.exe cmd (list string)
    """
    drrun_cmd = [
        DRRUN,
        "-c",
        WINAFLDLL,
        "-debug",
        "-target_module",
        config['module'],
        '-target_offset',
        config['offset'],
        '-fuzz_iterations',
        '10',
        '-nargs',
        config['nargs'],
        '--'
    ]
    return drrun_cmd + running_cmd


def generate_winafl_cmd(config, running_cmd):
    """
    Generate winafl command line
    Args:
        config (dict): configuration
        running_cmd (list string)
    Returns:
        winafl cmd (list string)
    """
    winafl_cmd = [
        WINAFL_PATH + WINAFL_BIN,
        '-i',
        config['in_dir'],
        '-o',
        config['out_dir'],
        '-D',
        DYNAMORIO_PATH,
        '-t',
        config['timeout'],
        '-f',
        config['file'],
        '--',
        '-coverage_module',
        config['module'],
        '-target_module',
        config['module'],
        '-target_offset',
        config['offset'],
        '-nargs',
        config['nargs'],
        '--'
    ]
    running_cmd = ["@@" if config['file'] in x else x for x in running_cmd]
    return winafl_cmd + running_cmd


def pp_cmd(cmd):
    """
    Convert a list of string to a string
    Args:
        cmd (list of string)
    Returns:
        cmd as a string
    """
    return ' '.join(cmd)


def run_drrun(config, running_cmd):
    """
    Run drrun.exe (debug function)
    Args:
        config (dict): configuration
        running_cmd (list string)

    Log stdout in log_out file, stderr in log_err file
    """
    cmd = generate_drrun_cmd(config, running_cmd)
    log_out = open("log_out", 'w')
    log_err = open("log_err", 'w')
    proc = subprocess.Popen(cmd, shell=True,
                            stdout=log_out, stderr=log_err,
                            cwd=config['working_dir'])
    proc.wait()


def run_winafl(config, running_cmd):
    """
    Run winafl
    Args:
        config (dict): configuration
        running_cmd (list string)
    Returns: 0 if error, 1 if success
    TODO JF: To be improved: using timeout and detecting if process still running
    """

    cmd = generate_winafl_cmd(config, running_cmd)
    proc = subprocess.Popen(pp_cmd(cmd), cwd=config['working_dir'])
    time.sleep(60)
    if proc.poll() is None:
        print "Winafl running!"
        return 1
    else:
        print "Winafl not running"
        return 0
