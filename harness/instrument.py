"""
Instrumentation functions for running DynamoRIO client & the fuzzing server
Imports harness/config.py for argument and config file handling.
Imports harness/state.py for fuzzing lifecycle management
Imports harness/enums.py for the targeting mode enum
"""

import subprocess
import time
import signal
import threading
import uuid
import os
import json
import traceback
import sys
from enum import IntEnum

from .state import parse_triage_output, finalize, write_output_files, stringify_program_array
from . import config


print_lock = threading.Lock()
can_fuzz = True


class Mode(IntEnum):
    """ Function selection modes. KEEP THIS UP-TO-DATE with common/enums.h """
    MATCH_INDEX = 1 << 0
    MATCH_RETN_ADDRESS = 1 << 1
    MATCH_ARG_HASH = 1 << 2
    MATCH_ARG_COMPARE = 1 << 3


def print_l(*args):
    """ Thread safe print """
    with print_lock:
        print(*args)


def start_server():
    """ Start the server if it's not already running """
    if not os.path.isfile(config.sl2_server_pipe_path):
        subprocess.Popen(["powershell", "start", "powershell",
                          "{-NoExit", "-Command", "\"{}\"}}".format(config.config['server_path'])])
    while not os.path.isfile(config.sl2_server_pipe_path):
        time.sleep(1)


def run_dr(config_dict, save_stderr=False, verbose=False, timeout=None):
    """ Runs dynamorio with the given config. Clobbers console output if save_stderr/stdout are true """
    program_arr = [config_dict['drrun_path'], '-pidfile', 'pidfile'] + config_dict['drrun_args'] + \
        ['-c', config_dict['client_path']] + config_dict['client_args'] + \
        ['--', config_dict['target_application_path']] + config_dict['target_args']

    if verbose:
        print_l("Executing drrun: %s" % stringify_program_array(program_arr[0], program_arr[1:]))

    # Run client on target application
    started = time.time()

    stdout = sys.stdout if config_dict['inline_stdout'] else subprocess.PIPE
    stderr = subprocess.PIPE
    popen_obj = subprocess.Popen(program_arr,
                                 stdout=stdout,
                                 stderr=stderr)

    # Try to get the output from the process, time out if necessary
    try:
        stdout, stderr = popen_obj.communicate(timeout=timeout)

        if verbose:
            print_l("Process completed after %s seconds" % (time.time() - started))

        # Overwrite fields on the object we return to make stdout/stderr the right type
        popen_obj.stdout = stdout
        popen_obj.stderr = stderr
        popen_obj.timed_out = False

        return popen_obj

    # Handle cases where the program didn't exit in time
    except subprocess.TimeoutExpired:
        if verbose:
            print_l("Process Timed Out after %s seconds" % (time.time() - started))

        # Parse PID of target application and kill it, which causes drrun to exit
        with open('pidfile', 'r') as pidfile:
            pid = pidfile.read().strip()
            if verbose:
                print_l("Killing child process:", pid)
            os.kill(int(pid), signal.SIGTERM)

        # Try to get the output again
        try:
            stdout, stderr = popen_obj.communicate(timeout=5)  # Try to grab the existing console output
            popen_obj.stdout = stdout
            popen_obj.stderr = stderr

        # If the timeout fires again, we probably caused the target program to hang
        except subprocess.TimeoutExpired:
            if verbose:
                print_l("Caused the target application to hang")

            # Fix types again (expects bytes)
            popen_obj.stdout = "ERROR".encode('utf-8')
            popen_obj.stderr = "EXCEPTION_SL2_TIMEOUT".encode('utf-8')

        popen_obj.timed_out = True

        return popen_obj


def wizard_run(config_dict):
    """ Runs the wizard and lets the user select a target function """
    completed_process = run_dr({'drrun_path': config_dict['drrun_path'],
                                'drrun_args': config_dict['drrun_args'],
                                'client_path': config_dict['wizard_path'],
                                'client_args': [],
                                'target_application_path': config_dict['target_application_path'],
                                'target_args': config_dict['target_args'],
                                'inline_stdout': config_dict['inline_stdout'] },
                                save_stderr=True,
                                verbose=config_dict['verbose'])
    wizard_output = completed_process.stderr.decode('utf-8')
    wizard_findings = []

    for line in wizard_output.splitlines():
        try:
            obj = json.loads(line)
            if "wrapped" == obj["type"]:
                # TODO do something here later
                pass
            elif "in" == obj["type"]:
                # TODO do something here later
                pass
            elif "id" == obj["type"]:
                obj['mode'] = Mode.MATCH_INDEX
                obj['selected'] = False
                wizard_findings.append(obj)
        except Exception:
            pass

    return wizard_findings


def fuzzer_run(config_dict):
    """ Runs the fuzzer """
    completed_process = run_dr(config_dict, True,
                               verbose=config_dict['verbose'], timeout=config_dict.get('fuzz_timeout', None))

    # Parse run ID from fuzzer output
    run_id = 'ERR'
    proc_stderr = completed_process.stderr.decode('utf-8')

    for line in str.splitlines(proc_stderr):
        if 'Beginning fuzzing run' in line:
            uuid_s = line.replace('Beginning fuzzing run ', '').strip()
            run_id = uuid.UUID(uuid_s)
    if run_id == 'ERR':
        print_l("Error: No run ID could be parsed from the server output")
        return False, -1

    # Identify whether the fuzzing run resulted in a crash
    crashed = 'EXCEPTION_' in proc_stderr
    if crashed:
        print_l('Fuzzing run %s returned %s' % (run_id, completed_process.returncode))
        # Write stdout and stderr to files
        # TODO fix issue #40
        write_output_files(completed_process, run_id, 'fuzz')
    elif config_dict['verbose']:
        print_l("Run %s did not find a crash" % run_id)

    # Handle orphaned pipes after a timeout
    if completed_process.timed_out:
        if crashed:
            finalize(run_id, True)
        else:
            finalize(run_id, False)

    return crashed, run_id


def triage_run(config_dict, run_id):
    """ Runs the triaging tool """
    completed_process = run_dr({'drrun_path': config_dict['drrun_path'],
                                'drrun_args': config_dict['drrun_args'],
                                'client_path': config_dict['triage_path'],
                                'client_args': config_dict['client_args'] + ['-r', str(run_id)],
                                'target_application_path': config_dict['target_application_path'],
                                'target_args': config_dict['target_args'],
                                'inline_stdout': config_dict['inline_stdout']},
                               True,
                               config_dict['verbose'],
                               config_dict.get('triage_timeout', None))

    # Write stdout and stderr to files
    write_output_files(completed_process, run_id, 'triage')

    formatted, _ = parse_triage_output(run_id)
    return formatted


def fuzz_and_triage(config_dict):
    """ Runs the fuzzer (in a loop if continuous is true), then runs the triage tool if a crash is found """
    global can_fuzz
    # TODO: Move try/except so we can start new runs after an exception
    try:
        while can_fuzz:
            crashed, run_id = fuzzer_run(config_dict)
            if crashed:
                formatted = triage_run(config_dict, run_id)
                print_l(formatted)

                if config_dict['exit_early']:
                    can_fuzz = False  # Prevent other threads from starting new fuzzing runs

            if not config_dict['continuous']:
                return

    except Exception:
        traceback.print_exc()


def kill():
    global can_fuzz
    can_fuzz = False
