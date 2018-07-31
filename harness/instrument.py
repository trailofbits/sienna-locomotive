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
import os
import json
import traceback
import sys
from enum import IntEnum

from .state import (
    parse_triage_output,
    finalize,
    write_output_files,
    create_invocation_statement,
    check_fuzz_line_for_crash,
    check_fuzz_line_for_run_id,
    get_path_to_run_file,
)

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


def run_dr(config_dict, verbose=False, timeout=None):
    """ Runs dynamorio with the given config. Clobbers console output if save_stderr/stdout are true """
    program_arr, program_str, pidfile = create_invocation_statement(config_dict)

    if verbose:
        print_l("Executing drrun: %s" % program_str)

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
        with open(pidfile, 'r') as pidfile:
            pid = pidfile.read().strip()
            if verbose:
                print_l("Killing child process:", pid)
            try:
                os.kill(int(pid), signal.SIGTERM)
            except PermissionError:
                print_l("WARNING: Couldn't kill child process")

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
            popen_obj.stderr = json.dumps({"exception": "EXCEPTION_SL2_TIMEOUT"}).encode('utf-8')

        popen_obj.timed_out = True
    finally:
        try:
            os.remove(pidfile)
        except OSError:
            print_l("[!] Couldn't remove pidfile: ", pidfile)

    return popen_obj


def triager_run(run_id):
    dmpfile = get_path_to_run_file(run_id, "initial.dmp")
    if os.path.isfile(dmpfile):
        cmd = [r'.\build\triage\Debug\triager.exe', dmpfile]
        # TODO(ww): Unused variable.
        out = subprocess.check_output(cmd, shell=False)
        if config.config["debug"]:
            print_l(repr(out))
    else:
        print_l("[!] No initial.dmp to triage!")


def wizard_run(config_dict):
    """ Runs the wizard and lets the user select a target function """
    completed_process = run_dr({'drrun_path': config_dict['drrun_path'],
                                'drrun_args': config_dict['drrun_args'],
                                'client_path': config_dict['wizard_path'],
                                'client_args': [],
                                'target_application_path': config_dict['target_application_path'],
                                'target_args': config_dict['target_args'],
                                'inline_stdout': config_dict['inline_stdout']},
                               verbose=config_dict['verbose'])
    wizard_findings = []
    mem_map = {}
    base_addr = None

    for line in completed_process.stderr.split(b'\n'):
        try:
            line = line.decode('utf-8')
            obj = json.loads(line)

            if "map" == obj["type"]:
                mem_map[(obj["start"], obj["end"])] = obj["mod_name"]
                if ".exe" in obj["mod_name"]:
                    base_addr = obj["start"]
            elif "id" == obj["type"]:
                obj['mode'] = Mode.MATCH_INDEX
                obj['selected'] = False
                ret_addr = obj["retAddrOffset"] + base_addr
                for addrs in mem_map.keys():
                    if ret_addr in range(*addrs):
                        obj['called_from'] = mem_map[addrs]

                wizard_findings.append(obj)
        except UnicodeDecodeError:
            if config_dict["verbose"]:
                print_l("[!] Not UTF-8:", repr(line))
        except json.JSONDecodeError:
            pass
        except Exception as e:
            print_l("[!] Unexpected exception:", e)

    return wizard_findings


def fuzzer_run(config_dict):
    """ Runs the fuzzer """
    completed_process = run_dr(config_dict, verbose=config_dict['verbose'], timeout=config_dict.get('fuzz_timeout', None))

    # Parse run ID from fuzzer output
    run_id = None
    crashed = False

    for line in completed_process.stderr.split(b'\n'):
        try:
            line = line.decode('utf-8')
            # Extract the run id from the run
            if not run_id:
                run_id = check_fuzz_line_for_run_id(line)

            # Identify whether the fuzzing run resulted in a crash
            if not crashed:
                crashed, exception = check_fuzz_line_for_crash(line)
        except UnicodeDecodeError:
            if config_dict['verbose']:
                print_l("[!] Not UTF-8:", repr(line))

    if not run_id:
        print_l("Error: No run ID could be parsed from the server output")
        return False, -1

    if crashed:
        print_l('Fuzzing run %s returned %s after raising %s' % (run_id, completed_process.returncode, exception))
        # Write stdout and stderr to files
        # TODO fix issue #40
        write_output_files(completed_process, run_id, 'fuzz')
    elif config_dict['verbose']:
        print_l("Run %s did not find a crash" % run_id)

    # Handle orphaned pipes after a timeout
    if completed_process.timed_out:
        finalize(run_id, crashed)

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
                               config_dict['verbose'],
                               config_dict.get('triage_timeout', None))

    # Write stdout and stderr to files
    write_output_files(completed_process, run_id, 'triage')

    formatted, raw = parse_triage_output(run_id)
    triager_run(run_id)
    return formatted, raw


def fuzz_and_triage(config_dict):
    """ Runs the fuzzer (in a loop if continuous is true), then runs the triage tool if a crash is found """
    global can_fuzz
    # TODO: Move try/except so we can start new runs after an exception
    try:
        while can_fuzz:
            crashed, run_id = fuzzer_run(config_dict)
            if crashed:
                formatted, _ = triage_run(config_dict, run_id)
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
