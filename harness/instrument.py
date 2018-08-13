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
import shutil
from enum import IntEnum
from typing import NamedTuple

from .state import (
    parse_triage_output,
    generate_run_id,
    write_output_files,
    create_invocation_statement,
    check_fuzz_line_for_crash,
    get_path_to_run_file,
    get_paths_to_run_file,
)

from . import config

print_lock = threading.Lock()
can_fuzz = True


class Mode(IntEnum):
    """
    Function selection modes.
    KEEP THIS UP-TO-DATE with common/enums.h
    """
    MATCH_INDEX = 1 << 0
    MATCH_RETN_ADDRESS = 1 << 1
    MATCH_ARG_HASH = 1 << 2
    MATCH_ARG_COMPARE = 1 << 3


class DRRun(NamedTuple):
    """
    Represents the state returned by a call to run_dr.
    """
    process: subprocess.Popen
    seed: str


def print_l(*args):
    """
    Prints the given arguments in a thread-safe manner.
    """
    with print_lock:
        print(*args)


def ps_run(command):
    """
    Runs the given command in a new PowerShell session.
    """
    subprocess.Popen(["powershell", "start", "powershell", "{-NoExit", "-Command", "\"{}\"}}".format(command)])


def start_server():
    """
    Start the server, if it's not already running.
    """
    if not os.path.isfile(config.sl2_server_pipe_path):
        ps_run(config.config['server_path'])
    while not os.path.isfile(config.sl2_server_pipe_path):
        time.sleep(1)


def run_dr(config_dict, verbose=False, timeout=None, run_id=None, tracing=False):
    """
    Runs dynamorio with the given config.
    Clobbers console output if save_stderr/stdout are true.
    Returns a DRRun instance containing the popen object and PRNG seed
    used during the run.
    """
    invoke = create_invocation_statement(config_dict, run_id)

    if verbose:
        print_l("Executing drrun: %s" % invoke.cmd_str)

    # Run client on target application
    started = time.time()

    stdout = sys.stdout if config_dict['inline_stdout'] else subprocess.PIPE
    stderr = subprocess.PIPE
    popen_obj = subprocess.Popen(invoke.cmd_arr,
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

        return DRRun(popen_obj, invoke.seed)

    # Handle cases where the program didn't exit in time
    except subprocess.TimeoutExpired:
        if verbose:
            print_l("Process Timed Out after %s seconds" % (time.time() - started))

        if run_id:
            pids_file = get_path_to_run_file(run_id, "trace.pids" if tracing else "fuzz.pids")

            with open(pids_file, 'rb') as pids_contents:
                for line in pids_contents.read().decode('utf-16').split('\n'):
                    if line:
                        # TODO(ww): We probably want to call finalize() once per pid here,
                        # since each pid has its own session/thread on the server.
                        pid = int(line)
                        if verbose:
                            print_l("Killing child process:", pid)
                        try:
                            os.kill(pid, signal.SIGTERM)
                        except (PermissionError, OSError) as e:
                            print_l("WARNING: Couldn't kill child process:", e)
                            print_l("Try running the harness as an Administrator.")
        else:
            print_l("WARNING: No run ID, so not looking for PIDs to kill.")

        # Try to get the output again
        try:
            # Try to grab the existing console output
            stdout, stderr = popen_obj.communicate(timeout=5)
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

    return DRRun(popen_obj, invoke.seed)


def triager_run(run_id):
    """
    Runs the (breakpad-based) triager on each of the minidumps generated
    by a fuzzing run.

    Yields the output of each triaging run.
    """
    dmpfiles = get_paths_to_run_file(run_id, "initial.*.dmp")

    if not dmpfiles:
        print_l("[!] No initial minidumps to triage!")
        return None

    for dmpfile in dmpfiles:
        cmd = [config.config['triager_path'], dmpfile]
        out = subprocess.check_output(cmd, shell=False)
        if config.config["verbose"]:
            print_l(repr(out))
        yield out


def wizard_run(config_dict):
    """
    Runs the wizard and lets the user select a target function.
    """
    run = run_dr(
        {
            'drrun_path': config_dict['drrun_path'],
            'drrun_args': config_dict['drrun_args'],
            'client_path': config_dict['wizard_path'],
            'client_args': config_dict['client_args'],
            'target_application_path': config_dict['target_application_path'],
            'target_args': config_dict['target_args'],
            'inline_stdout': config_dict['inline_stdout']
        },
        verbose=config_dict['verbose']
    )

    wizard_findings = []
    mem_map = {}
    base_addr = None

    for line in run.process.stderr.split(b'\n'):
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

    # Generate a run ID and hand it to the fuzzer.
    run_id = generate_run_id(config_dict)

    run = run_dr(
        {
            'drrun_path': config_dict['drrun_path'],
            'drrun_args': config_dict['drrun_args'],
            'client_path': config_dict['client_path'],
            'client_args': [*config_dict['client_args'], '-r', str(run_id)],
            'target_application_path': config_dict['target_application_path'],
            'target_args': config_dict['target_args'],
            'inline_stdout': config_dict['inline_stdout']
        },
        verbose=config_dict['verbose'],
        timeout=config_dict.get('fuzz_timeout', None),
        run_id=run_id,
        tracing=False,
    )

    # Parse crash status from the output.
    crashed = False

    for line in run.process.stderr.split(b'\n'):
        try:
            line = line.decode('utf-8')

            # Identify whether the fuzzing run resulted in a crash
            if not crashed:
                crashed, exception = check_fuzz_line_for_crash(line)
        except UnicodeDecodeError:
            if config_dict['verbose']:
                print_l("[!] Not UTF-8:", repr(line))

    write_output_files(run, run_id, 'fuzz')

    if crashed:
        print_l('Fuzzing run %s returned %s after raising %s'
                % (run_id, run.process.returncode, exception))
    else:
        if config_dict['verbose']:
            print_l("Run %s did not find a crash" % run_id)

        if config_dict['preserve_runs']:
            print_l('Preserving run %s without a crash (requested)' % run_id)
        else:
            shutil.rmtree(os.path.join(config.sl2_runs_dir, str(run_id)), ignore_errors=True)

    return crashed, run_id


# TODO(ww): Rename this to "tracer_run" or something similar,
# and break the internal triager_run call into another method
# (trace_and_triage, maybe?)
def triage_run(config_dict, run_id):
    """ Runs the triaging tool """
    run = run_dr(
        {
            'drrun_path': config_dict['drrun_path'],
            'drrun_args': config_dict['drrun_args'],
            'client_path': config_dict['tracer_path'],
            'client_args': [*config_dict['client_args'], '-r', str(run_id)],
            'target_application_path': config_dict['target_application_path'],
            'target_args': config_dict['target_args'],
            'inline_stdout': config_dict['inline_stdout']
        },
        config_dict['verbose'],
        config_dict.get('triage_timeout', None),
        run_id=run_id
    )

    # Write stdout and stderr to files
    write_output_files(run, run_id, 'triage')

    formatted, raw = parse_triage_output(run_id)
    triager_run(run_id)
    return formatted, raw


def fuzz_and_triage(config_dict):
    """
    Runs the fuzzer (in a loop if continuous is true), then runs the triage
    tools (DR and breakpad) if a crash is found.
    """
    global can_fuzz
    # TODO: Move try/except so we can start new runs after an exception
    try:
        while can_fuzz:
            crashed, run_id = fuzzer_run(config_dict)
            if crashed:
                formatted, _ = triage_run(config_dict, run_id)
                print_l(formatted)

                if config_dict['exit_early']:
                    # Prevent other threads from starting new fuzzing runs
                    can_fuzz = False

            if not config_dict['continuous']:
                return

    except Exception:
        traceback.print_exc()


def kill():
    """
    Ends a sequence of fuzzing runs.
    """
    global can_fuzz
    can_fuzz = False
