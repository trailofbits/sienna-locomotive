## @package instrument
# Instrumentation functions for running DynamoRIO client & the fuzzing server
# Imports harness/config.py for argument and config file handling.
# Imports harness/state.py for fuzzing lifecycle management
# Imports harness/enums.py for the targeting mode enum


import array
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback
from enum import IntEnum

import msgpack

from sl2.db import Crash, Tracer
from sl2.db.run_block import SessionManager
from . import config
from . import named_mutex
from .state import (
    parse_tracer_crash_files,
    generate_run_id,
    write_output_files,
    create_invocation_statement,
    check_fuzz_line_for_crash,
    get_path_to_run_file,
    get_target_dir,
    get_target_slug,
)

print_lock = threading.Lock()
can_fuzz = True

## class Mode
#  Enum storing bit flags that control how the fuzzer and tracer target functions
class Mode(IntEnum):
    """
    Function selection modes.
    KEEP THIS UP-TO-DATE with common/enums.h
    """

    ## Match the number of times a given target-able function has been called
    MATCH_INDEX = 1 << 0
    ## Match the return address of the targetable function
    MATCH_RETN_ADDRESS = 1 << 1
    ## Match the hash of the arguments of the function
    MATCH_ARG_HASH = 1 << 2
    ## Match the bytewise comparison of the argument buffer
    MATCH_ARG_COMPARE = 1 << 3
    ## Hybrid algorithm - fuzzy
    LOW_PRECISION = 1 << 4
    ## Hybrid algorithm - precise, can be applied to multiple instances of identical calls
    MEDIUM_PRECISION = 1 << 5
    ## Hybrid algorithm - precise, can only be applied once
    HIGH_PRECISION = 1 << 6
    ## Match a comparison of the filename (if available)
    MATCH_FILENAMES = 1 << 7
    ## Match the number of times the client has encountered a given return address
    MATCH_RETN_COUNT = 1 << 8


## Named tuple for storing information about a call to run_dr
class DRRun(object):
    """
    Represents the state returned by a call to run_dr.
    """

    def __init__(self, process, seed, run_id, coverage=None):
        self.process: subprocess.Popen = process
        self.seed: str = seed
        self.run_id: str = run_id
        self.coverage: dict = coverage


## Safe printing
#  TODO - we should switch to the logging module to make this simpler
def print_l(*args):
    """
    Prints the given arguments in a thread-safe manner.
    """
    with print_lock:
        print(*args)


def perror(*args):
    print_l("[E]", *args)


def pwarning(*args):
    print_l("[W]", *args)


## Run a command in a powershell wrapper so a new window pops up
def ps_run(command, close_on_exit=False):
    """
    Runs the given command in a new PowerShell session.
    """
    if close_on_exit:
        subprocess.Popen(["powershell", "start", "powershell", "{", "-Command", '"{}"}}'.format(command)])
    else:
        subprocess.Popen(["powershell", "start", "powershell", "{-NoExit", "-Command", '"{}"}}'.format(command)])


## Run the server in a new powershell window, if it's not already running
def start_server(close_on_exit=False):
    """
    Start the server, if it's not already running.
    """
    # NOTE(ww): This is technically a TOCTOU, but it's probably reliable enough for our purposes.
    server_cmd = " ".join([config.config["server_path"], *config.config["server_args"]])
    if named_mutex.test_named_mutex("fuzz_server_mutex"):
        ps_run(server_cmd, close_on_exit=close_on_exit)
    named_mutex.spin_named_mutex("fuzz_server_mutex")


## Helper for arbitrary runs of dynamorio - wizard, fuzzer, and tracer
#  @param config_dict - a set of key:value pairs from the config module
#  @param verbose - verbosity level
#  @param timeout - number of seconds to wait before killing drrun
#  @param run_id - specify the run id to pass to the client
#  @param tracing - indicate whether this run is a tracer run
def run_dr(config_dict, verbose=0, timeout=None, run_id=None, tracing=False):
    """
    Runs dynamorio with the given config.
    Clobbers console output if save_stderr/stdout are true.
    Returns a DRRun instance containing the popen object and PRNG seed
    used during the run.
    """
    fuzzing = run_id and not tracing
    invoke = create_invocation_statement(config_dict, run_id)

    if verbose:
        print_l("Executing drrun: %s" % invoke.cmd_str)

    # Run client on target application
    started = time.time()

    stdout = sys.stdout if (verbose > 1) or config_dict["inline_stdout"] else subprocess.PIPE
    stderr = subprocess.PIPE
    popen_obj = subprocess.Popen(invoke.cmd_arr, stdout=stdout, stderr=stderr)

    try:
        stdout, stderr = popen_obj.communicate(timeout=timeout)

        if verbose:
            print_l("Process completed after %s seconds" % (time.time() - started))

        # Overwrite fields on the object we return to make stdout/stderr the right type
        popen_obj.stdout = stdout
        popen_obj.stderr = stderr
        popen_obj.timed_out = False

        if verbose > 1:
            try:
                print_l(popen_obj.stderr.decode(sys.stderr.encoding))
            except UnicodeDecodeError:
                pass

        return DRRun(popen_obj, invoke.seed, run_id)

    # Handle cases where the program didn't exit in time
    except subprocess.TimeoutExpired:
        if verbose:
            print_l("Process Timed Out after %s seconds" % (time.time() - started))

        if run_id:
            pids_file = get_path_to_run_file(run_id, "trace.pids" if tracing else "fuzz.pids")

            try:
                with open(pids_file, "rb") as pids_contents:
                    for line in pids_contents.read().decode("utf-16").split("\n"):
                        if line:
                            # TODO(ww): We probably want to call finalize() once per pid here,
                            # since each pid has its own session/thread on the server.
                            pid = int(line)
                            if verbose:
                                print_l("Killing child process:", pid)
                            try:
                                # If we're fuzzing or triaging, try a "soft" kill with taskkill:
                                # taskkill will send a WM_CLOSE before anything else,
                                # which will hopefully kill the client more gently
                                # than a "hard" os.kill (which will prevent the client's
                                # exit handlers from running).
                                # TODO(ww): Replace this with a direct WM_CLOSE message.
                                if fuzzing or tracing:
                                    os.system("taskkill /T /PID {}".format(pid))
                                else:
                                    os.kill(pid, signal.SIGTERM)
                            except PermissionError as e:
                                pwarning("Couldn't kill child process (insufficient privilege?):", e)
                                pwarning("Try running the harness as an Administrator.")
                            except OSError as e:
                                pwarning("Couldn't kill child process (maybe already dead?):", e)
            except FileNotFoundError:
                perror("The PID file was missing so we couldn't kill the child process.")
                perror("Most likely this is due to a server crash.")
                run_id = -1
        else:
            pwarning("No run ID, so not looking for PIDs to kill.")

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
            popen_obj.stdout = "ERROR".encode("utf-8")
            popen_obj.stderr = json.dumps({"exception": "EXCEPTION_SL2_TIMEOUT"}).encode("utf-8")

        popen_obj.timed_out = True

    return DRRun(popen_obj, invoke.seed, run_id)


## Executes a Triage run
# Runs the sl2 triager on each of the minidumps generated
# by a fuzzing run.  The information that gets returned
# can't be used across threads so we end up fetching it from the db in the gui
# @param cfg Configuration context dictionary
# @param run_id Run ID (guid)
def triager_run(cfg, run_id):
    tracerOutput, _ = tracer_run(cfg, run_id)

    if tracerOutput:
        crashInfo = Crash.factory(run_id, get_target_slug(cfg), cfg["target_application_path"])
        return {"run_id": run_id, "tracerOutput": tracerOutput, "crashInfo": crashInfo}
    else:
        return None


## Runs the wizard and lets the user select a target function.
#  @return wizard_findings: List[Dict] - list of targetable functions
def wizard_run(config_dict):
    run = run_dr(
        {
            "drrun_path": config_dict["drrun_path"],
            "drrun_args": config_dict["drrun_args"],
            "client_path": config_dict["wizard_path"],
            "client_args": config_dict["client_args"],
            "target_application_path": config_dict["target_application_path"],
            "target_args": config_dict["target_args"],
            "inline_stdout": config_dict["inline_stdout"],
        },
        verbose=config_dict["verbose"],
    )

    wizard_findings = []
    mem_map = {}
    base_addr = None

    for line in run.process.stderr.split(b"\n"):
        try:
            line = line.decode("utf-8")

            if re.match(r"ERROR: Target process .* is for the wrong architecture", line):
                perror("Bad architecture for target application:", config_dict["target_application_path"])
                return []

            obj = json.loads(line)

            if "map" == obj["type"]:
                mem_map[(obj["start"], obj["end"])] = obj["mod_name"]
                if ".exe" in obj["mod_name"]:
                    base_addr = obj["start"]
            elif "id" == obj["type"]:
                obj["mode"] = Mode.HIGH_PRECISION
                obj["selected"] = False
                ret_addr = obj["retAddrOffset"] + base_addr
                for addrs in mem_map.keys():
                    if ret_addr in range(*addrs):
                        obj["called_from"] = mem_map[addrs]

                wizard_findings.append(obj)
        except UnicodeDecodeError:
            if config_dict["verbose"]:
                pwarning("Not UTF-8:", repr(line))
        except json.JSONDecodeError:
            pass
        except Exception as e:
            perror("Unexpected exception:", e)

    return wizard_findings


## Runs the fuzzer with a given config dict and targets file.
#  @return (crashed, run): Tuple(bool, DRRun) - whether the program crashed, and the run metadata
def fuzzer_run(config_dict, targets_file):
    """ Runs the fuzzer """

    if not os.path.isfile(targets_file):
        perror("Nonexistent targets file:", targets_file)

    with open(targets_file, "rb") as targets_msg:
        targets = msgpack.load(targets_msg)

    hasher = hashlib.sha256()
    hasher.update(targets_file.encode("utf-8"))

    for target in targets:
        if not target[b"selected"]:
            pass
        # Together with the semiunique targets_file name above, this should
        # be enough entropy to avoid arena collisions.
        hasher.update(target[b"argHash"])
        hasher.update(array.array("B", target[b"buffer"]))
        hasher.update(target[b"func_name"])

    arena_id = hasher.hexdigest()

    # Generate a run ID and hand it to the fuzzer.
    run_id = generate_run_id(config_dict)

    run = run_dr(
        {
            "drrun_path": config_dict["drrun_path"],
            "drrun_args": config_dict["drrun_args"],
            "client_path": config_dict["client_path"],
            "client_args": [*config_dict["client_args"], "-r", str(run_id), "-a", arena_id],
            "target_application_path": config_dict["target_application_path"],
            "target_args": config_dict["target_args"],
            "inline_stdout": config_dict["inline_stdout"],
        },
        verbose=config_dict["verbose"],
        timeout=config_dict.get("fuzz_timeout", None),
        run_id=run_id,
        tracing=False,
    )

    # Parse crash status from the output.
    crashed = False
    coverage_info = None

    for line in run.process.stderr.split(b"\n"):
        try:
            line = line.decode("utf-8")

            # Identify whether the fuzzing run resulted in a crash
            if not crashed:
                crashed, exception = check_fuzz_line_for_crash(line)

            if "#COVERAGE:" in line:
                coverage_info = json.loads(line.replace("#COVERAGE:", ""))
        except UnicodeDecodeError:
            if config_dict["verbose"]:
                perror("Not UTF-8:", repr(line))

    run = DRRun(run.process, run.seed, run.run_id, coverage_info)

    if crashed:
        print_l("Fuzzing run %s returned %s after raising %s" % (run_id, run.process.returncode, exception))
        write_output_files(run, run_id, "fuzz")
    elif config_dict["preserve_runs"]:
        print_l("Preserving run %s without a crash (requested)" % run_id)
        write_output_files(run, run_id, "fuzz")
    else:
        if config_dict["verbose"]:
            print_l("Run %s did not find a crash" % run_id)
        shutil.rmtree(os.path.join(config.sl2_runs_dir, str(run_id)), ignore_errors=True)

    return crashed, run


## Runs the triaging tool
# Triage includes the tracer, exploitability, and crashash generation
# @param config_dict Configuration context dictionary
# @param run_id Run ID (guid)
def tracer_run(config_dict, run_id):
    run = run_dr(
        {
            "drrun_path": config_dict["drrun_path"],
            "drrun_args": config_dict["drrun_args"],
            "client_path": config_dict["tracer_path"],
            "client_args": [*config_dict["client_args"], "-r", str(run_id)],
            "target_application_path": config_dict["target_application_path"],
            "target_args": config_dict["target_args"],
            "inline_stdout": config_dict["inline_stdout"],
        },
        config_dict["verbose"],
        config_dict.get("tracer_timeout", None),
        run_id=run_id,
    )

    # Write stdout and stderr to files
    write_output_files(run, run_id, "trace")

    success = False
    message = None

    for line in run.process.stderr.split(b"\n"):
        try:
            obj = json.loads(line.decode("utf-8"))

            if obj["run_id"] == str(run_id) and "success" in obj:
                success = obj["success"]
                message = obj["message"]
                break
        except Exception:
            pass

    if success:
        formatted, raw = parse_tracer_crash_files(run_id)
        if raw is not None:
            Tracer.factory(run_id, formatted, raw)
        return formatted, raw
    else:
        perror("Tracer failure:", message)
        return None, None


## Fuzzing run followed by triage
# Runs the fuzzer (in a loop if continuous is true), then runs the triage
# tools (DR tracer and breakpad) if a crash is found.
# @param config_dict Configuration context dictionary
# @param run_id Run ID (guid)
def fuzz_and_triage(config_dict):
    global can_fuzz

    targets_file = os.path.join(get_target_dir(config_dict), "targets.msg")

    # TODO: Move try/except so we can start new runs after an exception
    with SessionManager(get_target_slug(config_dict)) as manager:
        while can_fuzz:
            try:
                crashed, run = fuzzer_run(config_dict, targets_file)
                manager.run_complete(run, found_crash=crashed)

                if crashed:

                    triagerInfo = triager_run(config_dict, run.run_id)

                    if triagerInfo:
                        print_l(triagerInfo)
                    else:
                        perror("Triage failure?")

                    if config_dict["exit_early"]:
                        # Prevent other threads from starting new fuzzing runs
                        can_fuzz = False

                if run.run_id == -1:
                    start_server()

                if not config_dict["continuous"]:
                    return

            except Exception:
                traceback.print_exc()


def kill():
    """
    Ends a sequence of fuzzing runs.
    """
    global can_fuzz
    can_fuzz = False
