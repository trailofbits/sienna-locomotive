"""
Fuzzing harness for DynamoRIO client. Imports fuzzer_config.py for argument and config file handling.
"""

import os
import concurrent.futures
import re
import subprocess
import json
import traceback
import threading
import time
import signal
import struct
import json
import uuid

import fuzzer_config
from state import get_target_dir, get_targets

print_lock = threading.Lock()
can_fuzz = True


def print_l(*args):
    """ Thread safe print """
    with print_lock:
        print(*args)


def get_path_to_run_file(run_id, filename):
    """ Helper function for easily getting the full path to a file in the current run's directory """
    return os.path.join(fuzzer_config.sl2_dir, 'working', str(run_id), filename)


def run_dr(_config, save_stdout=False, save_stderr=False, verbose=False, timeout=None):
    """ Runs dynamorio with the given config. Clobbers console output if save_stderr/stdout are true """
    program_arr = [_config['drrun_path'], '-pidfile', 'pidfile'] + _config['drrun_args'] + \
        ['-c', _config['client_path']] + _config['client_args'] + \
        ['--', _config['target_application_path']] + _config['target_args']

    if verbose:
        print_l("Executing drrun: %s" % ' '.join((k if " " not in k else "\"{}\"".format(k)) for k in program_arr))

    # Run client on target application
    started = time.time()
    popen_obj = subprocess.Popen(program_arr,
                                 stdout=(subprocess.PIPE if save_stdout else None),
                                 stderr=(subprocess.PIPE if save_stderr else None))

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


def write_output_files(proc, run_id, stage_name):
    """ Writes the stdout and stderr buffers for a run into the working directory """
    try:
        if proc.stdout is not None:
            with open(get_path_to_run_file(run_id, '{}.stdout'.format(stage_name)), 'wb') as stdoutfile:
                stdoutfile.write(proc.stdout)
        if proc.stderr is not None:
            with open(get_path_to_run_file(run_id, '{}.stderr'.format(stage_name)), 'wb') as stderrfile:
                stderrfile.write(proc.stderr)
    except FileNotFoundError:
        print_l("Couldn't find an output directory for run %s" % run_id)


def finalize(run_id, crashed):
    """ Manually closes out a fuzzing run. Only necessary if we killed the target binary before DynamoRIO could
    close out the run """
    f = open("\\\\.\\pipe\\fuzz_server", 'w+b', buffering=0)
    f.write(struct.pack('B', 0x4))  # Write the event ID (4)
    f.seek(0)
    f.write(run_id.bytes)  # Write the run ID
    f.seek(0)
    f.write(struct.pack('?', 1 if crashed else 0))  # Write a bool indicating a crash
    f.close()


def select_and_dump_wizard_findings(wizard_findings, target_file):
    """ Print and select findings, then write to disk """
    print_l("Functions found:")
    for i, finding in enumerate(wizard_findings):
        if 'source' in finding:
            print_l("{}) {func_name} from {source}:{start}-{end}".format(i, **finding))
        else:
            print_l("{}) {func_name}".format(i, **finding))
        print_l("   ", '\n   '.join(line for line in finding['hexdump_lines'][:4]))
        if len(finding['hexdump_lines']) > 4:
            print_l("   ...")

    # Let the user select a finding, add it to the config
    index = -1
    done = False
    while not done:
        try:
            index = int(input("Choose a function to fuzz> "))
        except ValueError:
            pass
        if index not in range(len(wizard_findings)):
            print_l("Function number is invalid.")
        else:
            done = True
    wizard_findings[index]['selected'] = True

    with open(target_file, 'w') as json_file:
        json.dump(wizard_findings, json_file)

    return wizard_findings


def wizard_run(_config):
    """ Runs the wizard and lets the user select a target function """
    completed_process = run_dr({'drrun_path': _config['drrun_path'],
                                'drrun_args': _config['drrun_args'],
                                'client_path': _config['wizard_path'],
                                'client_args': [],
                                'target_application_path': _config['target_application_path'],
                                'target_args': _config['target_args']},
                               save_stdout=True,
                               save_stderr=True,
                               verbose=_config['verbose'])
    wizard_output = completed_process.stderr.decode('utf-8')
    wizard_findings = []
    sections = re.split(r"--------\n", wizard_output)

    # Enumerate wrapped functions -- TODO use
    for line in str.splitlines(sections[0]):
        if '<wrapped ' in line:
            re.search(r"<wrapped (?P<func_name>\S+) @ (?P<address>\S+) in (?P<module>\S+)", line).groupdict()

    # Get function names, ID's, and contents, if applicable
    for section in sections[1:]:
        # Create result dict from parsing applicable lines
        results = {'index': -123, 'func_name': 'PARSE ERROR', 'hexdump_lines': [], 'selected': False}
        for line in section.splitlines():
            if '<id:' in line:
                results.update(re.search(r"<id: (?P<index>\d+),(?P<func_name>\S+)>", line).groupdict())
            elif 'source:' in line:
                results.update(re.search(r"source: (?P<source>[\S ]+)", line).groupdict())
            elif 'range:' in line:
                results.update(re.search(r"range: (?P<start>\S+),(?P<end>\S+)", line).groupdict())
            else:
                if len(line.strip()) > 0:
                    results['hexdump_lines'].append(line.strip())

        # Add function to wizard findings if it's not already there
        if not any((lambda l, r: l['index'] == r['index'] and l['func_name'] == r['func_name'])(results, finding)
                   for finding in wizard_findings):
            if 'ERROR' not in results['func_name']:
                wizard_findings.append(results)

        results['index'] = int(results['index'])

    return wizard_findings


def fuzzer_run(_config):
    """ Runs the fuzzer """
    completed_process = run_dr(_config, True, True,
                               verbose=_config['verbose'], timeout=_config.get('fuzz_timeout', None))

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
    elif _config['verbose']:
        print_l("Run %s did not find a crash" % run_id)

    # Handle orphaned pipes after a timeout
    if completed_process.timed_out:
        if crashed:
            finalize(run_id, True)
        else:
            finalize(run_id, False)

    return crashed, run_id


def triage_run(_config, run_id):
    """ Runs the triaging tool """
    completed_process = run_dr({'drrun_path': _config['drrun_path'],
                                'drrun_args': _config['drrun_args'],
                                'client_path': _config['triage_path'],
                                'client_args': _config['client_args'] + ['-r', str(run_id)],
                                'target_application_path': _config['target_application_path'],
                                'target_args': _config['target_args']},
                               True,
                               True,
                               _config['verbose'],
                               _config.get('triage_timeout', None))

    # Write stdout and stderr to files
    write_output_files(completed_process, run_id, 'triage')

    # Parse triage results and print them
    try:
        with open(get_path_to_run_file(run_id, 'crash.json'), 'r') as crash_json:
            results = json.loads(crash_json.read())
            results['run_id'] = run_id
            print_l("Triage ({score}): {reason} in run {run_id} caused {exception}".format(**results))
            print_l("\t0x{location:02x}: {instruction}".format(**results))
    except FileNotFoundError:
        print_l("Triage run %s returned %s (no crash file found)" % (run_id, completed_process.returncode))


def fuzz_and_triage(_config):
    """ Runs the fuzzer (in a loop if continuous is true), then runs the triage tool if a crash is found """
    global can_fuzz
    # TODO: Move try/except so we can start new runs after an exception
    try:
        while can_fuzz:
            crashed, run_id = fuzzer_run(_config)
            if crashed:
                triage_run(_config, run_id)

                if _config['exit_early']:
                    can_fuzz = False  # Prevent other threads from starting new fuzzing runs

            if not _config['continuous']:
                return

    except Exception:
        traceback.print_exc()


def main():
    config = fuzzer_config.config

    # Start the server if it's not already running
    if not os.path.isfile("\\\\.\\pipe\\fuzz_server"):
        subprocess.Popen(["powershell", "start", "powershell",
                          "{-NoExit", "-Command", "\"{}\"}}".format(config['server_path'])])

    if 'stage' in config:
        if config['stage'] == 'WIZARD':
            select_and_dump_wizard_findings(wizard_run(config), os.path.join(get_target_dir(config), 'targets.json'))
        if config['stage'] == 'FUZZER':
            pass
            # select target
            # update config with selections from target
            # fuzzer_run(config)
        if config['stage'] == 'TRIAGE':
            pass
            # select run id
            # Update triage run with config from run id
            # triage_run(config, run_id)
        return

    # Run the wizard to select a target function if we don't have one saved
    target_file = os.path.join(get_target_dir(config), 'targets.json')
    if not os.path.exists(target_file):
        select_and_dump_wizard_findings(wizard_run(config), target_file)

    config['client_args'].append('-t')
    config['client_args'].append(target_file)

    # Spawn a thread that will run DynamoRIO and wait for the output
    with concurrent.futures.ThreadPoolExecutor(max_workers=config['simultaneous']) as executor:
        # If we're in continuous mode, spawn as many futures as we can run simultaneously.
        # Otherwise, spawn as many as we want to run in total
        fuzz_futures = [executor.submit(fuzz_and_triage, config)
                        for _ in range(config['runs'] if not config['continuous'] else config['simultaneous'])]

        # Wait for exit
        concurrent.futures.wait(fuzz_futures)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print_l("Waiting for worker threads to exit...")
        can_fuzz = False
        raise
