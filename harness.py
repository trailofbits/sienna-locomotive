"""
Fuzzing harness for DynamoRIO client. Imports fuzzer_config.py for argument and config file handling.
"""

import os
import concurrent.futures
import traceback
import subprocess
import json
import threading
from functools import reduce

print_lock = threading.Lock()
can_fuzz = True


def get_path_to_run_file(run_id, filename):
    """ Helper function for easily getting the full path to a file in the current run's directory """
    return reduce(os.path.join, [os.getenv('APPDATA'), 'Trail of Bits', 'fuzzkit', 'working', str(run_id), filename])


def configure_future_attributes(future, callback, **kwargs):
    """ Adds a completion callback and any custom attributes to a future """
    for key, item in kwargs.iteritems():
        setattr(future, key, item)
    future.add_done_callback(callback)
    return future


def run_dr(_config, save_stdout=False, save_stderr=False, verbose=False, timeout=None):
    """ Runs dynamorio with the given config. Clobbers console output if save_stderr/stdout are true """
    program_arr = [_config['drrun_path']] + _config['drrun_args'] + ['-c', _config['client_path']] + \
        _config['client_args'] + ['--', _config['target_application_path']] + _config['target_args']
    if verbose:
        with print_lock:
            print("Executing drrun: %s" % ' '.join(program_arr))
    completed_process = subprocess.run(program_arr,
                                       stdout=(subprocess.PIPE if save_stdout else None),
                                       stderr=(subprocess.PIPE if save_stderr else None),
                                       timeout=timeout)
    return completed_process


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
        print("Couldn't find an output directory for run %s" % run_id)


def wizard_run(_config):
    """ Runs the wizard and lets the user select a target function """
    completed_process = run_dr({'drrun_path': _config['drrun_path'],
                                'drrun_args': _config['drrun_args'],
                                'client_path': _config['wizard_path'],
                                'client_args': [],
                                'target_application_path': _config['target_application_path'],
                                'target_args': _config['target_args']},
                               save_stdout=False,
                               save_stderr=True,
                               verbose=_config['verbose'])
    wizard_output = completed_process.stderr.decode('utf-8')
    wizard_findings = []
    for line in str.splitlines(wizard_output):
        if '<id:' in line:
            func_name = line.strip('<id: >').split(',')[0] + ',' + line.strip('<id: >').split(',')[-1]
            if func_name not in wizard_findings:
                wizard_findings.append(func_name)
    print(wizard_output)
    print("Functions found:")
    for i, func_name in enumerate(wizard_findings):
        print("{})".format(i), func_name)
    index = int(input("Choose a function to fuzz> "))
    _config['client_args'].append('-t')
    _config['client_args'].append(wizard_findings[index])
    return _config


def fuzzer_run(_config):
    """ Runs the fuzzer """
    completed_process = run_dr(_config, True, True, _config['verbose'], _config.get('fuzz_timeout', None))

    # Parse run ID from stderr)
    run_id = 'ERR'
    for line in str.splitlines(completed_process.stderr.decode('utf-8')):
        if 'Beginning fuzzing run' in line:
            run_id = int(line.replace('Beginning fuzzing run ', '').strip())
        # TODO validate the run ID

    # Start triage if the fuzzing harness exited with an error code
    if completed_process.returncode != 0:
        print('Fuzzing run %s returned %s' % (run_id, completed_process.returncode))
        # Write stdout and stderr to files
        # TODO figure out why proc.stdout is always empty
        # https://stackoverflow.com/questions/47038990/python-subprocess-cannot-capture-output-of-windows-program
        write_output_files(completed_process, run_id, 'fuzz')
    elif _config['verbose']:
        print("Run %d did not find a crash" % run_id)

    return (completed_process.returncode != 0), run_id


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
            with print_lock:
                print("Triage ({score}): {reason} in run {run_id} caused {exception}".format(**results))
                print("\t0x{location:02x}: {instruction}".format(**results))
    except FileNotFoundError:
        print("Triage run %s returned %s (no crash file found)" % (run_id, completed_process.returncode))


def fuzz_and_triage(_config):
    global can_fuzz
    while can_fuzz:
        crashed, run_id = fuzzer_run(_config)
        if crashed:
            triage_run(_config, run_id)

            if _config['exit_early']:
                can_fuzz = False

        if not _config['continuous']:
            return


def main():
    from fuzzer_config import config

    # Start the server if it's not already running
    if not os.path.isfile("\\\\.\\pipe\\fuzz_server"):
        subprocess.Popen(["powershell", "start", "powershell",
                          "{-NoExit", "-Command", "\"{}\"}}".format(config['server_path'])])

    # Run the wizard to select a target function
    if config['wizard']:
        config = wizard_run(config)

    # Spawn a thread that will run DynamoRIO and wait for the output
    with concurrent.futures.ThreadPoolExecutor(max_workers=config['simultaneous']) as executor:
        fuzz_futures = [executor.submit(fuzz_and_triage, config) for _ in range(config['runs'])]  # TODO - more reasonable number
        concurrent.futures.wait(fuzz_futures)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("Waiting for worker threads to exit...")
        can_fuzz = False
        raise
