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
    program_arr = [_config['drrun_path'], '-pidfile', 'pidfile'] + _config['drrun_args'] + ['-c', _config['client_path']] + \
        _config['client_args'] + ['--', _config['target_application_path']] + _config['target_args']
    if verbose:
        with print_lock:
            print("Executing drrun: %s" % ' '.join(program_arr))

    started = time.time()
    popen_obj = subprocess.Popen(program_arr, stdout=(subprocess.PIPE if save_stdout else None), stderr=(subprocess.PIPE if save_stderr else None))

    try:
        stdout, stderr = popen_obj.communicate(timeout=timeout)
        if verbose:
            print("Process completed after %s seconds" % (time.time() - started))
        popen_obj.stdout = stdout
        popen_obj.stderr = stderr
        popen_obj.timed_out = False
        return popen_obj
    except subprocess.TimeoutExpired:
        if verbose:
            print("Process Timed Out after %s seconds" % (time.time() - started))
        with open('pidfile', 'r') as pidfile:
            pid = pidfile.read().strip()
            if verbose:
                print("Killing child process:", pid)
            os.kill(int(pid), signal.SIGTERM)
        try:
            stdout, stderr = popen_obj.communicate(timeout=5)  # Try to grab the existing console output
            popen_obj.stdout = stdout
            popen_obj.stderr = stderr
        except subprocess.TimeoutExpired:
            if verbose:
                print("Caused the target application to hang")
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
        print("Couldn't find an output directory for run %s" % run_id)


def finalize(run_id, crashed):
    f = open("\\\\.\\pipe\\fuzz_server", 'w+b', buffering=0)
    f.write(struct.pack('B', 0x4))
    f.seek(0)
    f.write(struct.pack('I', run_id))
    f.seek(0)
    f.write(struct.pack('?', 1 if crashed else 0))
    f.close()


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
    for line in str.splitlines(sections[0]):
        if '<wrapped ' in line:
            re.search(r"<wrapped (?P<func_name>\S+) @ (?P<address>\S+) in (?P<module>\S+)", line).groupdict()  # TODO use
    for section in sections[1:]:
        results = {'index': -123, 'func_name': 'PARSE ERROR', 'hexdump_lines': []}
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
        if not any((lambda l, r: l['index'] == r['index'] and l['func_name'] == r['func_name'])(results, finding) for finding in wizard_findings):
            if 'ERROR' not in results['func_name']:
                wizard_findings.append(results)
    print("Functions found:")
    for i, finding in enumerate(wizard_findings):
        if 'source' in finding:
            print("{}) {func_name} from {source}:{start}-{end}".format(i, **finding))
        else:
            print("{}) {func_name}".format(i, **finding))
        print("   ", '\n   '.join(line for line in finding['hexdump_lines'][:4]))
        if len(finding['hexdump_lines']) > 4:
            print("   ...")
    index = int(input("Choose a function to fuzz> "))
    _config['client_args'].append('-t')
    _config['client_args'].append("{},{}".format(wizard_findings[index]['index'], wizard_findings[index]['func_name']))
    return _config


def fuzzer_run(_config):
    """ Runs the fuzzer """
    completed_process = run_dr(_config, True, True, verbose=_config['verbose'], timeout=_config.get('fuzz_timeout', None))
    run_id = 'ERR'
    proc_stderr = completed_process.stderr.decode('utf-8')
    for line in str.splitlines(proc_stderr):
        if 'Beginning fuzzing run' in line:
            run_id = int(line.replace('Beginning fuzzing run ', '').strip())
    if run_id == 'ERR':
        print("Error: No run ID could be parsed from the server output")
        return False, -1

    # Start triage if the fuzzing harness exited with an error code
    if 'EXCEPTION_' in proc_stderr:
        print('Fuzzing run %s returned %s' % (run_id, completed_process.returncode))
        # Write stdout and stderr to files
        # TODO figure out why proc.stdout is always empty
        # https://stackoverflow.com/questions/47038990/python-subprocess-cannot-capture-output-of-windows-program
        write_output_files(completed_process, run_id, 'fuzz')
    elif _config['verbose']:
        print("Run %d did not find a crash" % run_id)
    if completed_process.timed_out:
        if 'EXCEPTION_' in proc_stderr:
            finalize(run_id, True)
        else:
            finalize(run_id, False)

    return ('EXCEPTION_' in proc_stderr), run_id


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
    try:
        while can_fuzz:
            crashed, run_id = fuzzer_run(_config)
            if crashed:
                triage_run(_config, run_id)

                if _config['exit_early']:
                    can_fuzz = False

            if not _config['continuous']:
                return
    except Exception:
        traceback.print_exc()


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
