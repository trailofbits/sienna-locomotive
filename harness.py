"""
Fuzzing harness for DynamoRIO client. Imports fuzzer_config.py for argument and config file handling.
"""

import os
import concurrent.futures
import traceback
import subprocess
import json

def run_dr(_config, save_stdout=False, save_stderr=False, verbose=False):
    program_arr = [_config['drrun_path']] + _config['drrun_args'] + ['-c', _config['client_path']] + _config['client_args'] + ['--', _config['target_application']] + _config['target_args']
    if verbose:
        print("Executing drrun: %s" % ' '.join(program_arr))
    completed_process = subprocess.run(program_arr, stdout=(subprocess.PIPE if save_stdout else None), stderr=(subprocess.PIPE if save_stderr else None))
    return completed_process

def main():
    from fuzzer_config import config, get_path_to_run_file

    # Run the wizard to select a target function
    if config['wizard']:
        completed_process = run_dr({'drrun_path': config['drrun_path'], \
                                    'drrun_args': config['drrun_args'], \
                                    'client_path': config['wizard_path'], \
                                    'client_args': [], \
                                    'target_application': config['target_application'], \
                                    'target_args': config['target_args']}, save_stdout=False, save_stderr=True, verbose=config['verbose'])
        wizard_output = completed_process.stderr.decode('utf-8')
        wizard_findings = set()
        for line in str.splitlines(wizard_output):
            if '<id:' in line:
                func_name = line.split('<id: ')[0].split(',')[0] + ',' + line.replace(">","").split(',')[-1]
                wizard_findings.add(func_name)
        wizard_findings = list(wizard_findings)
        print(wizard_output)
        print("Functions found:")
        for i, func_name in enumerate(wizard_findings):
            print("{})".format(i), func_name)
        index = int(input("Choose a function to fuzz> "))
        config['client_args'].append('-t')
        config['client_args'].append(wizard_findings[index])

    # Start the server if it's not already running
    if not os.path.isfile("\\\\.\\pipe\\fuzz_server"):
        pid = subprocess.Popen([config['server_path']], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).pid
        print("Server running in process {}".format(pid))

    # Spawn a thread that will run DynamoRIO and wait for the output
    with concurrent.futures.ThreadPoolExecutor(max_workers=config['simultaneous']) as executor:
        fuzz_futures = [executor.submit(run_dr, config, False, True, config['verbose']) for i in range(config['runs'])]
        triage_futures = []

        # Handle futures created for fuzzing
        for future in concurrent.futures.as_completed(fuzz_futures, timeout=None):
            try:
                proc = future.result()
            except Exception as e:
                print('fuzzing run generated an exception: %s' % (e))
                traceback.print_exc()
            else:
                # Parse run ID from stderr
                run_id = 'ERR'
                for line in str.splitlines(proc.stderr.decode('utf-8')):
                    if 'Beginning fuzzing run' in line:
                        run_id = int(line.replace('Beginning fuzzing run ', '').strip())

                # Write stdout and stderr to files
                # https://stackoverflow.com/questions/47038990/python-subprocess-cannot-capture-output-of-windows-program
                if proc.stdout is not None: # TODO: figure out why proc.stdout is always empty
                    with open(get_path_to_run_file(run_id, 'fuzz.stdout'), 'wb') as stdoutfile:
                                stdoutfile.write(proc.stdout)
                if proc.stderr is not None:
                    with open(get_path_to_run_file(run_id, 'fuzz.stderr'), 'wb') as stderrfile:
                        stderrfile.write(proc.stderr)

                # Start triage if the fuzzing harness exited with an error code
                if proc.returncode != 0:
                    print('Fuzzing run %s returned %s' % (run_id, proc.returncode))
                    triage_config = {'drrun_path': config['drrun_path'], \
                                    'drrun_args': config['drrun_args'], \
                                    'client_path': config['triage_path'], \
                                    'client_args': ['-r', str(run_id)], \
                                    'target_application': config['target_application'], \
                                    'target_args': config['target_args']}
                    triage_future = executor.submit(run_dr, triage_config, True, True, verbose=config['verbose'])
                    setattr(triage_future, "run_id", run_id) # Bind run id to the future so it's easier to find next time
                    triage_futures.append(triage_future)

        # Handle futures created for triaging
        for future in concurrent.futures.as_completed(triage_futures, timeout=None):
            try:
                proc = future.result()
            except Exception as e:
                print('Triage run generated an exception: %s' % (e))
                traceback.print_exc()
            else:
                run_id = future.run_id

                # Write stdout and stderr to files
                if proc.stdout is not None:
                    with open(get_path_to_run_file(run_id, 'triage.stdout'), 'wb') as stdoutfile:
                        stdoutfile.write(proc.stdout)
                if proc.stderr is not None:
                    with open(get_path_to_run_file(run_id, 'triage.stderr'), 'wb') as stderrfile:
                        stderrfile.write(proc.stderr)

                # Parse triage results and print them
                with open(get_path_to_run_file(run_id, 'crash.json'), 'r') as crash_json:
                    results = json.loads(crash_json.read())
                    results['run_id'] = run_id
                    print("Triage ({score}): {reason} in run {run_id} caused {exception}".format(**results))
                    print("\t0x{location:02x}: {instruction}".format(**results))

if __name__ == '__main__':
    main()
