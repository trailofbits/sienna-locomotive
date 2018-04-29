"""
Fuzzing harness for DynamoRIO client. Imports fuzzer_config.py for argument and config file handling.
"""

import os
import concurrent.futures
import traceback
import subprocess

def run_dr(_config, save_stdout=False, save_stderr=False):
    program_arr = [_config['drrun_path']] + _config['drrun_args'] + ['-c', _config['client_path']] + _config['client_args'] + ['--', _config['target_application']] + _config['target_args']
    completed_process = subprocess.run(program_arr, stdout=(subprocess.PIPE if save_stdout else None), stderr=(subprocess.PIPE if save_stderr else None))
    return completed_process

def main():
    from fuzzer_config import config

    if config['wizard']:
        completed_process = run_dr({'drrun_path': config['drrun_path'], \
                                    'drrun_args': config['drrun_args'], \
                                    'client_path': config['wizard_path'], \
                                    'client_args': [], \
                                    'target_application': config['target_application'], \
                                    'target_args': config['target_args']}, save_stdout=False, save_stderr=True)
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
        futures = [executor.submit(run_dr, config) for i in range(config['runs'])]
        for future in concurrent.futures.as_completed(futures, timeout=None):
            try:
                proc = future.result()
            except Exception as e:
                print('fuzzing run generated an exception: %s' % (e))
                traceback.print_exc()
            else:
                print('fuzzing run returned %s' % (proc.returncode))

if __name__ == '__main__':
    main()
