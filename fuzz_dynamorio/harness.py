"""
Fuzzing harness for DynamoRIO client. Imports fuzzer_config.py for argument and config file handling.
"""

import os
import concurrent.futures
import traceback
import subprocess

def run_dr(_config):
    program_arr = [_config['drrun_path'], '-c', _config['client_path']] + _config['client_args'] + ['--', _config['target_application']] + _config['target_args']
    return subprocess.call(program_arr)

def main():
    from fuzzer_config import config

    # Start the server if it's not already running
    if not os.path.isfile("\\\\.\\pipe\\fuzz_server"):
        pid = subprocess.Popen([config['server_path']], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).pid
        print("Server running in process {}".format(pid))

    # Spawn a thread that will run DynamoRIO and wait for the output
    with concurrent.futures.ThreadPoolExecutor(max_workers=config['simultaneous']) as executor:
        futures = [executor.submit(run_dr, config) for i in range(config['runs'])]
        for future in concurrent.futures.as_completed(futures, timeout=None):
            try:
                return_code = future.result()
            except Exception as e:
                print('fuzzing run generated an exception: %s' % (e))
                traceback.print_exc()
            else:
                print('fuzzing run returned %s' % (return_code))

if __name__ == '__main__':
    main()
