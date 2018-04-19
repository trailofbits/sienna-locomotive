"""
Fuzzing harness for DynamoRIO client. Imports fuzzer_config.py for argument and config file handling.
"""

import concurrent.futures
import traceback
from subprocess import call
from fuzzer_config import config

def run_dr():
    return call([config['drrun_path'], '-c', config['client_path'], '--', config['target_application']] + config['target_args'])

# We can use a with statement to ensure threads are cleaned up promptly
with concurrent.futures.ThreadPoolExecutor(max_workers=config['simultaneous']) as executor:
    futures = [executor.submit(run_dr) for i in range(config['runs'])]
    for future in concurrent.futures.as_completed(futures, timeout=None):
        try:
            return_code = future.result()
        except Exception as e:
            print('fuzzing run generated an exception: %s' % (e))
            traceback.print_exc()
        else:
            print('fuzzing run returned %s' % (return_code))
