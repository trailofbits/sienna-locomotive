"""
Driver class for DynamoRIO client.
Imports harness/config.py for argument and config file handling.
Imports harness/state.py for managing the fuzzing lifecycle
Imports harness/instrument.py for running DynamoRIO instrumentation clients.
"""

import os
import concurrent.futures
import json
import atexit
import threading
import harness.config
import harness.statz
from harness.state import get_target_dir, get_targets, get_runs, stringify_program_array
from harness.instrument import print_l, wizard_run, fuzzer_run, triage_run, start_server, fuzz_and_triage, kill

print_lock = threading.Lock()
can_fuzz = True


@atexit.register
def goodbye():
    # We use os._exit instead of sys.exit here to make sure that we totally
    # kill the harness, even when inside of the non-main thread.
    kill()
    os._exit(0)



def print_l(*args):
    """ Thread safe print """
    with print_lock:
        print(*args)


def get_path_to_run_file(run_id, filename):
    """ Helper function for easily getting the full path to a file in the current run's directory """
    return os.path.join(harness.config.sl2_dir, 'working', str(run_id), filename)


def run_dr(_config, save_stdout=False, save_stderr=False, verbose=False, timeout=None, stats=harness.statz.Statz()):
    """ Runs dynamorio with the given config. Clobbers console output if save_stderr/stdout are true """
    program_arr = [_config['drrun_path'], '-pidfile', 'pidfile'] + _config['drrun_args'] + \
        ['-c', _config['client_path']] + _config['client_args'] + \
        ['--', _config['target_application_path']] + _config['target_args']

    if verbose:
        print_l("Executing drrun: %s" % ' '.join((k if " " not in k else "\"{}\"".format(k)) for k in program_arr))

    # Run client on target application
    popen_obj = subprocess.Popen(program_arr,
                                 stdout=(subprocess.PIPE if save_stdout else None),
                                 stderr=(subprocess.PIPE if save_stderr else None))

    stats.increment()
    # Try to get the output from the process, time out if necessary
    try:
        stdout, stderr = popen_obj.communicate(timeout=timeout)

        if verbose:
            print_l("Process completed: ", stats)

        # Overwrite fields on the object we return to make stdout/stderr the right type
        popen_obj.stdout = stdout
        popen_obj.stderr = stderr
        popen_obj.timed_out = False

        return popen_obj

    # Handle cases where the program didn't exit in time
    except subprocess.TimeoutExpired:
        if verbose:
            print_l("Process timed out: ", stats)

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
    f = open(harness.config.sl2_server_path, 'w+b', buffering=0)
    f.write(struct.pack('B', 0x4))  # Write the event ID (4)
    f.seek(0)
    f.write(run_id.bytes)  # Write the run ID
    f.seek(0)
    # Write a bool indicating a crash
    f.write(struct.pack('?', 1 if crashed else 0))
    # Write a bool indicating whether to preserve run files (without a crash)
    f.write(struct.pack('?', 1 if True else 0))
    f.close()



def select_from_range(max_range, message):
    """ Helper function for selecting an int between 0 and some value """
    index = -1
    while True:
        try:
            index = int(input(message))
        except ValueError:
            pass
        if index not in range(max_range):
            print_l("Invalid selection.")
        else:
            return index


def select_and_dump_wizard_findings(wizard_findings, target_file):
    """ Print and select findings, then write to disk """
    print_l("Functions found:")
    for i, finding in enumerate(wizard_findings):
        if 'source' in finding:
            print_l("{}) {func_name} from {source}:{start}-{end}".format(i, **finding))
        else:
            print_l("{}) {func_name}".format(i, **finding))
        buffer = bytearray(finding['buffer'])
        hexdump(buffer)

    # Let the user select a finding, add it to the config
    index = select_from_range(len(wizard_findings), "Choose a function to fuzz> ")
    wizard_findings[index]['selected'] = True

    with open(target_file, 'w') as json_file:
        json.dump(wizard_findings, json_file)

    return wizard_findings


def hexdump(buffer, lines=4, line_len=16):
    """ Dump buffer byte array to stdout """
    for address in range(0, len(buffer), line_len):
        if address > lines * 16:
            print_l('...')
            break
        hexstr = " ".join("{:02X}".format(c) for c in buffer[address:address + line_len])
        asciistr = "".join((chr(c) if c in range(31, 127) else '.') for c in buffer[address:address + line_len])
        print_l("%08X:  %s  | %s" % (address, hexstr + " "*(line_len*3 - len(hexstr)), asciistr))



def main():
    config = harness.config.config

    start_server()

    target_file = os.path.join(get_target_dir(config), 'targets.json')

    # If the user selected a single stage, do that instead of running anything else
    if 'stage' in config:
        # Re-run the wizard stage and dump the output in the target directory
        if config['stage'] == 'WIZARD':
            select_and_dump_wizard_findings(wizard_run(config), target_file)

        # Parse the list of targets and select one to fuzz
        if config['stage'] == 'FUZZER':
            targets = get_targets()
            mapping = []
            for target in targets:
                print("{}) [{}]  {}".format(len(mapping),
                                            target[-40:][:8],  # first 8 bytes of the SHA hash
                                            stringify_program_array(targets[target][0], targets[target][1])))
                mapping.append(target)
            target_id = mapping[select_from_range(len(mapping), "Select a target to fuzz> ")]
            config['target_application_path'], config['target_args'] = targets[target_id]
            config['client_args'].append('-t')
            config['client_args'].append(os.path.join(target_id, 'targets.json'))
            fuzzer_run(config)

        # Parse the list of run ID's and select one to triage
        if config['stage'] == 'TRIAGE':
            runs = get_runs()
            mapping = []
            for run_id in runs:
                print("{}) [{}]  {}".format(len(mapping),
                                            run_id[-36:][:8],  # first 8 bytes of the UUID
                                            stringify_program_array(runs[run_id][0], runs[run_id][1])))
                mapping.append(run_id)
            run_id = mapping[select_from_range(len(mapping), "Select a run to triage> ")]
            config['target_application_path'], config['target_args'] = runs[run_id]
            config['client_args'].append('-t')
            config['client_args'].append(target_file)
            triage_run(config, run_id[-36:])

    else:
        # Run the wizard to select a target function if we don't have one saved
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
        kill()
        raise
