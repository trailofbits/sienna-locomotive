"""
Fuzzing harness for DynamoRIO client.
Imports harness/config.py for argument and config file handling.
Imports harness/state.py for utility functions.
"""

import os
import concurrent.futures
import json
import binascii
import atexit

import harness.config
from harness.state import get_target_dir, get_targets, get_runs, stringify_program_array
from harness.instrument import print_l, wizard_run, fuzzer_run, triage_run, start_server, fuzz_and_triage, kill


@atexit.register
def goodbye():
    print_l("Exit handler called")
    # We use os._exit instead of sys.exit here to make sure that we totally
    # kill the harness, even when inside of the non-main thread.
    os._exit(0)


def select_from_range(max_range, message):
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


def chunkify(x, size):
    """ Breaks bytes into chunks for hexdump """
    d, m = divmod(len(x), 16)
    for i in range(d):
        yield x[i*size:(i+1)*size]
    if m:
        yield x[d*size:]


def hexdump(x):
    for addy, d in enumerate(chunkify(x, 16)):
        print_l("%08X: %s" % (addy, binascii.hexlify(d).decode()))


def main():
    config = harness.config.config

    start_server()

    # If the user selected a single stage, do that instead of running anything else
    if 'stage' in config:
        # Re-run the wizard stage and dump the output in the target directory
        if config['stage'] == 'WIZARD':
            select_and_dump_wizard_findings(wizard_run(config), os.path.join(get_target_dir(config), 'targets.json'))
        # Parse the list of targets and select one to fuzz
        if config['stage'] == 'FUZZER':
            targets = get_targets()
            mapping = []
            for target in targets:
                print("{}) [{}]  {}".format(len(mapping),
                                            target[-40:][:8],
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
                                            run_id[-36:][:8],
                                            stringify_program_array(runs[run_id][0], runs[run_id][1])))
                mapping.append(run_id)
            run_id = mapping[select_from_range(len(mapping), "Select a run to triage> ")]
            config['target_application_path'], config['target_args'] = runs[run_id]
            config['client_args'].append('-t')
            config['client_args'].append(os.path.join(get_target_dir(config), 'targets.json'))  # TODO make this less hacky
            triage_run(config, run_id[-36:])
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
        kill()
        raise
