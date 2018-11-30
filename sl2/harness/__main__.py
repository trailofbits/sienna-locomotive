"""
@package harness
Driver class for DynamoRIO client.
Imports harness/config.py for argument and config file handling.
Imports harness/state.py for managing the fuzzing lifecycle
Imports harness/instrument.py for running DynamoRIO instrumentation clients.
"""

import atexit
import concurrent.futures
import os
import signal
import sys

import msgpack

from .config import config
from .instrument import print_l, wizard_run, fuzzer_run, tracer_run, start_server, fuzz_and_triage, kill
from .state import sanity_checks, get_target_dir, get_all_targets, get_runs, stringify_program_array


## Call os.exit to totally kill the harness
@atexit.register
def goodbye():
    # We use os._exit instead of sys.exit here to make sure that we totally
    # kill the harness, even when inside of the non-main thread.
    kill()
    os._exit(0)


## Print exit message and exit
def interrupted(_signal, _frame):
    print_l("[!] Harness interrupted by Ctrl-C. Exiting.")
    goodbye()


## Helper function to select an int from a range
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


## Print and select findings, then write to disk
# This will happen if there weren't any hookable functions in the target,
# OR if the target's architecture isn't supported.
# Either way there isn't much we can do, so exit.
def select_and_dump_wizard_findings(wizard_findings, target_file):
    cfg = config

    if len(wizard_findings) == 0:
        print_l("[!] No wizard findings!")
        sys.exit()

    index = cfg["function_number"]
    if index in range(0, len(wizard_findings)):
        pass
    else:
        print_l("Functions found:")
        for i, finding in enumerate(wizard_findings):
            if "source" in finding:
                print_l("{}) {func_name} from {source}:{start}-{end}".format(i, **finding))
            else:
                print_l("{}) {func_name}".format(i, **finding))
            buffer = bytearray(finding["buffer"])
            hexdump(buffer)

        # Let the user select a finding, add it to the config
        index = select_from_range(len(wizard_findings), "Choose a function to fuzz> ")

    wizard_findings[index]["selected"] = True
    with open(target_file.replace("targets.msg", "all_targets.msg"), "wb") as msg_file:
        msgpack.dump(wizard_findings, msg_file)
    with open(target_file, "wb") as msg_file:
        msgpack.dump(list(filter(lambda k: k["selected"], wizard_findings)), msg_file)

    return wizard_findings


## Dump buffer byte array to stdout for user selection
def hexdump(buffer, lines=4, line_len=16):
    """ Dump buffer byte array to stdout """
    for address in range(0, len(buffer), line_len):
        if address > lines * line_len:
            print_l("...")
            break
        hexstr = " ".join("{:02X}".format(c) for c in buffer[address: address + line_len])
        asciistr = "".join((chr(c) if c in range(31, 127) else ".") for c in buffer[address: address + line_len])
        print_l("%08X:  %s  | %s" % (address, hexstr + " " * (line_len * 3 - len(hexstr)), asciistr))


## Run single stages, or the complete fuzzing lifecycle
def _main():
    sanity_checks()

    start_server(no_window=config["no_server_window"])

    target_file = os.path.join(get_target_dir(config), "targets.msg")

    # If the user selected a single stage, do that instead of running anything else
    if "stage" in config:
        # Re-run the wizard stage and dump the output in the target directory
        if config["stage"] == "WIZARD":
            select_and_dump_wizard_findings(wizard_run(config), target_file)

        # Parse the list of targets and select one to fuzz
        if config["stage"] == "FUZZER":
            targets = get_all_targets()
            mapping = []
            for target in targets:
                print(
                    "{}) [{}]  {}".format(
                        len(mapping),
                        target[-40:][:8],  # first 8 bytes of the SHA hash
                        stringify_program_array(targets[target][0], targets[target][1]),
                    )
                )
                mapping.append(target)
            target_id = mapping[select_from_range(len(mapping), "Select a target to fuzz> ")]
            config["target_application_path"], config["target_args"] = targets[target_id]
            config["client_args"].append("-t")
            targets_file = os.path.join(target_id, "targets.msg")
            config["client_args"].append(targets_file)
            fuzzer_run(config, targets_file)

        # Parse the list of run ID's and select one to triage
        if config["stage"] == "TRACER":
            if "run_id" in config:
                run_id = config["run_id"]
                runs = get_runs(run_id)
                run_id = list(runs.keys())[0]
            else:
                runs = get_runs()
                mapping = []
                for run_id in runs:
                    print(
                        "{}) [{}]  {}".format(
                            len(mapping),
                            run_id[-36:][:8],  # first 8 bytes of the UUID
                            stringify_program_array(runs[run_id][0], runs[run_id][1]),
                        )
                    )
                    mapping.append(run_id)

                run_id = mapping[select_from_range(len(mapping), "Select a run to triage> ")]
            config["target_application_path"], config["target_args"] = runs[run_id]
            config["client_args"].append("-t")
            config["client_args"].append(target_file)
            tracerResults = tracer_run(config, run_id[-36:])[0]
            print(tracerResults)

    else:
        # Run the wizard to select a target function if we don't have one saved
        if not os.path.exists(target_file):
            select_and_dump_wizard_findings(wizard_run(config), target_file)

        config["client_args"].append("-t")
        config["client_args"].append(target_file)

        # Spawn a thread that will run DynamoRIO and wait for the output
        with concurrent.futures.ThreadPoolExecutor(max_workers=config["simultaneous"]) as executor:
            # If we're in continuous mode, spawn as many futures as we can run simultaneously.
            # Otherwise, spawn as many as we want to run in total
            fuzz_futures = [
                executor.submit(fuzz_and_triage, config)
                for _ in range(config["runs"] if not config["continuous"] else config["simultaneous"])
            ]

            # Wait for exit
            concurrent.futures.wait(fuzz_futures)


## wrapper around_main that handles keyboard interrupts
def main():
    signal.signal(signal.SIGINT, interrupted)

    try:
        _main()
    except KeyboardInterrupt:
        print_l("Waiting for worker threads to exit...")
        kill()
        raise


if __name__ == "__main__":
    main()
