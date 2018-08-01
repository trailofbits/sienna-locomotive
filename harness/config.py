"""
Handles argument and config file parsing for the fuzzer.

1: Check if the config file exists. If not, create it with sensible defaults.
2: If the config file exists, read in the contents.
3: If the user has provided any arguments that overwrite the values in the
config file, use those instead.
"""

import os
import sys
import argparse
import configparser

# NOTE(ww): Keep these up-to-data with include/server.hpp!
sl2_server_pipe_path = "\\\\.\\pipe\\fuzz_server"
sl2_dir = os.path.join(os.getenv('APPDATA', default="."), 'Trail of Bits', 'fuzzkit')
sl2_runs_dir = os.path.join(sl2_dir, 'runs')
sl2_arenas_dir = os.path.join(sl2_dir, 'arenas')
sl2_log_dir = os.path.join(sl2_dir, 'log')
sl2_targets_dir = os.path.join(sl2_dir, 'targets')
sl2_config_path = os.path.join(sl2_dir, 'config.ini')

os.makedirs(sl2_runs_dir, exist_ok=True)
os.makedirs(sl2_arenas_dir, exist_ok=True)
os.makedirs(sl2_log_dir, exist_ok=True)
os.makedirs(sl2_targets_dir, exist_ok=True)

# Create a default config file if one doesn't exist
if not os.path.exists(sl2_config_path):
    default_config = configparser.ConfigParser()
    default_config['DEFAULT'] = {'drrun_path': 'dynamorio\\bin64\\drrun.exe',
                                 'drrun_args': '',
                                 'client_path': 'build\\fuzz_dynamorio\\Debug\\fuzzer.dll',
                                 'client_args': '',
                                 'server_path': 'build\\server\\Debug\\server.exe',
                                 'wizard_path': 'build\\wizard\\Debug\\wizard.dll',
                                 'triage_path': 'build\\triage_dynamorio\\Debug\\tracer.dll',
                                 'triager_path': r'.\build\triage\Debug\triager.exe',
                                 'target_application_path': 'build\\corpus\\test_application\\Debug\\test_application.exe',
                                 'target_args': '0,-f',
                                 'runs': 1,
                                 'simultaneous': 1,
                                 'inline_stdout': False
                                 }
    with open(sl2_config_path, 'w') as configfile:
        default_config.write(configfile)

# Read the config file
try:
    _config = configparser.ConfigParser()
    _config.read(sl2_config_path)
except configparser.Error as e:
    print("ERROR: Failed to load configuration:", e)
    sys.exit()

# Set up argument parser
parser = argparse.ArgumentParser(
    description='Run the DynamoRIO fuzzing harness. \
    You can pass arguments to the command line to override \
    the defaults in config.ini')

parser.add_argument(
    '-v', '--verbose',
    action='store_true',
    dest='verbose',
    default=False,
    help="Tell drrun to run in verbose mode")

parser.add_argument(
    '-d', '--debug',
    action='store_true',
    dest='debug',
    default=False,
    help="Tell drrun to run in debug mode")

parser.add_argument(
    '-n', '--nopersist',
    action='store_true',
    dest='nopersist',
    default=False,
    help="Tell drrun not to use persistent code caches (slower)")

parser.add_argument(
    '-p', '--profile',
    action='store',
    dest='profile',
    default='DEFAULT',
    type=str,
    help="Load the given profile (from config.ini). Defaults to DEFAULT")

parser.add_argument(
    '-c', '--continuous',
    action='store_true',
    dest='continuous',
    default=False,
    help="Continuously fuzz the target application")

parser.add_argument(
    '-x', '--exit',
    action='store_true',
    dest='exit_early',
    default=False,
    help="Exit the application once it finds and triages a single crash")

parser.add_argument(
    '-f', '--fuzztimeout',
    action='store',
    dest='fuzz_timeout',
    type=int,
    help="Timeout (seconds) after which fuzzing runs should be killed. \
    By default, runs are not killed.")

parser.add_argument(
    '-i', '--triagetimeout',
    action='store',
    dest='triage_timeout',
    type=int,
    help="Timeout (seconds) after which triage runs should be killed. \
    By default, runs are not killed.")

parser.add_argument(
    '-r', '--runs',
    action='store',
    dest='runs',
    type=int,
    help="Number of times to run the target application")

parser.add_argument(
    '-s', '--simultaneous',
    action='store',
    dest='simultaneous',
    type=int,
    help="Number of simultaneous instances of the target application to run")

parser.add_argument(
    '-t', '--target',
    action='store',
    dest='target_application_path',
    type=str,
    help="Path to the target application. \
    Note: Ignores arguments in the config file")

parser.add_argument(
    '-e', '--stage',
    action='store',
    dest='stage',
    type=str,
    choices=['WIZARD', 'FUZZER', 'TRIAGE'],
    help="Synchronously re-run a single stage (for debugging purposes)")

parser.add_argument(
    '-a', '--arguments',
    action='store',
    dest='target_args',
    nargs=argparse.REMAINDER,
    type=str,
    help="Arguments for the target application. \
    Multiple arguments are supported, but must come last.")

parser.add_argument(
    '-l', '--inline_stdout',
    action='store_true',
    dest='inline_stdout',
    default=False,
    help="Inline stdout of program under test to console stdout")

args = parser.parse_args()

# Read the ConfigParser object into a standard dict
config = {}  # This is what gets exported


def set_profile(new_profile):
    """
    Updates the global configuration to match the supplied profile.
    """
    global config
    try:
        config = dict(_config[new_profile])
    except Exception as e:
        print("ERROR: No such profile:", new_profile)
        sys.exit()

    update_config_from_args()


def create_new_profile(name, dynamorio_exe, build_dir, target_path, target_args):
    global _config
    _config[name] = {'drrun_path': dynamorio_exe,
                     'drrun_args': '',
                     'client_path': os.path.join(build_dir, 'fuzz_dynamorio\\Debug\\fuzzer.dll'),
                     'client_args': '',
                     'server_path': os.path.join(build_dir, 'server\\Debug\\server.exe'),
                     'wizard_path': os.path.join(build_dir, 'wizard\\Debug\\wizard.dll'),
                     'triage_path': os.path.join(build_dir, 'triage_dynamorio\\Debug\\tracer.dll'),
                     'triager_path': os.path.join(build_dir,  r'\triage\Debug\triager.exe'),
                     'target_application_path': target_path,
                     'target_args': target_args,
                     'runs': 1,
                     'simultaneous': 1,
                     'inline_stdout': False}

    with open(sl2_config_path, 'w') as configfile:
        _config.write(configfile)


def update_config_from_args():
    """
    Supplements the global configuration with command-line arguments
    passed by the user.
    """
    global config
    # Convert numeric arguments into ints.
    # Need to update this list manually if adding anything.
    int_options = ['runs', 'simultaneous', 'fuzz_timeout', 'triage_timeout']
    for opt in int_options:
        if opt in config:
            config[opt] = int(config[opt])

    # Convert comma-separated arguments into lists
    list_options = ['drrun_args', 'client_args', 'target_args']
    for opt in list_options:
        config[opt] = [] if (len(config[opt]) == 0) else config[opt].split(',')

    if args.target_application_path is not None and len(config['target_args']) > 0:
        config['target_args'] = []

    if args.verbose:
        config['drrun_args'].append('-verbose')

    if args.debug:
        config['drrun_args'].append('-debug')

    if not args.nopersist:
        config['drrun_args'].append('-persist')

    # Replace any values in the config dict with the optional value from the argument.
    # Note that if you set a default value for an arg, this will overwrite its value in the config
    # file even if the argument is not explicitly set by the user, so make sure you use keys that aren't
    # in the config file for any arguments that have default values.
    for arg in vars(args):
        if getattr(args, arg) is not None:
            config[arg] = getattr(args, arg)

    for key in config:
        if 'path' in key:
            if not os.path.exists(config[key]):
                print("WARNING: {key} = {dest}, which does not exist.".format(key=key, dest=config[key]))
            else:
                root, extension = os.path.splitdrive(config[key])
                if len(root) > 0 and ':' not in root:  # UNC Path
                    print("WARNING: Replacing UNC Path", config[key], "with", extension)
                    config[key] = extension


set_profile(args.profile)

if __name__ == '__main__':
    from pprint import pprint
    pprint(config)
