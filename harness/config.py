## @package config
#
# Handles argument and config file parsing for SL2.
# 1: Check if the config file exists. If not, create it with sensible defaults.
# 2: If the config file exists, read in the contents.
# 3: If the user has provided any arguments that overwrite the values in the
# config file, use those instead.


import argparse
import configparser
import os
import shlex
import sys

## Schematizes the SL2 configuration.
# Every configuration key has a 'test' function, an 'expected'
# string that explains the result of a failed test, and a 'required'
# bool that indicates whether the harness should continue without its
# presence.
# TODO(ww): Add conversion to the schema as well?
CONFIG_SCHEMA = {}

# Increment this version number for any changes that might break backwards compatibilty.
# This could be database schema changes, paths, file glob patterns, etc..
VERSION = 9

PATH_KEYS = ['drrun_path', 'client_path', 'server_path', 'wizard_path', 'tracer_path', 'triager_path']
ARGS_KEYS = ['drrun_args', 'client_args', 'server_args', 'target_args']
INT_KEYS = ['runs', 'simultaneous', 'fuzz_timeout', 'tracer_timeout', 'seed', 'verbose', 'function_number']
FLAG_KEYS = ['debug', 'nopersist', 'continuous', 'exit_early', 'inline_stdout', 'preserve_runs']

profile = 'DEFAULT'

for path in PATH_KEYS:
    CONFIG_SCHEMA[path] = {
        'test': os.path.isfile,
        'expected': 'path to an existing file',
        'required': True,
    }

for args in ARGS_KEYS:
    CONFIG_SCHEMA[args] = {
        'test': lambda xs: type(xs) is list and all(type(x) is str for x in xs),
        'expected': 'command-line arguments (array of strings)',
        'required': True,
    }

for num in INT_KEYS:
    CONFIG_SCHEMA[num] = {
        'test': lambda x: type(x) is int,
        'expected': 'integer value',
        'required': False,
    }

for flag in FLAG_KEYS:
    CONFIG_SCHEMA[flag] = {
        'test': lambda x: type(x) is bool,
        'expected': 'boolean',
        'required': False,
    }

# NOTE(ww): Keep these up-to-data with include/server.hpp!
sl2_server_pipe_path = "\\\\.\\pipe\\fuzz_server"
## Path to SL2 data and configuration
sl2_dir = os.path.join(os.getenv('APPDATA', default="."), 'Trail of Bits', 'fuzzkit')
## Path to runs directory
sl2_runs_dir = os.path.join(sl2_dir, 'runs')
sl2_arenas_dir = os.path.join(sl2_dir, 'arenas')
## Path to log files
sl2_log_dir = os.path.join(sl2_dir, 'log')
sl2_targets_dir = os.path.join(sl2_dir, 'targets')
sl2_config_path = os.path.join(sl2_dir, 'config.ini')

# This is a pointer to the current db session for convience

os.makedirs(sl2_runs_dir, exist_ok=True)
os.makedirs(sl2_arenas_dir, exist_ok=True)
os.makedirs(sl2_log_dir, exist_ok=True)
os.makedirs(sl2_targets_dir, exist_ok=True)

# Create a default config file if one doesn't exist
if not os.path.exists(sl2_config_path):
    default_config = configparser.ConfigParser()
    default_config[profile] = {
        'drrun_path': 'dynamorio\\bin64\\drrun.exe',
        'drrun_args': '',
        'client_path': 'build\\fuzz_dynamorio\\Debug\\fuzzer.dll',
        'client_args': '',
        'server_path': 'build\\server\\Debug\\server.exe',
        'server_args': '',
        'wizard_path': 'build\\wizard\\Debug\\wizard.dll',
        'tracer_path': 'build\\tracer_dynamorio\\Debug\\tracer.dll',
        'triager_path': 'build\\triage\\Debug\\triager.exe',
        'checksec_path': r'build\winchecksec\Debug\winchecksec.exe',
        'target_application_path': 'build\\corpus\\test_application\\Debug\\test_application.exe',
        'target_args': '0 -f',
        'runs': 1,
        'simultaneous': 1,
        'function_number': -1,
        'inline_stdout': False,
        'preserve_runs': False,
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
    action='count',
    default=0,
    dest='verbose',
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
    default=profile,
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
    '-fn', '--functionnumber',
    action='store',
    dest='function_number',
    default=-1,
    type=int,
    help="Function call number to run")

parser.add_argument(
    '-g', '--registry',
    action='store_true',
    dest='registry',
    help="Enable tracking registry calls like RegQuery()")

parser.add_argument(
    '-i', '--triagetimeout',
    action='store',
    dest='tracer_timeout',
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
    choices=['WIZARD', 'FUZZER', 'TRACER'],
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

parser.add_argument(
    '-P', '--preserve_runs',
    action='store_true',
    dest='preserve_runs',
    default=False,
    help="Preserve all fuzzer runs, even when they don't cause crashes")

parser.add_argument(
    '--run_id',
    action='store',
    dest='run_id',
    type=str,
    help="Set the Run ID for a given run to a specific value instead \
    of using an auto-generated value. Useful for replaying triage runs.")

args = parser.parse_args()

# Read the ConfigParser object into a standard dict
config = {}  # This is what gets exported


def set_profile(new_profile):
    """
    Updates the global configuration to match the supplied profile.
    """
    global config
    global profile
    try:
        config = dict(_config[new_profile])
    except:
        print("ERROR: No such profile:", new_profile)
        sys.exit()

    profile = new_profile
    update_config_from_args()
    validate_config()


## Creates a default profile configuration
# @param name String name of configuration context
# @param dynamorio_exe String path to dynamorio executable ddrun
# @param build_dir CMake build directory
# @param target_path Path to PUT, target executable we are fuzzing
# @param target_args Command line arguments to the target executable
def create_new_profile(name, dynamorio_exe, build_dir, target_path, target_args):
    global _config
    _config[name] = {
        'drrun_path': dynamorio_exe,
        'drrun_args': '',
        'client_path': os.path.join(build_dir, 'fuzz_dynamorio\\Debug\\fuzzer.dll'),
        'client_args': '',
        'server_path': os.path.join(build_dir, 'server\\Debug\\server.exe'),
        'server_args': '',
        'wizard_path': os.path.join(build_dir, 'wizard\\Debug\\wizard.dll'),
        'tracer_path': os.path.join(build_dir, 'tracer_dynamorio\\Debug\\tracer.dll'),
        'triager_path': os.path.join(build_dir, 'triage\\Debug\\triager.exe'),
        'checksec_path': os.path.join(build_dir, r'winchecksec\Debug\winchecksec.exe'),
        'target_application_path': target_path,
        'target_args': target_args,
        'runs': 1,
        'simultaneous': 1,
        'function_number': -1,
        'inline_stdout': False,
    }

    with open(sl2_config_path, 'w') as config_file:
        _config.write(config_file)


## Merges command line arguments into configuration
def update_config_from_args():
    """
    Supplements the global configuration with command-line arguments
    passed by the user.
    """
    global config
    # Convert numeric arguments into ints.
    for opt in INT_KEYS:
        if opt in config:
            config[opt] = int(config[opt])

    # Convert command line strings into lists
    for opt in ARGS_KEYS:
        config[opt] = [] if (len(config[opt]) == 0) else shlex.split(config[opt], posix=False)

    if args.target_application_path is not None and len(config['target_args']) > 0:
        config['target_args'] = []

    if args.verbose:
        config['drrun_args'].append('-verbose')

    if args.debug:
        print("WARNING: debug mode may destabilize the binary instrumentation!")
        config['drrun_args'].append('-debug')

    if not args.nopersist:
        config['drrun_args'].append('-persist')

    if args.registry:
        config['client_args'].append('-registry')

    # Replace any values in the config dict with the optional value from the argument.
    # Note that if you set a default value for an arg, this will overwrite its value in the config
    # file even if the argument is not explicitly set by the user, so make sure you use keys that aren't
    # in the config file for any arguments that have default values.
    for arg in vars(args):
        if getattr(args, arg) is not None:
            config[arg] = getattr(args, arg)

    for key in PATH_KEYS:
        root, extension = os.path.splitdrive(config[key])
        if len(root) > 0 and ':' not in root:  # UNC Path
            print("WARNING: Replacing UNC Path", config[key], "with", extension)
            config[key] = extension


## Sanity check for configuration
def validate_config():
    """
    Check the (argv-supplanted) configuration, making sure that
    all required keys are present and that all keys satisfy their
    invariants.
    """
    for key in CONFIG_SCHEMA:
        # If the key is required but not present, fail loudly.
        if CONFIG_SCHEMA[key]['required'] and key not in config:
            print("ERROR: Missing required key:", key)
            sys.exit()
        # If they key is present but doesn't validate, fail loudly.
        if key in config:
            if not CONFIG_SCHEMA[key]['test'](config[key]):
                print("ERROR: Failed to validate %s: expected %s" % (key, CONFIG_SCHEMA[key]['expected']))
                sys.exit()


set_profile(args.profile)

if __name__ == '__main__':
    from pprint import pprint

    pprint(config)
