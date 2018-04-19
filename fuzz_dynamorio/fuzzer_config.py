"""
Handles argument and config file parsing for the fuzzer

1: Check if the config file exists. If not, create it with sensible defaults
2: If the config file exists, read in the contents
3: If the user has provided any arguments that overwrite the values in the config file, use those instead 
"""
import os
import argparse
import configparser

# Create a default config file if one doesn't exist
if not os.path.exists('config.ini'):
	default_config = configparser.ConfigParser()
	default_config['DEFAULT'] = {'drrun_path': 'dynamorio\\bin64\\drrun.exe', 'client_path': 'build\\x64-Debug\\fuzzer.dll', \
								 'target_application': 'notepad.exe', 'target_args':'', 'runs': 1, 'simultaneous': 1}
	with open('config.ini', 'w') as configfile:
		default_config.write(configfile)

# Read the config file
_config = configparser.ConfigParser()
_config.read('config.ini')

# Set up argument parser
parser = argparse.ArgumentParser(description='Run the DynamoRIO fuzzing harness. You can pass arguments to the command line to override the defaults in config.ini')
parser.add_argument('-p', '--profile', action='store', dest='profile', default='DEFAULT', type=str, help="Pull configuration from a specific section in config.ini. Defaults to DEFAULT")
parser.add_argument('-r', '--runs', action='store', dest='runs', type=int, help="Number of times to run the target application")
parser.add_argument('-s', '--simultaneous', action='store', dest='simultaneous', type=int, help="Number of simultaneous instances of the target application that can run")
parser.add_argument('-t', '--target', action='store', dest='target_application', type=str, help="Path to the target application")
args = parser.parse_args()

# Read the ConfigParser object into a standard dict
config = {} # This is what gets exported
for key in _config[args.profile]:
	config[key] = _config[args.profile].get(key)

# Convert numeric arguments into ints. Need to update this list manually if adding anything.
int_options = ['runs', 'simultaneous']
for opt in int_options:
	config[opt] = int(config[opt])

# Convert comma-separated arguments into lists
list_options = ['target_args']
for opt in list_options:
	config[opt] = config[opt].split(',')

# Replace any values in the config dict with the optional value from the argument.
# Note that if you set a default value for an arg, this will overwrite its value in the config
# file even if the argument is not explicitly set by the user, so make sure you use keys that aren't
# in the config file for any arguments that have default values.
for arg in vars(args):
	if getattr(args, arg) is not None:
		config[arg] = getattr(args, arg)
