import os
import glob
import re
import shlex
from hashlib import sha1

from . import config


def stringify_program_array(target_application_path, target_args_array):
    """ Escape paths with spaces in them by surrounding them with quotes """
    return "{} {}\n".format(shlex.quote(target_application_path)), ' '.join(shlex.quote(arg) for arg in target_args_array)


def unstringify_program_array(stringified):
    """ Turn a stringified program array back into the tokens that went in. Treates quoted entities as atomic,
         splits all others on spaces. """
    invoke = shlex.split(stringified)

    return invoke[0], invoke[1:]


def get_target_dir(_config):
    """ Gets (or creates) the path to a target directory for the current config file """
    exe_name = _config['target_application_path'].split('\\')[-1].strip('.exe').upper()
    hash = sha1("{} {}".format(_config['target_application_path'], _config['target_args']).encode('utf-8')).hexdigest()
    dir_name = os.path.join(config.sl2_targets_dir, "{}_{}".format(exe_name, hash))
    if not os.path.isdir(dir_name):
        os.makedirs(dir_name)
    arg_file = os.path.join(dir_name, 'arguments.txt')
    if not os.path.exists(arg_file):
        with open(arg_file, 'w') as argfile:
            argfile.write(stringify_program_array(_config['target_application_path'], _config['target_args']))
    return dir_name


def get_targets():
    """ Returns a dict mapping target directories to the contents of the argument file """
    targets = {}
    for _dir in glob.glob(os.path.join(config.sl2_targets_dir, '*')):
        with open(os.path.join(_dir, 'arguments.txt'), 'r') as program_string_file:
            targets[_dir] = unstringify_program_array(program_string_file.read().strip())
    return targets


def get_runs():
    """ Returns a dict mapping run ID's to the contents of the argument file """
    runs = {}
    for _dir in glob.glob(os.path.join(os.getenv('APPDATA'), 'Trail of Bits', 'fuzzkit', 'working', '*')):
        with open(os.path.join(_dir, 'arguments.txt'), 'rb') as program_string_file:
            runs[_dir] = unstringify_program_array(program_string_file.read().decode('utf-16').strip())
    return runs
