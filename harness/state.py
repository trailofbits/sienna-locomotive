import os
import glob
import re
import struct
from hashlib import sha1

from . import config


# TODO(ww): Use shlex or something similar here.
def stringify_program_array(target_application_path, target_args_array):
    """ Escape paths with spaces in them by surrounding them with quotes """
    return "{} {}\n".format(target_application_path if " " not in target_application_path
                                                    else "\"{}\"".format(target_application_path),
                            ' '.join((k if " " not in k else "\"{}\"".format(k))for k in target_args_array))


# TODO: Use shlex or something similar here.
def unstringify_program_array(stringified):
    """ Turn a stringified program array back into the tokens that went in. Treats quoted entities as atomic,
         splits all others on spaces. """
    invoke = []
    split = re.split('(\".*?\")', stringified)  # TODO use this for config file parsing
    for token in split:
        if len(token) > 0:
            if "\"" in token:
                invoke.append(token)
            else:
                for inner_token in token.split(' '):
                    invoke.append(inner_token)

    return invoke[0], invoke[1:]


def get_target_dir(_config):
    """ Gets (or creates) the path to a target directory for the current config file """
    exe_name = _config['target_application_path'].split('\\')[-1].strip('.exe').upper()
    dir_hash = sha1("{} {}".format(_config['target_application_path'], _config['target_args']).encode('utf-8')).hexdigest()
    dir_name = os.path.join(config.sl2_targets_dir, "{}_{}".format(exe_name, dir_hash))
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
    for _dir in glob.glob(os.path.join(config.sl2_working_dir, '*')):
        with open(os.path.join(_dir, 'arguments.txt'), 'rb') as program_string_file:
            runs[_dir] = unstringify_program_array(program_string_file.read().decode('utf-16').strip())
    return runs


def get_path_to_run_file(run_id, filename):
    """ Helper function for easily getting the full path to a file in the current run's directory """
    return os.path.join(config.sl2_dir, 'working', str(run_id), filename)


def finalize(run_id, crashed):
    """ Manually closes out a fuzzing run. Only necessary if we killed the target binary before DynamoRIO could
    close out the run """
    f = open(config.sl2_server_pipe_path, 'w+b', buffering=0)
    f.write(struct.pack('B', 0x4))  # Write the event ID (4)
    f.seek(0)
    f.write(run_id.bytes)  # Write the run ID
    f.seek(0)
    # Write a bool indicating a crash
    f.write(struct.pack('?', 1 if crashed else 0))
    # Write a bool indicating whether to preserve run files (without a crash)
    f.write(struct.pack('?', 1 if True else 0))
    f.close()