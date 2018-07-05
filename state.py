import os
import glob
from hashlib import sha1

target_dir = os.path.join(os.getenv('APPDATA'), 'Trail of Bits', 'fuzzkit', 'targets')
if not os.path.isdir(target_dir):
    os.makedirs(target_dir)


def get_target_dir(_config):
    exe_name = _config['target_application_path'].split('\\')[-1].strip('.exe').upper()
    hash = sha1("{} {}".format(_config['target_application_path'], _config['target_args']).encode('utf-8')).hexdigest()
    dir_name = os.path.join(target_dir, "{}_{}".format(exe_name, hash))
    if not os.path.isdir(dir_name):
        os.makedirs(dir_name)
    arg_file = os.path.join(dir_name, 'arguments.txt')
    if not os.path.exists(arg_file):
        with open(arg_file, 'w') as argfile:
            argfile.write("{} {}\n".format(_config['target_application_path'], ' '.join(_config['target_args'])))
    return dir_name


def get_targets():
    targets = {}
    for _dir in glob.glob(os.path.join(target_dir, '*')):
        with open(os.path.join(_dir, 'arguments.txt'), 'r') as program_string_file:
            targets[_dir[-40:]] = program_string_file.read().strip()
    return targets


def get_runs():
    runs = {}
    for _dir in glob.glob(os.path.join(os.getenv('APPDATA'), 'Trail of Bits', 'fuzzkit', 'runs', '*')):
        with open(os.path.join(_dir, 'arguments.txt'), 'r') as program_string_file:
            runs[dir] = program_string_file.read().strip()
    return runs
