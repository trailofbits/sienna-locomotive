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
    return dir_name
