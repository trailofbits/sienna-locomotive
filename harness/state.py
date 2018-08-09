"""
Helper functions for reading and writing files to manage the fuzzing lifecycle
Imports harness/config.py for argument and config file handling.
"""
import os
import glob
import re
import json
import msgpack
import uuid
import random
from hashlib import sha1
from csv import DictWriter
from typing import NamedTuple

from . import config

uuid_regex = re.compile("[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}")

class InvocationState(NamedTuple):
    """
    Represents the state created by a call to
    create_invocation_statement.
    """
    cmd_arr: list
    cmd_str: str
    seed: str


def esc_quote_paren(raw):
    if (" " not in raw and "(" not in raw) or '\"' in raw:
        return raw
    else:
        return "\"{}\"".format(raw)


def create_invocation_statement(config_dict, run_id):
    """
    Returns an InvocationState containing the command run
    and the PRNG seed used.
    """
    seed = str(generate_seed(run_id))
    program_arr = [
        config_dict['drrun_path'],
        *config_dict['drrun_args'],
        '-prng_seed',
        seed,
        # '-no_follow_children', # NOTE(ww): We almost certainly don't want this.
        '-c',
        config_dict['client_path'],
        *config_dict['client_args'],
        '--',
        config_dict['target_application_path'].strip('\"'),
        *config_dict['target_args']
    ]

    return InvocationState(
        program_arr,
        stringify_program_array(program_arr[0], program_arr[1:]),
        seed
    )


def generate_seed(run_id):
    """
    Takes a UUID, strips out the non-random bits, and returns the rest as an int
    :param run_id:
    :return: 120-bit random int
    """
    if re.match(uuid_regex, str(run_id)):
        parsed = str(run_id).replace('-', '')
        parsed = parsed[:12] + parsed[13:16] + parsed[17:]  # Strip the non-random bits
        return int(parsed, 16)
    else:
        return random.getrandbits(120)


def stringify_program_array(target_application_path, target_args_array):
    """
    Escape paths with spaces in them by surrounding them with quotes.
    """
    out = "{} {}\n".format(
        esc_quote_paren(target_application_path),
        ' '.join(esc_quote_paren(k) for k in target_args_array)
    )

    return out


# TODO: Use shlex or something similar here.
def unstringify_program_array(stringified):
    """
    Turn a stringified program array back into the tokens that went in.
    Treats quoted entities as atomic,
    splits all others on spaces.
    """
    invoke = []
    # TODO use this for config file parsing
    split = re.split('(\".*?\")', stringified)
    for token in split:
        if "\"" in token:
            invoke.append(token)
        else:
            for inner_token in token.split(' '):
                invoke.append(inner_token)
    invoke = list(filter(lambda b: len(b) > 0, invoke))
    return invoke[0], invoke[1:]


def get_target_dir(_config):
    """
    Gets (or creates) the path to a target directory for the current
    config file.
    """
    # TODO(ww): Use os.path.basename for this?
    exe_name = _config['target_application_path'].split('\\')[-1].strip('.exe').upper()
    dir_hash = sha1(
        "{} {}".format(_config['target_application_path'], _config['target_args']).encode('utf-8')
    ).hexdigest()
    dir_name = os.path.join(config.sl2_targets_dir, "{}_{}".format(exe_name, dir_hash))

    if not os.path.isdir(dir_name):
        os.makedirs(dir_name)
    arg_file = os.path.join(dir_name, 'arguments.txt')

    if not os.path.exists(arg_file):
        with open(arg_file, 'w') as argfile:
            argfile.write(stringify_program_array(_config['target_application_path'], _config['target_args']))
    return dir_name


class TargetAdapter(object):

    def __init__(self, target_list, filename):
        super().__init__()
        self.target_list = target_list
        self.filename = filename
        self.pause_saving = False

    def __iter__(self):
        return self.target_list.__iter__()

    def update(self, index, **kwargs):
        for key in kwargs:
            self.target_list[index][key] = kwargs[key]

        if not self.pause_saving:
            self.save()

    def pause(self):
        self.pause_saving = True

    def unpause(self):
        self.pause_saving = False
        self.save()

    def set_target_list(self, new_targets):
        self.target_list = new_targets
        if not self.pause_saving:
            self.save()

    def save(self):
        with open(self.filename, 'wb') as msgfile:
            msgpack.dump(list(filter(lambda k: k['selected'], self.target_list)), msgfile)
        with open(self.filename.replace("targets.msg", "all_targets.msg"), 'wb') as msgfile:
            msgpack.dump(self.target_list, msgfile)


def get_target(_config):
    target_file = os.path.join(get_target_dir(_config), 'targets.msg')
    try:
        with open(target_file.replace("targets.msg", "all_targets.msg"), 'rb') as target_msg:
            return TargetAdapter(msgpack.load(target_msg, encoding='utf-8'), target_file)
    except FileNotFoundError:
        return TargetAdapter([], target_file)


def get_all_targets():
    """
    Returns a dict mapping target directories to the contents of the
    argument file.
    """
    targets = {}
    for _dir in glob.glob(os.path.join(config.sl2_targets_dir, '*')):
        argfile = os.path.join(_dir, 'arguments.txt')
        if not os.path.exists(argfile):
            print("Warning: {} is missing".format(argfile))
            continue
        with open(argfile, 'r') as program_string_file:
            targets[_dir] = unstringify_program_array(program_string_file.read().strip())
    return targets


def get_runs(run_id=None):
    """
    Returns a dict mapping run ID's to the contents of the argument file.
    """
    runs = {}
    for _dir in glob.glob(os.path.join(config.sl2_runs_dir, '*' if run_id is None else run_id)):
        argfile = os.path.join(_dir, 'arguments.txt')
        if not os.path.exists(argfile):
            print("Warning: {} is missing".format(argfile))
            continue
        with open(argfile, 'rb') as program_string_file:
            runs[_dir] = unstringify_program_array(program_string_file.read().decode('utf-16').strip())
    return runs


def get_path_to_run_file(run_id, filename):
    """
    Returns the full path to the given filename within
    the given run's directory.
    """
    return os.path.join(config.sl2_runs_dir, str(run_id), filename)


def write_output_files(run, run_id, stage_name):
    """
    Writes the PRNG seed, stdout, and stderr buffers for a particular stage
    into a run's directory.
    """
    try:
        with open(get_path_to_run_file(run_id, '{}.seed'.format(stage_name)), 'w') as seedfile:
            seedfile.write(run.seed)
        if run.process.stdout is not None:
            with open(get_path_to_run_file(run_id, '{}.stdout'.format(stage_name)), 'wb') as stdoutfile:
                stdoutfile.write(run.process.stdout)
        if run.process.stderr is not None:
            with open(get_path_to_run_file(run_id, '{}.stderr'.format(stage_name)), 'wb') as stderrfile:
                stderrfile.write(run.process.stderr)
    except FileNotFoundError:
        print("Couldn't find an output directory for run %s" % run_id)


def parse_triage_output(run_id):
    """
    Parses the results of a triage run and prints them in
    human-readable form.
    """
    try:
        crash_file = get_path_to_run_file(run_id, 'crash.json')
        with open(crash_file, 'r') as crash_json:
            results = json.loads(crash_json.read())
            results['run_id'] = run_id
            results['crash_file'] = crash_file
            formatted = "Triage ({score}): {reason} in run {run_id} caused {exception}".format(**results)
            formatted += ("\n\t0x{location:02x}: {instruction}".format(**results))
            return formatted, results
    except FileNotFoundError:
        message = "The triage tool exited improperly during run {}, \
but no crash file could be found. It may have timed out. \
To retry it manually, run \
`python harness.py -v -e TRIAGE -p {} --run_id {}`"

        return message.format(run_id, config.profile, run_id), None


def export_crash_data_to_csv(crashes, csv_filename):
    fields = [
        'score',
        'run_id',
        'exception',
        'reason',
        'instruction',
        'location',
        'crash_file',
    ]

    with open(csv_filename, 'w') as csvfile:
        writer = DictWriter(csvfile, fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(crashes)


def generate_run_id(config_dict):
    run_id = uuid.uuid4() if 'run_id' not in config_dict else config_dict['run_id']

    os.makedirs(os.path.join(config.sl2_runs_dir, str(run_id)))

    program = esc_quote_paren(config_dict['target_application_path'])

    with open(get_path_to_run_file(run_id, "program.txt"), "wb") as program_file:
        program_file.write(program.encode("utf-16"))

    with open(get_path_to_run_file(run_id, "arguments.txt"), "wb") as arguments_file:
        arguments_file.write(stringify_program_array(program, config_dict['target_args']).encode("utf-16"))

    return run_id


def check_fuzz_line_for_crash(line):
    """
    Attempt to parse a line as JSON, returning a tuple of the crash state
    and the exception code. If no crash can be detected in the line, return
    False, None.
    """
    try:
        obj = json.loads(line)
        if obj["exception"]:
            return True, obj["exception"]
    except (json.JSONDecodeError, KeyError):
        pass
    except Exception as e:
        print("[!] Unexpected exception while checking for crash:", e)
    return False, None
