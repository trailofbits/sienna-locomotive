"""
Helper functions for reading and writing files to manage the fuzzing lifecycle
Imports harness/config.py for argument and config file handling.
"""
import glob
import json
import os
import random
import re
import uuid
import sys
from csv import DictWriter
from hashlib import sha1
from typing import NamedTuple
import csv
import shutil
from shutil import ignore_patterns
import winreg

import msgpack

from sl2 import db
from sl2.db import Crash, Tracer, Checksec
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


# TODO: Use winshlex here.
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


def get_target_slug(_config):
    # TODO(ww): Use os.path.basename for this?

    exe_name = _config['target_application_path'].split('\\')[-1].strip('.exe').upper()
    dir_hash = sha1(
        "{} {}".format(_config['target_application_path'], _config['target_args']).encode('utf-8')
    ).hexdigest()
    return "{}_{}".format(exe_name, dir_hash)


def get_target_dir(_config):
    """
    Gets (or creates) the path to a target directory for the current
    config file.
    """
    slug = get_target_slug(_config)
    dir_name = os.path.join(config.sl2_targets_dir, slug)

    if not os.path.isdir(dir_name):
        os.makedirs(dir_name)
    arg_file = os.path.join(dir_name, 'arguments.txt')

    if not os.path.exists(arg_file):
        with open(arg_file, 'w') as argfile:
            argfile.write(stringify_program_array(_config['target_application_path'], _config['target_args']))

    # Primes the db for checksec for this target if it doesn't already exist
    db.TargetConfig.bySlug(slug, _config['target_application_path'])
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


def get_paths_to_run_file(run_id, pattern):
    """
    Returns all paths under the given run's directory
    that match the given pattern glob.
    """
    pattern = os.path.join(config.sl2_runs_dir, str(run_id), pattern)
    return glob.glob(pattern)


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


def parse_tracer_crash_files(run_id):
    """
    Parses the results of a tracer run and returns them in
    human-readable form.
    """
    crash_files = get_paths_to_run_file(run_id, 'crash.*.json')

    if not crash_files:
        message = "The tracer tool exited improperly during run {}, \
but no crash files could be found. It may have timed out. \
To retry it manually, run \
`python harness.py -v -e TRIAGE -p {} --run_id {}`".format(run_id, config.profile, run_id)
        print(message)
        return 'ERROR', None

    # TODO(ww): Parse all crash files, not just the first.
    crash_file = crash_files[0]
    with open(crash_file, 'r') as crash_json:
        results = json.loads(crash_json.read())
        results['run_id'] = run_id
        results['crash_file'] = crash_file
        formatted = "Tracer ({score}): {reason} in run {run_id} caused {exception}".format(**results)
        formatted += ("\n\t0x{location:02x}: {instruction}".format(**results))
        return formatted, results


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

## strips out characters in a string that could be harmful for filenames or paths
# @param s strings to sanitize
# @return sanitized string
def sanitizeString(s):
    ret = re.sub(r"[^a-zA-Z0-9._]+", "_", s)
    return re.sub(r"_+", "_", ret)


## Class for exporting triage results. Will iterate each crash from the db
# and copy to the appropriate directory based on exploitability, the reason
# for the crash, and the crashash.
class TriageExport:

    ## Constructor to export triage results
    # @param exportDir Directory to export all crashes
    def __init__(self, exportDir, slug):
        self.exportDir = exportDir
        self.slug = slug
        self.checksec_cols = [
                     # Checksec table.
                     'aslr',
                     'authenticode',
                     'cfg',
                     'dynamicBase',
                     'forceIntegrity',
                     'gs',
                     'highEntropyVA',
                     'isolation',
                     'nx',
                     'rfg',
                     'safeSEH',
                     'seh',
                     'path']

        self.crash_cols = [
                     # Crash table.
                     'runid',
                     'crashAddressString',
                     'crashReason',
                     'crashash',
                     'exploitability',
                     'instructionPointerString',
                     'minidumpPath',
                     'ranksString',
                     'stackPointerString',
                     'timestamp',
                     'tag',
                     'cs',
                     'dr0',
                     'dr1',
                     'dr2',
                     'dr3',
                     'dr6',
                     'dr7',
                     'ds',
                     'eflags',
                     'es',
                     'fs',
                     'gs',
                     'mx_csr',
                     'r8',
                     'r9',
                     'r10',
                     'r11',
                     'r12',
                     'r13',
                     'r14',
                     'r15',
                     'rax',
                     'rbp',
                     'rbx',
                     'rcx',
                     'rdi',
                     'rdx',
                     'rip',
                     'rsi',
                     'rsp',
                     'ss']

    ## Exports crash from run directories to appropriate directory structure.  Also generates
    # triage.csv file with summary of crashes
    def export(self):
        csvPath = os.path.join(self.exportDir, "triage.csv")
        with open(csvPath, "w") as f:
            csvWriter = csv.writer(f, lineterminator='\n')
            csvWriter.writerow(self.checksec_cols + self.crash_cols + ['tracer.formatted'])
            session = db.getSession()
            for crash in session.query(Crash).filter(Crash.target_config_slug == self.slug).all():
                checksec = session.query(Checksec).filter(Checksec.hash == crash.target_config_slug).first()
                tracer = session.query(Tracer).filter(Tracer.runid == crash.runid).first()
                row = []
                for col in self.checksec_cols:
                    row.append(getattr(checksec, col, None))
                for col in self.crash_cols:
                    row.append(getattr(crash, col, None))
                row.append(tracer.formatted)
                csvWriter.writerow(row)

        crashies = db.getSession().query(Crash).filter(Crash.target_config_slug == self.slug).all()
        for crash in crashies:
            try:
                dstdir = os.path.join(self.exportDir,
                                      sanitizeString(crash.exploitability),
                                      sanitizeString(crash.crashReason),
                                      sanitizeString(crash.crashash),
                                      crash.runid)
                # os.makedirs( dstdir, exist_ok=True )
                srcdir = os.path.dirname(crash.minidumpPath)
                print("%s -> %s" % (srcdir, dstdir))
                shutil.copytree(srcdir, dstdir, ignore=ignore_patterns("mem*.dmp"))
            except FileExistsError as x:
                print("File already exists for crash ", crash.minidumpPath, x)

    @staticmethod
    def checksecToExploitabilityRank(targetPath):
        checksec = db.Checksec.byExecutable(targetPath)
        if checksec is None:
            return 0
        attrmap = {
            'aslr': 1,
            'authenticode': 0,
            'cfg': 1,
            'dynamicBase': 1,  # maybe 0?
            'forceIntegrity': 0,
            'gs': 1,
            'highEntropyVA': 0,
            'nx': 1,
        }
        return attrmap

def sanity_checks(exit=True):
    """
    Make sure the system is in a state that's nominally ready for fuzzing.
    Exits loudly if a check fails.
    """
    sane = True
    errors = []

    bad_keys = [
        'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\DebugObjectRPCEnabled',
        'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\Auto',
    ]

    for bad_key in bad_keys:
        try:
            reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            key = winreg.OpenKey(reg, bad_key, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
            reg.CloseKey(key)

            if exit:
                print("[+] Fatal: Found a registry key that will interfere with fuzzing/triaging:", bad_key)
                sys.exit()
            else:
                sane = False
                errors.append("Registry key {} will interfere with fuzzing/triaging.".format(bad_key))
        except OSError:
            # OSError means the key doesn't exist, which is what we want.
            pass
        except Exception as e:
            print("[+] Unexpected exception during sanity checks:", e)

    try:
        reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        key = winreg.OpenKey(reg, "SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting", 0,
                             (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        disabled = winreg.QueryValueEx(key, "Disabled")[0]

        if disabled != 1:

            if exit:
                print("[+] Fatal: Cowardly refusing to run with WER enabled.")
                print(
                      "[+] Set HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\Disabled to 1 (DWORD) to continue.")
                sys.exit()
            else:
                sane = False
                errors.append("WER is enabled, refusing to continue.")

        winreg.CloseKey(key)
    except OSError:
        # OSError here means that we *haven't* disabled WER, which is a problem.

        if exit:
            print("[+] Fatal: Cowardly refusing to run with WER enabled.")
            print(
                  "[+] Set HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\Disabled to 1 (DWORD) to continue.")
            sys.exit()
        else:
            sane = False
            errors.append("WER isn't explicitly disabled, refusing to continue.")
        pass
    except Exception as e:
        print("[+] Unexpected exception during sanity checks:", e)

    return sane, errors
