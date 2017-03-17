import subprocess
import shutil
import yaml
import time
import sys
import os
import re

def get_fopen(sys_config, run_config):
    dr_cmd = [
        os.path.join(sys_config['path_dynamorio'], 'drrun.exe'),
        '-c',
        os.path.join(sys_config['path_dynamorio'], 'samples\\build\\bin\\instrcalls.dll'),
        '--'
    ]

    dr_cmd += run_config['command']
    print ' '.join(dr_cmd)

    proc = subprocess.Popen(dr_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    print 'OUT:', out
    print 'ERR:', err
    candidates = []
    for line in out.split('\n'):
        if line.startswith('***fopen'):
            _, mod, off = line.split('\t')
            off = re.sub('0x0+([1-9])', '0x\\1', off)
            print 'FOUND:', mod, off
            candidates.append((mod, off))

    return candidates

# run under dr_cmd to get fopen function and addr
def get_mod_off(run_cmd):
    candidates = get_fopen(run_cmd)

    if len(candidates) == 0:
        print 'No fopen candidates found.'
        return None, None
    elif len(candidates) == 1:
        mod, off = candidates[0]
    else:
        idx = 0
        for candidate in candidates:
            print '%d) %s %s' % (idx, candidates[idx])
            idx += 1

        selection = ''
        while not selection.isdigit() and int(selection) < 0 or int(selection) >= idx:
            selection = raw_input('Select your target function (0-%d): ' % (idx-1))
        
        selection = int(selection)
        mod, off = candidates[selection]

    print 'Using module %s and offset %s.' % (mod, off)
    return mod, off

def mkdir_ifne(path):
    if not os.path.exists(path):
        os.mkdir(path)

# create in and out directories and copy file to in_dir
def init_dirs(sys_config, run_config):
    run_id = str(int(time.time()))
    
    base = sys_config['path_winafl_working_dir']
    in_dir = os.path.join(base, '%s_in' % run_id)
    crash_dir = os.path.join(base, '%s_crash' % run_id)
    
    mkdir_ifne(base)
    mkdir_ifne(in_dir)
    mkdir_ifne(out_dir)

    shutil.copy(run_config['file'], in_dir)
    return in_dir, out_dir

# create winafl command
def winafl(sys_config, run_config):
    winafl_cmd = [
        # 'C:\\Users\\Douglas\\Documents\\work\\winafl\\build64\\Release\\afl-fuzz.exe',
        os.path.join(sys_config['path_winafl'], 'afl-fuzz.exe'),
        '-i',
        run_config['in_dir'],
        '-o',
        run_config['crash_dir'],
        '-D',
        sys_config['path_dynamorio'],
        # 'C:\\Users\\Douglas\\Documents\\work\\dynamorio\\bin64\\',
        '-t',
        run_config['winafl_timeout'],
        '-f',
        run_config['file'],
        '--',
        '-coverage_module',
        run_config['module'],
        '-target_module',
        run_config['module'],
        '-target_offset',
        run_config['offset'],
        '-nargs',
        run_config['winafl_nargs'],
        '--'
    ]

    winafl_cmd += run_cmd
    for ea in winafl_cmd:
        print ea,
    print

    # run
    proc = subprocess.Popen(winafl_cmd, cwd=sys_config['path_winafl'])
    return proc

# same as vmfuzz utils, didn't want to import
def load_config(config_file):
    f = open(config_file, 'r')
    config = yaml.load(f)
    f.close()
    return config

def check_config(config, required):
    missing = []
    for req in required:
        if req not in config:
            missing.append(req)
    return missing

def check_configs(sys_config, run_config):
    sys_required = ['path_winafl', 'path_dynamorio', 'path_winafl_working_dir']
    sys_missing = check_config(sys_config, sys_required)
    run_required = ['job_name', 'command', 'file', 'module', 'offset', 'winafl_nargs', 'winafl_timeout', 'run_time']
    run_missing = check_config(run_config, run_required)
    return {'sys': sys_missing, 'run': run_missing}

def run_configs_file(sys_config_file, run_config_file):
    sys_config = load_config(sys_config_file)
    run_config = load_config(run_config_file)
    run_configs(sys_config, run_config)

def run_configs(sys_config, run_config)
    missing = check_configs(sys_config, run_config)

    # at this point nothing should be missing
    # web interface should handle it
    if len(missing['sys']) != 0 or len(missing['job']) != 0:
        return {'status': 'error', 'missing': missing}