import subprocess
import shutil
import time
import sys
import os
import re

def get_fopen(run_cmd):
    dr_cmd = [
        'C:\\Users\\Douglas\\Documents\\work\\dynamorio\\bin64\\drrun.exe',
        '-c',
        'C:\\Users\\Douglas\\Documents\\work\\dynamorio\\samples\\build\\bin\\instrcalls.dll',
        '--'
    ]

    dr_cmd += run_cmd
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
def init_dirs(file):
    run_id = str(int(time.time()))
    
    in_dir = 'C:\\Users\\Douglas\\Desktop\\fuzz\\%s_in' % run_id
    out_dir = 'C:\\Users\\Douglas\\Desktop\\fuzz\\%s_out' % run_id
    
    mkdir_ifne('C:\\Users\\Douglas\\Desktop\\fuzz')
    mkdir_ifne(in_dir)
    mkdir_ifne(out_dir)

    shutil.copy(file, in_dir)
    return in_dir, out_dir

# create winafl command
def winafl(run_cmd, config):
    winafl_cmd = [
        'C:\\Users\\Douglas\\Documents\\work\\winafl\\build64\\Release\\afl-fuzz.exe',
        '-i',
        config['in_dir'],
        '-o',
        config['out_dir'],
        '-D',
        'C:\\Users\\Douglas\\Documents\\work\\dynamorio\\bin64\\',
        '-t',
        config['timeout'],
        '-f',
        config['file'],
        '--',
        '-coverage_module',
        config['module'],
        '-target_module',
        config['module'],
        '-target_offset',
        config['offset'],
        '-nargs',
        config['nargs'],
        '--'
    ]

    winafl_cmd += run_cmd
    for ea in winafl_cmd:
        print ea,
    print

    # run
    proc = subprocess.Popen(winafl_cmd, cwd='C:\\Users\\Douglas\\Documents\\work\\winafl\\build64\\Release\\')
    time.sleep(60*config['time_limit'])
    proc.terminate()
    return True

def restore_sigs():
    file = 'C:\\Users\\Douglas\\Desktop\\fuzz\\sigs.ldb'
    shutil.copy('C:\\Users\\Douglas\\Desktop\\fuzz\\_sigs.ldb', 'C:\\Users\\Douglas\\Desktop\\fuzz\\sigs.ldb')

def main():
    # specify run command 
    run_cmd = [
        'C:\\PF\\ClamAV-x64\\clamscan.exe',
        '-d',
        'C:\\Users\\Douglas\\Desktop\\fuzz\\sigs.ldb',
        'C:\\PF\\ClamAV-x64\\clambc.exe'
    ]

    restore_sigs()

    # specify file
    file = 'C:\\Users\\Douglas\\Desktop\\fuzz\\sigs.ldb'

    mod, off = get_mod_off(run_cmd)

    in_dir, out_dir = init_dirs(file)

    config = {
        'in_dir': in_dir,
        'out_dir': out_dir,
        'file': 'C:\\Users\\Douglas\\Desktop\\fuzz\\sigs.ldb',
        'module': mod,
        'offset': off,
        'nargs': '5',
        'timeout': '10000+',
    }

    winafl(run_cmd, config)

if __name__ == '__main__':
    main()