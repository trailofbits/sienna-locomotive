from .. import shared
import subprocess
import yaml
import json
import sys
import os
import re

def init():
    '''
    Validates and initializes paths.
    '''
    shared.init(64)

    crashy_path = os.path.join(shared.config['path_sienna'], 'triage', 'corpus', 'win_asm', 'crashes.exe')
    if not os.path.exists(crashy_path):
        print 'ERROR: cannot find crashes.exe at %s' % crashy_path
        sys.exit(1)
    shared.config['crashy_path'] = crashy_path

    data_path = os.path.join(shared.config['path_sienna'], 'triage/test/win_asm/data/')
    shared.config['data_path'] = data_path

def get_tests():
    '''
    Get the intersection between tests in crashy_mccrashface and 
    tests that we have expected output for (in data/).
    '''

    scratch_file = 'crash_scratch.txt'
    out_file = os.path.join(shared.config['path_tmp'], 'crash_test_out.txt')
    cmd = [shared.config['pin_path'], '-t', shared.config['tool_path']]
    cmd += ['--', shared.config['crashy_path']]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    out, _ = proc.communicate()
    print 'OUT: ', out
    tests = [ea for ea in out.split('\n')[1:] if '\t' in ea]
    lookup = {}
    for ea in tests:
        num, name = ea.split('\t')
        lookup[name] = num

    flist = os.listdir(shared.config['data_path'])
    flist = set([ea.split('.')[0] for ea in flist if '.json' in ea])

    tests = set(lookup.keys()) & flist
    return tests, lookup

def initialize_data(lookup):
    '''
    For creating expected output files from the tests' actual output.
    Useful if test data is ever lost.
    '''

    scratch_file = os.path.join(shared.config['path_tmp'], 'crash_scratch.txt')
    out_file = os.path.join(shared.config['path_tmp'], 'crash_test_out.txt')
    print lookup

    for ea in lookup:
        print ea
        cmd = [shared.config['pin_path'], '-t', shared.config['tool_path'], '-f', scratch_file]
        cmd += ['--', shared.config['crashy_path'], lookup[ea]]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        out, _ = proc.communicate()

        fname = os.path.join(shared.config['data_path'], '_%s.json' % ea)
        with open(fname, 'w') as f:
            f.write(out)

def run_tests(tests, lookup):
    '''
    Test loop.
    '''

    scratch_file = os.path.join(shared.config['path_tmp'], 'crash_scratch.txt')
    out_file = os.path.join(shared.config['path_tmp'], 'crash_test_out.txt')
    results = {}

    for test in tests:
        print 'RUNNING: %s' % test,
        cmd = [shared.config['pin_path'], '-t', shared.config['tool_path'], '-f', scratch_file]
        cmd += ['--', shared.config['crashy_path'], lookup[test]]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        out, _ = proc.communicate()

        data = shared.extract_results(out)
        expected_path = os.path.join(shared.config['data_path'], '%s.json' % test)

        with open(expected_path) as f:
            expected_contents = f.read()
        expected = json.loads(expected_contents)

        if data['score'] != expected['score']:
            print 'FAIL'
            results[test] = False
            continue

        if data['signal'] != expected['signal']:
            print 'FAIL'
            results[test] = False
            continue

        if not shared.regs_contain(expected, data):
            print 'FAIL'
            results[test] = False
            continue

        print 'OK'
        results[test] = True

    print results

def run():
    init()

    tests, lookup = get_tests()
    print tests

    # initialize_data(lookup)
    run_tests(tests, lookup)

    return 0

if __name__ == '__main__':
    run()