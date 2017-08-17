import subprocess
import yaml
import json
import sys
import os

def init():
    '''
    Validates and initializes paths.
    '''

    global config
    with open('../config.yaml') as f:
        config = f.read()

    config = yaml.load(config)

    tool_path = os.path.join(config['tool_dir'], 'obj-intel64', 'taint.so')
    if not os.path.exists(tool_path):
        print 'ERROR: cannot find taint.so at %s' % tool_path
        sys.exit(1)
    config['tool_path'] = tool_path

    pin_path = os.path.join(config['pin_dir'], 'pin')
    if not os.path.exists(pin_path):
        print 'ERROR: cannot find pin at %s' % pin_path
        sys.exit(1)
    config['pin_path'] = pin_path

    crashy_path = os.path.join(config['sienna_dir'], 'triage', 'corpus', 'asm', 'crashy_mccrashface')
    if not os.path.exists(crashy_path):
        print 'ERROR: cannot find crasy_mccrashface at %s' % crashy_path
        sys.exit(1)
    config['crashy_path'] = crashy_path

def get_tests():
    '''
    Get the intersection between tests in crashy_mccrashface and 
    tests that we have expected output for (in data/).
    '''

    scratch_file = os.path.join(config['tmp_dir'], 'crash_test_scratch')
    out_file = os.path.join(config['tmp_dir'], 'crash_test_out')
    cmd = [config['pin_path'], '-t', config['tool_path'], '-f', scratch_file, '--', config['crashy_path']]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    out, _ = proc.communicate()
    
    tests = [ea for ea in out.split('\n')[1:] if '\t' in ea]
    lookup = {}
    for ea in tests:
        num, name = ea.split('\t')
        lookup[name] = num

    flist = os.listdir('data')
    flist = set([ea.split('.')[0] for ea in flist if '.json' in ea])

    tests = set(lookup.keys()) & flist
    return tests, lookup

def initialize_data(lookup):
    '''
    For creating expected output files from the tests' actual output.
    Useful if test data is ever lost.
    '''

    scratch_file = os.path.join(config['tmp_dir'], 'crash_test_scratch')
    out_file = os.path.join(config['tmp_dir'], 'crash_test_out')

    for ea in lookup:
        print ea
        cmd = [config['pin_path'], '-t', config['tool_path'], '-f', scratch_file]
        cmd += ['--', config['crashy_path'], lookup[ea]]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        out, _ = proc.communicate()

        fname = 'data/%s._json' % ea
        with open(fname, 'w') as f:
            f.write(out)

def run_tests(tests, lookup):
    '''
    Test loop.
    '''

    scratch_file = os.path.join(config['tmp_dir'], 'crash_test_scratch')
    out_file = os.path.join(config['tmp_dir'], 'crash_test_out')
    results = {}

    for test in tests:
        cmd = [config['pin_path'], '-t', config['tool_path'], '-f', scratch_file]
        cmd += ['--', config['crashy_path'], lookup[test]]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        out, _ = proc.communicate()

        data = json.loads(out)
        expected_path = 'data/%s.json' % test
        with open(expected_path) as f:
            expected_contents = f.read()
        expected = json.loads(expected_contents)

        if data['verdict'] != expected['verdict']:
            results[test] = False
            continue

        if data['signal'] != expected['signal']:
            results[test] = False
            continue

        if len(set(expected['tainted_regs']) - set(data['tainted_regs'])) != 0:
            results[test] = False
            continue

        results[test] = True

    print results



def main():
    init()

    tests, lookup = get_tests()
    print tests

    run_tests(tests, lookup)

    return 0

if __name__ == '__main__':
    main()