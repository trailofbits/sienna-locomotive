import os
import re
import sys
import yaml
import json
import subprocess

# run program

# extract results

# proper errors

# send results to web

def init(config_path):
    '''
    Validates and initializes paths.
    '''
    arch_lookup = {
        32: 'obj-ia32',
        64: 'obj-intel64',
    }

    if not os.path.exists(config_path):
        print 'ERROR: could not find config at %s' % config_path
        sys.exit(1)

    global config
    config_path = os.path.join(os.path.dirname(__file__), config_path)
    with open(config_path) as f:
        config = f.read()

    config = yaml.load(config)

    arch = config['program_arch']
    try:
        assert int(arch) in arch_lookup
        arch = int(arch)
    except (ValueError, AssertionError):
        print 'ERROR: invalid arch %s' % str(arch)
        sys.exit(1)

    config['arch'] = arch

    tool_path = os.path.join(config['tool_dir'], arch_lookup[arch], 'taint.so')
    if not os.path.exists(tool_path):
        print 'ERROR: cannot find taint.so at %s' % tool_path
        sys.exit(1)
    config['tool_path'] = tool_path

    pin_path = os.path.join(config['pin_dir'], 'pin')
    if not os.path.exists(pin_path):
        print 'ERROR: cannot find pin at %s' % pin_path
        sys.exit(1)
    config['pin_path'] = pin_path

    if 'tainted_file' not in config:
        print 'WARNING: tainted_file not set, using __STDIN'
        config['tainted_file'] = '__STDIN'

    config['cmd'] = [config['pin_path'], '-t', config['tool_path'], '-f', config['tainted_file'], '--']
    config['cmd'] += [os.path.join(config['path_program'], config['program_name'])]
    config['cmd'] += [str(ea) for ea in config['program_params']]

def extract_results(out):
    pattern = '#### BEGIN CRASH DATA JSON\n.*?#### END CRASH DATA JSON'
    matches = re.findall(pattern, out, re.DOTALL)

    if len(matches) == 0:
        print 'FAIL'
        print 'ERROR: no json found'
        print out
        sys.exit(1)

    if len(matches) > 1:
        print 'FAIL'
        print 'ERROR: multiple json found'
        sys.exit(1)        

    result_str = matches[0]
    results = '\n'.join(result_str.split('\n')[1:-1])
    results = json.loads('\n'.join(result_str.split('\n')[1:-1]))

    return results

def run():
    proc = subprocess.Popen(config['cmd'], stdout=subprocess.PIPE)
    out, _ = proc.communicate()
    print extract_results(out)

def usage():
    print 'USAGE: python %s config_path'
    sys.exit(1)

def main():
    if len(sys.argv) == 1:
        usage()

    init(sys.argv[1])

    run()


if __name__ == '__main__':
    main()