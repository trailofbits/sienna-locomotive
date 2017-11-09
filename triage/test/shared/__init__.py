import json
import yaml
import sys
import os
import re

def init(arch):
    '''
    Validates and initializes paths.
    '''
    arches = {
        32: 'obj-ia32',
        64: 'obj-intel64',
    }

    global config
    config_path = os.path.join(os.path.dirname(__file__), '../config.yaml')
    with open(config_path) as f:
        config = f.read()

    config = yaml.load(config)

    if os.name == 'nt':
        tool_path = os.path.join(config['path_tool'], 'taint.dll')
    else:
        tool_path = os.path.join(config['path_tool'], arches[arch], 'taint.so')

    if not os.path.exists(tool_path):
        print 'ERROR: cannot find taint.so at %s' % tool_path
        sys.exit(1)
    config['tool_path'] = tool_path

    if os.name == 'nt':
        pin_path = os.path.join(config['path_pin'], 'pin.exe')
    else:
        pin_path = os.path.join(config['path_pin'], 'pin')

    if not os.path.exists(pin_path):
        print 'ERROR: cannot find pin at %s' % pin_path
        sys.exit(1)
    config['pin_path'] = pin_path

def regs_match(expected, data):
    return set(expected['tainted_regs']) == set(expected['tainted_regs'])

def regs_contain(expected, data):
    if len(set(expected['tainted_regs']) - set(data['tainted_regs'])) != 0:
        return False
    return True

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

def main():
    shared_init()
    if len(sys.argv) > 1:
        print sys.argv[1]
        test_set = sys.argv[1]
        mod = __import__(test_set)
        run = getattr(mod, 'run')
        run()

if __name__ == '__main__':
    main()