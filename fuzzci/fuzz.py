from pprint import pprint
import subprocess
import argparse
import shlex
import yaml
import os

# TODO: break out into utility script
# init fuzz folder
'''Make directory if not exists'''
def mkdir_ifne(path):
    if not os.path.exists(path):
        os.mkdir(path)

'''Initialize a new target folder and requisite files'''
def init_target(name):
    mkdir_ifne('.fuzzci')

    base_path = os.path.join('.fuzzci', name)
    mkdir_ifne(base_path)

    corpus_path = os.path.join(base_path, corpus)
    mkdir_ifne(corpus_path)

    # touch config.yml
    config_path = os.path.join(base_path, 'config.yml')
    with open(config_path, 'a'):
        pass

    # touch entry.cc
    entry_path = os.path.join(base_path, 'entry.cc')
    with open(entry, 'a'):
        pass

def get_config(target):
    base_path = os.path.join('.fuzzci', target)
    config_path = os.path.join(base_path, 'config.yml')

    if not os.path.exists(config_path):
        return None

    with open(config_path) as conf_file:
        config = yaml.load(conf_file)
        
    return config

# build fuzz binary
def build_target(commands):
    base_dir = os.getcwd()
    for cmd in commands:
        cmd_list = shlex.split(cmd)

        # cd doesn't work in Popen so we do this
        if len(cmd_list) == 2 and cmd_list[0] == 'cd':
            os.chdir(cmd_list[1])
        else:
            proc = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate()
            if proc.returncode != 0:
                print 'ERROR: non-zero return code'
                print 'Abandoning run!'
                print
                print 'stdout: '
                print out
                print
                print 'stderr: '
                print err
                return False

    os.chdir(base_dir)

    return True

def set_options(cmd, config):
    if 'options' in config:
        options = config['options']
        for opt in options:
            cmd.append('%s=%s' % (opt, options[opt]))

    if 'options' not in config or '-artifact_prefix' not in config['options']:
        cmd.append('-artifact_prefix=%s' % config['corpus'])

    return cmd

# run fuzz binary
def fuzz_target(config):
    executable = config['executable']
    corpus = config['corpus']
    cmd = [executable, corpus]
    
    set_options(cmd, config)
    print cmd

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    print out
    print err
    return err

def validate_config(config):
    print config
    required = ['corpus', 'build', 'executable']
    for req in required:
        if req not in config:
            print 'ERROR: %s required in config' % req
            return False

    return True

def test_target(config):
    executable = config['executable']
    corpus = config['corpus']
    results = {}
    for corpse in os.listdir(corpus):
        corpse_path = os.path.join(corpus, corpse)
        cmd = [executable, corpse_path, '-close_fd_mask=3']
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        results[corpse] = err

    for corpse in results:
        print '*' * 64
        print corpse
        print '*' * 64
        print results[corpse]
        print

    return results

def fuzz_one_target(target):
    config = get_config(target)
    validated = validate_config(config)
    
    if not validated:
        return 'ERROR: config failed to validate'
        
    built = build_target(config['build'])
    if not built:
        return 'ERROR: build failure'

    return fuzz_target(config)

def fuzz_all_targets():
    targets = ['target_parse']
    results = {}

    for target in targets:
        fuzz_results = fuzz_one_target(target)
        results[target] = fuzz_results

    return results

def test_one_target(target):
    config = get_config(target)

    if config is None:
        return 'ERROR: config not found'

    validated = validate_config(config)
    
    if not validated:
        return 'ERROR: config failed to validate'
        
    built = build_target(config['build'])
    if not built:
        return 'ERROR: build failure'

    test_results = test_target(config)
    return test_results

def test_all_targets():
    targets = ['target_parse']
    results = {}
    
    for target in targets:
        test_results = test_one_target(target)
        results[target] = test_results

    return results

if __name__ == '__main__':
    fuzz_all_targets()