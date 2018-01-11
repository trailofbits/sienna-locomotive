import subprocess
import json
import os 

'''
TODO:
xor_clear_nt - does not clear taint
dep - check memory permissions (nx)
stack exec 
break points
double free - can we detect these?
use after free - can we detect these?
'''
skip = [b'break_point', b'dep', b'use_after_free', b'double_free', b'stack_exec', b'xor_clear_nt']


crashes_path = '../../../corpus/win_asm/crashes.exe'
fuzzkit_base = '../../x64/Release/'
fuzzkit_path = os.path.join(fuzzkit_base, 'fuzzkit.exe')
triage_path = os.path.join(fuzzkit_base, 'triage.exe')

proc = subprocess.Popen([crashes_path], stdout=subprocess.PIPE)
stdout, _ = proc.communicate()

print(type(stdout))

lines = [ea.split(b'\t') for ea in stdout.split(b'\n') if b'\t' in ea]

print(lines)


def output_tests():
    for line in lines:
        data_path = os.path.join('data', '{}.json'.format(line[1].decode()))
        if os.path.exists(data_path) or line[1] in skip:
            print('Skipping {}, {}'.format(line[1], line[0]))
            continue

        print('Running {}, {}'.format(line[1], line[0]))
        print(' '.join([fuzzkit_path, '-t', crashes_path, line[0].decode()]))
        proc = subprocess.Popen([fuzzkit_path, '-t', crashes_path, line[0].decode()], stdout=subprocess.PIPE)
        stdout, _ = proc.communicate()
        runid = [ea.split(b' ')[2] for ea in stdout.split(b'\r\n') if ea.startswith(b'RUN ID: ')][0]

        print(' '.join([triage_path, '-r', runid.decode()]))
        proc = subprocess.Popen([triage_path, '-r', runid.decode()], stdout=subprocess.PIPE)
        stdout, _ = proc.communicate()
        crash_data = json.loads(stdout.split(b'#### BEGIN CRASH DATA JSON\r\n')[1].split(b'#### END CRASH DATA JSON\r\n')[0])

        with open(data_path, 'wb+') as f:
            f.write(json.dumps(crash_data).encode())

def run_tests():
    results = {}

    for line in lines:
        data_path = os.path.join('data', '{}.json'.format(line[1].decode()))
        if line[1] in skip:
            print('Skipping {}, {}'.format(line[1], line[0]))
            continue

        print('Running {}, {}'.format(line[1], line[0]))
        print(' '.join([fuzzkit_path, '-t', crashes_path, line[0].decode()]))
        proc = subprocess.Popen([fuzzkit_path, '-t', crashes_path, line[0].decode()], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = proc.communicate()
        runid = [ea.split(b' ')[2] for ea in stdout.split(b'\r\n') if ea.startswith(b'RUN ID: ')][0]

        print(' '.join([triage_path, '-r', runid.decode()]))
        proc = subprocess.Popen([triage_path, '-r', runid.decode()], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = proc.communicate()
        crash_data = json.loads(stdout.split(b'#### BEGIN CRASH DATA JSON\r\n')[1].split(b'#### END CRASH DATA JSON\r\n')[0])

        with open(data_path) as f:
            crash_truth = json.loads(f.read())

        print(json.dumps(crash_data))
        print(json.dumps(crash_truth))

        if crash_data['score'] != crash_truth['score'] \
            or crash_data['reason'] != crash_truth['reason'] \
            or crash_data['exception'] != crash_truth['exception']:
            results[line[1].decode()] = 'FAIL'
        else:
            results[line[1].decode()] = 'PASS'

    return results

results = run_tests()
print(results)