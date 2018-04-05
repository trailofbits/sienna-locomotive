import subprocess
import json
import os 

# drrun_path -c tracer_path -- crashes_path N
drrun_path = 'C:\\Users\\dgoddard\\Documents\\work\\DynamoRIO\\bin64\\drrun.exe'
tracer_path = 'C:\\Users\\dgoddard\\Documents\\GitHub\\sienna-locomotive\\triage_dynamorio\\build\\Debug\\tracer.dll'
crashes_path = 'C:\\Users\\dgoddard\\Documents\\GitHub\\sienna-locomotive\\corpus\\win_asm\\crashes.exe'

proc = subprocess.Popen([crashes_path], stdout=subprocess.PIPE)
stdout, _ = proc.communicate()
lines = [ea.split(b'\t') for ea in stdout.split(b'\n') if b'\t' in ea]

print(lines)

'''
stack_ptr_ret_t - 
windows can not recover from errors with no stack, hard crash
try: find a way to detect this scenario

double_free_nt -
detected by the system
does not result in an exception

dep - 
it looks like dynamorio is making heap allocations executable

stack_exec - 
stack is executable
try: see if dynamo is changing permissions or we just need nx on crashes.exe
'''
skip = [b'stack_ptr_ret_t', b'double_free_nt', b'dep', b'stack_exec']

def output_tests():
    for line in lines:
        data_path = os.path.join('data', '{}.json'.format(line[1].decode()))
        if line[1] in skip: #  os.path.exists(data_path) or 
            print('Skipping {}, {}'.format(line[1], line[0]))
            continue

        print('Running {}, {}'.format(line[1], line[0]))
        cmd = [drrun_path, '-c', tracer_path, '--', crashes_path, line[0].decode()]
        print(' '.join(cmd))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        stdout, _ = proc.communicate()
        # print(stdout)
        crash_data = json.loads(stdout.split(b'#### BEGIN CRASH DATA JSON\n')[1].split(b'#### END CRASH DATA JSON\n')[0])

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
        cmd = [drrun_path, '-c', tracer_path, '--', crashes_path, line[0].decode()]
        print(' '.join(cmd))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        stdout, _ = proc.communicate()
        crash_data = json.loads(stdout.split(b'#### BEGIN CRASH DATA JSON\n')[1].split(b'#### END CRASH DATA JSON\n')[0])

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
# output_tests()