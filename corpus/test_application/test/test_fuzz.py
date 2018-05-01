import subprocess
import json
import sys
import os

def print_usage():
    print('USAGE: {} TEST_NUMBER'.format(sys.argv[0]))
    print('TEST NUMBERS:')
    print('  0\tReadFile')
    print('  1\trecv')
    print('  2\tWinHttpReadData')
    print('  3\tInternetReadFile')
    print('  4\tRegQueryValueEx')
    print('  5\tWinHttpWebSocketReceive')

def main():
    test_number = 1

    functions = [
        'ReadFile',
        'recv',
        'WinHttpReadData',
        'InternetReadFile',
        'RegQueryValueExW,RegQueryValueExA',
        'WinHttpWebSocketReceive',
        # 'ReadEventLog',
    ]

    if len(sys.argv) != 2:
        print('ERROR: not enough arguments')
        print_usage()
        return

    try:
        test_number = int(sys.argv[1])
    except ValueError:
        print('ERROR: argument not int')
        print_usage()
        return

    if test_number not in range(0, len(functions)):
        print('ERROR: test number out of range')
        print_usage()
        return

    with open('config.json') as f:
        config = json.loads(f.read())

    dr_path = config['dr_path']
    sienna_path = config['sienna_path']

    drrun_path = os.path.join(dr_path, r'bin64\drrun.exe')
    fuzzer_path = os.path.join(sienna_path, r'build\fuzz_dynamorio\Debug\fuzzer.dll')
    test_application_path = os.path.join(sienna_path, r'build\corpus\test_application\Debug\test_application.exe')

    while True:
        if test_number == 1:
            socket_server_path = os.path.join(sienna_path, r'build\corpus\test_application\Debug\socket_server.exe')
            sock_proc = subprocess.Popen(socket_server_path)

        cmd = [drrun_path, '-c', fuzzer_path, '-i', functions[test_number], '--', test_application_path, str(test_number), '-f']

        proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        out, err = proc.communicate()
        print('out', out)
        print('err', err)
        print('========')
        if b'<crash found for run id ' in err:
            print(err)
            break

if __name__ == '__main__':
    main()