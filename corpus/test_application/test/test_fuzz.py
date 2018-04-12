import subprocess
import json
import os

with open('config.json') as f:
    config = json.loads(f.read())

dr_path = config['dr_path']
sienna_path = config['sienna_path']

drrun_path = os.path.join(dr_path, r'bin64\drrun.exe')
fuzzer_path = os.path.join(sienna_path, r'build\fuzz_dynamorio\Debug\fuzzer.dll')
test_application_path = os.path.join(sienna_path, r'build\corpus\test_application\Debug\test_application.exe')

test_number = 0

functions = [
    'ReadFile',
    'recv',
    'WinHttpReadData',
    'InternetReadFile',
    'RegQueryValueExW,RegQueryValueExA',
    'WinHttpWebSocketReceive',
    # 'ReadEventLog',
]

cmd = [drrun_path, '-c', fuzzer_path, '-i', functions[test_number], '--', test_application_path, str(test_number), '-f']

proc = subprocess.Popen(cmd)
proc.wait()