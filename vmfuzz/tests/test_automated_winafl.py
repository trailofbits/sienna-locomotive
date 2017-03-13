import os
from context import vmfuzz
import vmfuzz as vm
import fuzzers.winafl.compute_offset as compute_offset
import fuzzers.winafl.winafl as winafl
os.chdir('..')

compute_offset.WINGDB_PATH = "C:\\Program Files\\Windows Kits\\10\\Debuggers\\x86\\"
compute_offset.WINGDB_SCRIPT = r"E:\\vmfuzz\\fuzzers\\winafl\\compute_offset_windbg.py"
compute_offset.AUTOIT_BIN = r"C:\Program Files\AutoIt3\AutoIt3.exe"


winafl.AUTOIT_BIN = r"C:\Program Files\AutoIt3\AutoIt3.exe"
winafl.WINAFL_PATH = "C:\\Users\\monty\\Desktop\\test_afl_auto\\"
winafl.WINAFL_BIN = "afl-fuzz.exe"
winafl.DYNAMORIO_PATH = r"C:\Users\monty\Documents\dynamorio\build\bin32"
winafl.DRRUN = r"C:\Users\monty\Documents\dynamorio\build\bin32\drrun.exe"
winafl.WINAFLDLL = r"C:\Users\monty\winafl\bin32\winafl.dll"
winafl.WINAFL_WORKING_DIR = "F:\\winafl\\"
winafl.WINAFL_DEFAULT_TIMEOUT = 40000

config = vm.parse_config('yaml_config\\configEasyRmtoMP3.yaml')
vm.check_user_config(config)
winafl.launch_fuzzing(config)
