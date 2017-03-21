import os
from context import vmfuzz
os.chdir('..')

config_system = {'fuzzers': ['radamsa', 'winafl'],
                 'path_windbg': 'C:\\Program Files\\Windows Kits\\10\\Debuggers',
                 'path_vmfuzz': 'E:\\vmfuzz',
                 'path_radamsa': 'C:\\cygwin\\bin',
                 'path_autoit': 'C:\\Program Files\\AutoIt3',
                 'path_dynamorio': 'C:\\Users\\monty\\DynamoRIO',
                 'path_winafl': 'C:\\Users\\monty\\winafl',
                 'path_radamsa_working_dir': 'F:\\radamsa',
                 'path_autoit_working_dir': 'C:\\Users\\monty\\Desktop\\autoit',
                 'path_winafl_working_dir': 'F:\\winafl3'}


config_program_clamav = {'path_program': 'C:\\Program Files\\ClamAV',
                         'parameters': ['C:\\Program Files\\ClamAV\\clambc.exe', '-d'],
                         'file_format': '.ldb', 'seed_pattern': '*.ldb',
                         'auto_close': True,
                         'using_autoit': False,
                         'program_name': 'clamscan.exe',
                         'arch': 'x86',
                         'running_time': 2}

config_run_clamav_all = {'input_dir': 'F:\\winafl\\in_clamscan',
                         'crash_dir': 'F:\\crashes',
                         'timestamp': 'XXXX',
                         'radamsa_number_files_to_create': 100,
                         'winafl_last_path_timeout': 45,
                         'winafl_fuzzing_iteration': 100000,
                         'winafl_default_timeout': 40000,
                         'type': 'all'}

config_run_clamav_winafl_targets = {'input_dir': 'F:\\winafl\\in_clamscan',
                                    'crash_dir': 'F:\\crashes',
                                    'radamsa_number_files_to_create': 100,
                                    'winafl_last_path_timeout': 45,
                                    'winafl_fuzzing_iteration': 100000,
                                    'winafl_default_timeout': 40000,
                                    'timestamp': 'YYYY',
                                    'type': 'winafl_run_targets',
                                    'targets': [['libclamav.dll', '0x8cbe0', 'libclamav.dll'],
                                                ['clamscan.exe', '0x1000', 'clamscan.exe'],
                                                ['clamscan.exe', '0x1040', 'clamscan.exe']]}


#vmfuzz.fuzz(config_system, config_program_clamav, config_run_clamav_all)
vmfuzz.fuzz(config_system, config_program_clamav,
            config_run_clamav_winafl_targets)
