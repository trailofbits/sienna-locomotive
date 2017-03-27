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
                         'parameters': ['C:\\Program Files\\ClamAV\\clambc.exe', '-d', '<FILE>'],
                         'file_format': '.ldb', 'seed_pattern': '*.ldb',
                         'auto_close': True,
                         'using_autoit': False,
                         'program_name': 'clamscan.exe',
                         'arch': 'x86',
                         'running_time': 2}

config_run_clamav_all = {'input_dir': 'F:\\winafl\\in_clamscan',
                         'crash_dir': 'F:\\winafl\\crash_clamsav',
                         'timestamp': 'XXXX',
                         'run_type': 'all'}

config_run_clamav_winafl_targets = {'input_dir': 'F:\\winafl\\in_clamscan',
                                    'crash_dir': 'F:\\crashes',
                                    'timestamp': 'YYYY',
                                    'run_type': 'winafl_run_targets',
                                    'targets': [{'module': 'libclamav.dll', 'offset': '0x8cbe0', 'cov_modules': ['libclamav.dll']},
                                                {'module': 'clamscan.exe', 'offset': '0x1000', 'cov_modules': ['libclamav.dll', 'clamscan.exe']},
                                                {'module': 'clamscan.exe', 'offset': '0x1040', 'cov_modules': ['libclamav.dll', 'clamscan.exe']}
                                               ]
                                    }


#vmfuzz.fuzz(config_system, config_program_clamav, config_run_clamav_all)

vmfuzz.fuzz(config_system, config_program_clamav, config_run_clamav_winafl_targets)
