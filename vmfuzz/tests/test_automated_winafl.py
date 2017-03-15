import os
from context import vmfuzz
import vmfuzz as vm
import utils.parsing_config as parsing_config
import fuzzers.winafl.compute_offset as compute_offset
import fuzzers.winafl.winafl as winafl
os.chdir('..')

config = parsing_config.parse_config('yaml_config\\configEasyRmtoMP3.yaml')
parsing_config.check_user_config(config)

system_config = parsing_config.parse_config('yaml_config\\system.yaml')
parsing_config.check_system_config(system_config)
vm.init_system(system_config)

winafl.launch_fuzzing(config)
