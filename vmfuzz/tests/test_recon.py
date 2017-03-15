import os
import logging
from context import vmfuzz

import fuzzers.winafl.winafl as winafl
import fuzzers.winafl.recon as winafl_recon
import utils.parsing_config as parsing_config
os.chdir('..')

logging.basicConfig(filename="test_recon.log", filemode='w', level=logging.DEBUG)

config_system = parsing_config.parse_config('yaml_config\\system.yaml')
parsing_config.check_system_config(config_system)
winafl.init(config_system)

config = parsing_config.parse_config('yaml_config\\configClamAV.yaml')
parsing_config.check_user_config(config)

interested_targets = winafl_recon.launch_recon(config)

winafl_recon.save_targets(config, interested_targets)

