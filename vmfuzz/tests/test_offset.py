import os
from context import vmfuzz

import fuzzers.winafl.winafl as winafl
import utils.parsing_config as parsing_config
os.chdir('..')

config_system = parsing_config.parse_config('yaml_config\\system.yaml')
parsing_config.check_system_config(config_system)
winafl.init(config_system)

config = parsing_config.parse_config('yaml_config\\configClamAV.yaml')
parsing_config.check_user_config(config)

## Only needed if you want to print the winafl command
targets = winafl.compute_targets(config)
config_winafl = winafl.generate_config_winafl(config)
running_cmd = winafl.generate_running_cmd(config)

for (off, mod) in targets:
    print "Offset found: " + hex(off) + " in module: " + str(mod)

    ## Print the winafl command
    config_winafl['offset'] = hex(off)
    config_winafl['module'] = mod
    config_winafl['out_dir'] = config_winafl[
        'out_dir_ori'] + "_" + mod + "_" + hex(off)
    cmd = winafl.generate_winafl_cmd(config_winafl, running_cmd)
    print "Running cmd: " + winafl.pp_cmd(cmd) + " @@"
