""" Module used to perform quick winafl testing """
import os
import yaml
import fuzzers.winafl.winafl as winafl
import fuzzers.winafl.winafl_constants as winafl_constants
import fuzzers.winafl.stats as winafl_stats
import utils.logs as logging


def get_targets(path_file):
    """
    Get targets from a file

    Args:
        path_file (string): input file
    Returns:
        (int,string) list: targets
    Note:
        targets are read in plain text as :
        0x0,module1
        0x1,module2
    """
    input_file = open(os.path.join(winafl_constants.WINAFL_WORKING_DIR,
                                   path_file), "r")
    targets = yaml.load(input_file)
    input_file.close()
    return targets['targets']


def save_targets(targets, path_file):
    """
    Save targets into a file

    Args:
        interesting_targets ((int,string) list): targets to save
        path_file (string): output file
    Note:
        targets are stored in plain text as :
        0x0,module1
        0x1,module2
    """
    output_file = open(os.path.join(winafl_constants.WINAFL_WORKING_DIR,
                                    path_file),
                       "w")
    targets = {'targets': targets}
    yaml.dump(targets, output_file)
    output_file.close()


def launch_recon(config, t_fuzz_stopped):
    """
    Launch the recon mode of winafl \n
    The recon mode compute the offsets, try each one \n
    for 2 mins and export the one working with winafl

    Args:
        config (dict): the user configuration
    Returns:
        (int,string) list: The list of interesting targets
    Note:
        Winafl is launched for 2 min on each target.
        If not new path is found the target is not considered
    """
    prev_last_path_timeout = config['winafl_last_path_timeout']
    config['winafl_last_path_timeout'] = 1

    targets = winafl.compute_targets(config)

    print "Targets "+str(targets)
    config_winafl = winafl.generate_config_winafl(config)

    config_winafl['winafl_max_time'] = 60 * 2
    config_winafl["in_dir"] = winafl.get_in_dir(config)
    config_winafl["out_dir_ori"] = config_winafl["out_dir_ori"] + "_recon"

    running_cmd = winafl.generate_running_cmd(config)
    path_file_to_fuzz = winafl.generate_path_file_to_fuzz(config_winafl)

    interesting_targets = []
    for target in targets:
        winafl.update_target_on_winafl_config(config_winafl, target)
        ret = winafl.run_winafl(config, config_winafl,
                                running_cmd, path_file_to_fuzz)
        if t_fuzz_stopped.is_set():
            winafl.kill_all(config)
            break
        if ret == 0:
            logging.info("Winafl not running")
        elif ret == 1:
            # we now, we also keep these target as winafl works on it
            execs_sec = winafl_stats.get_execs_sec_from_config(config_winafl)
            logging.info("No path discoverd "+str(execs_sec))
            target['execs_sec_recon'] = execs_sec
            target['type'] = 'PATHS_RECON'
            interesting_targets.append(target)
        elif ret == 2 or ret == 3:
            number_paths = winafl_stats.get_number_paths_from_config(config_winafl)
            execs_sec = winafl_stats.get_execs_sec_from_config(config_winafl)
            target['type'] = 'PATHS_RECON'
            target['execs_sec_recon'] = execs_sec
            target['number_paths_recon'] = number_paths
            logging.info("Interesting target " + str(number_paths) +
                         " " + str(execs_sec))
            interesting_targets.append(target)
        else:
            logging.debug("Unknown return value")
        winafl.kill_all(config)

    config['winafl_last_path_timeout'] = prev_last_path_timeout
    logging.info("Interesting targets:\n" + str(interesting_targets))
    return interesting_targets


def winafl_on_targets(config, targets, t_fuzz_stopped):
    """
    Launch winafl on the targets

    Args:
        config (dict): the user configuration
        targets (string list) list: targets
    Note:
        one target = (module, offset, module_cov1, module_cov2, ..)
    """

    config_winafl = winafl.generate_config_winafl(config)
    running_cmd = winafl.generate_running_cmd(config)
    path_file_to_fuzz = winafl.generate_path_file_to_fuzz(config_winafl)
    for target in targets:
        logging.info("Launch on " + str(target))
        winafl.update_target_on_winafl_config(config_winafl, target)
        winafl.run_winafl(config, config_winafl,
                          running_cmd, path_file_to_fuzz)
        winafl.kill_all(config)
        winafl.move_generated_inputs(config_winafl, config['file_format'])
        if t_fuzz_stopped.is_set():
            break

    logging.info("End of winafl")
