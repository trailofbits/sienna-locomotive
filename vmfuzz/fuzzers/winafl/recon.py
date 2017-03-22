""" Module used to perform quick winafl testing """
import logging
import fuzzers.winafl.winafl as winafl
import fuzzers.winafl.winafl_constants as winafl_constants
import fuzzers.winafl.stats as winafl_stats



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
    input_file = open(path_file, "r")
    targets = input_file.read()
    targets = targets.split('\n')
    targets = [x.rstrip('\r').split(';') for x in targets]
    targets = [(int(x, 16), y) for (x, y) in targets[:-1]]
    return targets


def save_targets(interesting_targets, path_file):
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
    output_file = open(path_file, "w")
    for target in interesting_targets:
        output_file.write(";".join(target)+"\n")
    output_file.close()


def launch_recon(config):
    """
    Launch the recon mode of winafl \n
    The recon mode compute the offsets, try each one \n
    for 5 mins and export the one working with winafl

    Args:
        config (dict): the user configuration
    Returns:
        (int,string) list: The list of interesting targets
    Note:
        Winafl is launched for 2 min on each target.
        If not new path is found the target is not considered
    """
    prev_last_path_timeout = config['winafl_last_path_timeout']
    config['winafl_last_path_timeout'] = 2
    winafl_constants.WINAFL_LOOP_ITERATION = 1

    targets = winafl.compute_targets(config)
    config_winafl = winafl.generate_config_winafl(config)

    config_winafl["in_dir"] = winafl.get_in_dir_seed(config)
    config_winafl["out_dir_ori"] = config_winafl["out_dir_ori"] + "_recon"

    running_cmd = winafl.generate_running_cmd(config)
    path_file_to_fuzz = winafl.generate_path_file_to_fuzz(config_winafl)

    interesting_targets = []
    for target in targets:
        winafl.update_target_on_winafl_config(config_winafl, target)
        ret = winafl.run_winafl(config, config_winafl,
                                running_cmd, path_file_to_fuzz)
        if ret == 0:
            logging.info("Winafl not running")
        elif ret == 1:
            logging.info("No path discoverd")
            # we now, we also keep these target as winafl works on it
            interesting_targets.append(target)
        elif ret == 2:
            number_paths = winafl_stats.get_number_paths_from_config(config_winafl)
            logging.info("Interesting target " + str(number_paths))
            interesting_targets.append(target)
        else:
            logging.debug("Unknown return value")
        winafl.kill_all(config)

    config['winafl_last_path_timeout'] = prev_last_path_timeout
    winafl_constants.WINAFL_LOOP_ITERATION = 0
    logging.info("Interesting targets:\n" + str(interesting_targets))
    return interesting_targets


def winafl_on_targets(config, targets):
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
    logging.info("End of winafl")
