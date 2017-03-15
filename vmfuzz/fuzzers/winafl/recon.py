""" Module used to perform quick winafl testing """
import os
import logging
import winafl
import winafl_constants


def save_targets(config, interesting_targets):
    """
    Save targets into a file

    Args:
        config (dict): the user configuration
        interesting_targets (target): targets to save
    The file is located in the winafl working directory, as "program_name.targets"
    """
    path_file = os.path.join(winafl_constants.WINAFL_WORKING_DIR, config[
        'program_name'] + ".targets")
    output_file = open(path_file, "w")
    for (off, mod), nb_path in interesting_targets:
        output_file.write(hex(off) + ";" + mod + "\n")
    output_file.close()


def launch_recon(config):
    """
    Launch the recon mode of winafl

    Args:
        config (dict): the user configuration
    Returns:
        The list of interesting targets
    """
    prev_last_path_timeout = winafl_constants.WINAFL_LAST_PATH_TIMEOUT
    winafl_constants.WINAFL_LAST_PATH_TIMEOUT = 5
    winafl_constants.WINAFL_LOOP_ITERATION = 1

    targets = winafl.compute_targets(config)
    config_winafl = winafl.generate_config_winafl(config)

    config_winafl["in_dir"] = config_winafl["in_dir"] + "_recon"
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
        elif ret == 2:
            number_paths = winafl.get_number_paths_from_config(config_winafl)
            logging.info("Interesting target " + str(number_paths))
            interesting_targets.append((target, number_paths))
        else:
            logging.debug("Unknown return value")
        winafl.kill_all(config)

    winafl_constants.WINAFL_LAST_PATH_TIMEOUT = prev_last_path_timeout
    logging.info("Interesting targets:\n" + str(interesting_targets))
    return interesting_targets
