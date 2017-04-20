""" Module handling the stat on winafl """

import datetime
import os

import fuzzers.winafl.winafl_constants as winafl_constants
import utils.logs as logging


def parsing_stat(file_name):
    """
    Parsing winafl fuzzer_stats file

    Args:
        file_name (string): path to the fuzzer_stats file
    Returns:
        dict: the content of the file
    Note:
        If the fuzzer_stats does not exist, returns an empty dict
    """
    if not os.path.exists(file_name):
        return {}
    f_fuzzer_stats = open(file_name, "r")
    fuzzer_stats = f_fuzzer_stats.read()
    f_fuzzer_stats.close()
    fuzzer_stats = fuzzer_stats.split('\n')
    # for each line: "xxx :threading yyyy" becomes (xxx,yyy)
    fuzzer_stats = [(x[0:x.find(':')].rstrip(), x[x.find(':') + 2:])
                    for x in fuzzer_stats]
    fuzzer_stats = dict(fuzzer_stats)
    return fuzzer_stats


def get_stat(out_dir):
    """
    Return the winafl stat

    Args:
        out_dir (string): The output directory
    Returns:
        dict: the content of the file fuzzer_stat
    Note:
        If the fuzzer_stats does not exist, returns an empty dict
    """
    return parsing_stat(os.path.join(out_dir, "fuzzer_stats"))


def get_duration(fuzzer_stats):
    """
    Return the time (in sec) between now and the start

    Args:
        fuzerer_stats (dict)
    Returns:
        int: The time in seconds between now and the last crash
    """
    start_time = int(fuzzer_stats['start_time'])
    now = datetime.datetime.utcnow()
    # convert timestamp from windows
    start_time = datetime.datetime(1601, 1, 1) + \
        datetime.timedelta(0, start_time)
    return (now - start_time).total_seconds()


def get_last_crash_sec(fuzzer_stats):
    """
    Return the time (in sec) between now and the last crash

    Args:
        fuzerer_stats (dict)
    Returns:
        int: The time in seconds between now and the last crash
    Note:
        If no crashes have been found return the time between now and the start
    """
    last_crash = int(fuzzer_stats['last_crash'])
    if last_crash == 0:
        return 0
    now = datetime.datetime.utcnow()
    if last_crash == 0:
        last_crash = int(fuzzer_stats['start_time'])
    # convert timestamp from windows
    last_crash = datetime.datetime(1601, 1, 1) + \
        datetime.timedelta(0, last_crash)
    return (now - last_crash).total_seconds()


def get_last_path_sec(fuzzer_stats):
    """
    Return the time (in sec) between now and the last path discover

    Args:
        fuzerer_stats (dict)
    Returns:
        int: The time in seconds between now and the last path discover
    Note:
        If no paths have been found return the time between now and the start
    """
    last_path = int(fuzzer_stats['last_path'])
    now = datetime.datetime.utcnow()
    logging.debug("Now "+str(now))
    # convert timestamp from windows
    if last_path == 0:
        last_path = int(fuzzer_stats['start_time'])
        logging.debug("Time form start : "+str(last_path))
    last_path = datetime.datetime(1601, 1, 1) + \
        datetime.timedelta(0, last_path)
    logging.debug("Last path "+str(last_path))
    return (now - last_path).total_seconds()


def get_number_paths(fuzzer_stats):
    """
    Returns the number of paths found

    Args:
        fuzerer_stats (dict)
    Returns:
        int: The number of paths
    """
    return int(fuzzer_stats['paths_found'])


def get_execs_sec_paths(fuzzer_stats):
    """
    Returns the number of executions per sec

    Args:
        fuzerer_stats (dict)
    Returns:
        int: The number of executions per sec
    """
    return float(fuzzer_stats['execs_per_sec'])


def get_number_paths_from_config(config_winafl):
    """
    Returns the number of paths found

    Args:
        config_winafl (dict)
    Returns:
        int: The number of paths
    """
    path_fuzzer_stats = os.path.join(
        winafl_constants.WINAFL_WORKING_DIR,
        config_winafl['out_dir'],
        "fuzzer_stats")
    fuzzer_stats = parsing_stat(path_fuzzer_stats)
    if not fuzzer_stats:
        return 0
    return get_number_paths(fuzzer_stats)


def get_execs_sec_from_config(config_winafl):
    """
    Returns the number of paths found

    Args:
        config_winafl (dict)
    Returns:
        int: The number of paths
    """
    path_fuzzer_stats = os.path.join(
        winafl_constants.WINAFL_WORKING_DIR,
        config_winafl['out_dir'],
        "fuzzer_stats")
    fuzzer_stats = parsing_stat(path_fuzzer_stats)
    if not fuzzer_stats:
        return 0
    return get_execs_sec_paths(fuzzer_stats)


def get_number_crashes(fuzzer_stats):
    """
    Returns the number of crashes found

    Args:
        fuzerer_stats (dict)
    Returns:
        int: The number of crashes
    """
    return int(fuzzer_stats['uniq_crashes'])
