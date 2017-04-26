"""
    Module handling the log
"""
import logging
import utils.database as database

CONFIG = {}


def init_log(config, log_level):
    """
    Initialize the logging

    Args:
        config (dict): logging configuration
        log_level(int): the logging level
    Note:
        Log levels:\n
        - 0 = Debug
        - 1 = Info
        - 2 = Warning
        - 3 = Error

        The logging config needs the fields:\n
        - '_run_id'
        - '_worker_id'
        - 'webapp_ip'
    """

    global CONFIG

    CONFIG = config

    if log_level == 0:
        logging.basicConfig(filename="vmfuzz.log",
                            filemode='w', level=logging.DEBUG)
    elif log_level == 1:
        logging.basicConfig(filename="vmfuzz.log",
                            filemode='w', level=logging.INFO)
    elif log_level == 2:
        logging.basicConfig(filename="vmfuzz.log",
                            filemode='w', level=logging.WARNING)
    elif log_level == 3:
        logging.basicConfig(filename="vmfuzz.log",
                            filemode='w', level=logging.ERROR)


def debug(buf):
    """
    Debug message

    Args:
        buf (string) : Message
    """
    logging.debug(buf)
    print buf


def info(buf):
    """
    Info message

    Args:
        buf (string) : Message
    """
    logging.info(buf)
    print buf


def warning(buf):
    """
    Warning message

    Args:
        buf (string) : Message
    """
    logging.warning(buf)
    print buf


def error(buf):
    """
    Error message

    Args:
        buf (string) : Message
    Note:
        Send the error to the webapp
    """
    print buf
    logging.error(buf)
    database.send_error(CONFIG, buf)
    exit(0)
