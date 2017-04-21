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
        log_level(int): the logging level
    Note:
        0 = Debug \n
        1 = Info \n
        2 = Warning \n
        3 = Error
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


def info(buf):
    """
    Info message

    Args:
        buf (string) : Message
    """
    logging.info(buf)


def warning(buf):
    """
    Warning message

    Args:
        buf (string) : Message
    """
    logging.warning(buf)


def error(buf):
    """
    Error message

    Args:
        buf (string) : Message
    Note:
        Send the error to the webapp
    """
    logging.error(buf)
    database.send_error(CONFIG, buf)
    exit(0)
