""" Module handling autoit libaries system """
import os
import shutil

AUTOIT_LIB_DIRECTORY = ""
AUTOIT_WORKING_DIRECTORY = ""


def set_lib(autoit_script, name_lib):
    """
    Initiate the autoit script with the targeted libary

    Args:
        autoit_script (string): path to the autoit script
        name_lib (string) name of the libary
    Move the autoit script to the working directory and \
    copy the targeted libary inside
    See https://www.autoitscript.com/autoit3/docs/keywords/include.htm
    for different solutions to include user-defined libraries
    """
    new_dir = os.path.join(AUTOIT_WORKING_DIRECTORY, name_lib)
    autoit_name = os.path.basename(autoit_script)
    if not os.path.exists(new_dir):
        os.makedirs(new_dir)
    src = autoit_script
    dst = os.path.join(new_dir, autoit_name)
    shutil.copy(src, dst)
    src = os.path.join(AUTOIT_LIB_DIRECTORY, name_lib, "libfuzz.au3")
    dst = os.path.join(new_dir, "libfuzz.au3")
    shutil.copy(src, dst)


def get_autoit_path(autoit_script, name_lib):
    """
    Return the autoit path adjusted with the targeted libary

    Args:
        autoit_script (string): path to the autoit script
        name_lib (string) name of the libary
    Returns:
        string: path to the adjusted autoit script
    """
    autoit_name = os.path.basename(autoit_script)
    return os.path.join(AUTOIT_WORKING_DIRECTORY, name_lib, autoit_name)


def init_autoit(config):
    """
    Initiate the module

    Args:
        config: the configuration as a dict
    """
    path_autoit_script = config['path_autoit_script']
    set_lib(path_autoit_script, 'exploitable')
    set_lib(path_autoit_script, 'offset')
    set_lib(path_autoit_script, 'winafl')
    set_lib(path_autoit_script, '')
