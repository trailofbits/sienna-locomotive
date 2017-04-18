import os
import json

def is_hex(target):
    return all(ch in 'ABCDEFabcdef0123456789' for ch in target)
    
def error(msg):
    """
    Wrap a string in a JSON error for the front end
    Args:
        msg (str): error message
    Returns:
        str: stringified JSON error message
    """
    return json.dumps({'error': True, 'message': msg})

def mkdir_ifne(path):
    """
    Creates a directory if it does not exist
    Args:
        path (str): path of dir to be created
    """
    if not os.path.exists(path):
        print "Make dir "+str(path)
        os.mkdir(path)