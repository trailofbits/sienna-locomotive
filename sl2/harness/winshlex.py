import ctypes
from ctypes import wintypes

_CommandLineToArgvW = ctypes.windll.shell32.CommandLineToArgvW
_CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
_CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPCWSTR)


def split(args):
    """
    Converts a string of command-line arguments into a list
    via CommandLineToArgvW.
    """
    argc = ctypes.c_int(0)
    # NOTE(ww): This leaks memory, as we don't call LocalFree.
    argvw = _CommandLineToArgvW(args, ctypes.byref(argc))
    return [argvw[i] for i in range(0, argc.value)]
