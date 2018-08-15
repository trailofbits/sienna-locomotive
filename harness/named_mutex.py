import ctypes
from ctypes import wintypes

# Ripped from benhoyt/namedmutex.
_CreateMutex = ctypes.windll.kernel32.CreateMutexW
_CreateMutex.argtypes = [wintypes.LPCVOID, wintypes.BOOL, wintypes.LPWSTR]
_CreateMutex.restype = wintypes.HANDLE

_WaitForSingleObject = ctypes.windll.kernel32.WaitForSingleObject
_WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
_WaitForSingleObject.restype = wintypes.DWORD

_ReleaseMutex = ctypes.windll.kernel32.ReleaseMutex
_ReleaseMutex.argtypes = [wintypes.HANDLE]
_ReleaseMutex.restype = wintypes.BOOL

_CloseHandle = ctypes.windll.kernel32.CloseHandle
_CloseHandle.argtypes = [wintypes.HANDLE]
_CloseHandle.restype = wintypes.BOOL


def _test_handle(handle):
    """
    Tests the given mutex handle, returning True if the mutex
    is acquirable (at time of return) and False if the mutex is
    already acquired (at time of return).
    """
    status = _WaitForSingleObject(handle, 0)

    if status in (0x0, 0x80):
        _ReleaseMutex(handle)
        return True
    elif status == 0x102:
        return False
    else:
        raise wintypes.WinError()


def test_named_mutex(name):
    """
    Tests the given named mutex, returning True if the mutex
    is acquirable and False if already acquired.

    Note: This function is susceptible to TOCTOU.
    """
    handle = _CreateMutex(None, False, name)

    if not handle:
        raise wintypes.WinError()

    status = _test_handle(handle)

    _CloseHandle(handle)

    return status


def spin_named_mutex(name):
    """
    Repeatedly acquires and releases the given named mutex,
    until someone else steals it.
    """
    handle = _CreateMutex(None, False, name)

    if not handle:
        raise wintypes.WinError()

    while True:
        if _test_handle(handle):
            # We successfully grabbed and released the mutex.
            pass
        else:
            # Someone else acquired the mutex, so we're done.
            break

    _CloseHandle(handle)
