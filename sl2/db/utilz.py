##############################################################################################
## @package utilz
# General utilities and helper functions for the database

import os
import glob
import re
from hashlib import sha256
from functools import lru_cache
from sl2.harness import config


## Converts the full path to an sl2 minidump to a runid
# @param dmpPath minidump path
# @return string runid
def dumpPathToRunid(dmpPath):
    runid = None
    m = re.match(r".*\\runs\\([a-fA-F0-9-]+)\\.*", dmpPath)
    if m:
        runid = m.group(1)
    return runid


## Converts an sl2 runid into a minidump path
# @param runid Runid for the crash
# @return string path to minidump file
def runidToDumpPath(runid):
    dumpPath = None
    cfg = config

    dumpsGlob = os.path.join(cfg.sl2_runs_dir, runid, "initial.*.dmp")
    for dumpPath in glob.glob(dumpsGlob):
        return dumpPath

    return dumpPath


## Takes the sha256 hash of a file
#  @param filename: str -- Path to the file
#  @return str -- hex-encoded SHA256 hash
@lru_cache()
def hash_file(filename: str):
    m = sha256()
    with open(filename, "rb") as f:
        while True:
            data = f.read(1024 * 512)
            if not data:
                break
            m.update(data)
    return m.hexdigest()
