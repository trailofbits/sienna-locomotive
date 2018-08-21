import os
import glob
import re
import harness.config

def dumpPathToRunid( dmpPath ):
    """
    Converts the full path to an sl2 minidump to a runid
    """
    runid = None
    m = re.match(r".*\\runs\\([a-fA-F0-9-]+)\\.*", dmpPath)
    if m:
        runid = m.group(1)
    return runid



def runidToDumpPath( runid ):
    """
    Converts an sl2 runid into a minidump path
    """
    dumpPath = None
    cfg = harness.config

    dumpsGlob = os.path.join( cfg.sl2_runs_dir, runid,  'initial.*.dmp' )
    for dumpPath in glob.glob( dumpsGlob ):
        return dumpPath

    return dumpPath