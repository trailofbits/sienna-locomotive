############################################################################
## @package triage
# Python wrapper for triage functionality.  Mostly just handles triage
# exporting now since the ranks are processed in the db/model sections

import csv
import os
import shutil
import sqlite3
from shutil import ignore_patterns

from PySide2.QtWidgets import QFileDialog

import db
import utilz


## Class for exporting triage results. Will iterate each crash from the db
# and copy to the appropriate directory based on exploitability, the reason
# for the crash, and the crashash.
class TriageExport:

    ## Constructor to export triage results
    # @param exportDir Directory to export all crashes
    def __init__(self, exportDir):
        self.exportDir = exportDir
        self.cols = ['crash.runid',
                     'crashAddressString',
                     'crashReason',
                     'crashash',
                     'exploitability',
                     'instructionPointerString',
                     'minidumpPath',
                     'ranksString',
                     'stackPointerString',
                     'tag',
                     'formatted',
                     'targetPath',
                     'aslr',
                     'authenticode',
                     'cfg',
                     'dynamicBase',
                     'forceIntegrity',
                     'gs',
                     'highEntropyVA',
                     'isolation',
                     'nx',
                     'rfg',
                     'safeSEH',
                     'seh',
                     ]
        # TODO: Fix this to account for binary hashes
        self.sqlExport = 'select %s from crash left join tracer, checksec on crash.runid = tracer.runid and crash.targetPath = checksec.path' % ",".join(
            self.cols)

    ## Exports crash from run directories to appropriate directory structure.  Also generates
    # triage.csv file with summary of crashes
    def export(self):
        csvPath = os.path.join(self.exportDir, "triage.csv")
        with sqlite3.connect(db.dbpath) as conn:
            with open(csvPath, "w") as f:
                csvWriter = csv.writer(f, lineterminator='\n')
                cur = conn.cursor()
                cur = cur.execute(self.sqlExport)
                rows = cur.fetchall()
                csvWriter.writerow(self.cols)
                csvWriter.writerows(rows)
                f.close()

        crashies = db.Crash.getAll()
        for crash in crashies:
            try:
                dstdir = os.path.join(self.exportDir,
                                      utilz.sanitizeString(crash.exploitability),
                                      utilz.sanitizeString(crash.crashReason),
                                      utilz.sanitizeString(crash.crashash),
                                      crash.runid)
                # os.makedirs( dstdir, exist_ok=True )
                srcdir = os.path.dirname(crash.minidumpPath)
                print("%s -> %s" % (srcdir, dstdir))
                shutil.copytree(srcdir, dstdir, ignore=ignore_patterns("mem*.dmp"))
            except FileExistsError as x:
                print("File already exists for crash ", crash.minidumpPath, x)

    ## Mutator and gui code for setting the export directory
    def setExportDir(self):
        path = QFileDialog.getExistingDirectory(dir='.')
        if len(path) == 0:
            return
        self.exportDir = path
        # self.process()
        raise NotImplementedError("Exporting isn't finished yet")

    @staticmethod
    def checksecToExploitabilityRank(targetPath):
        checksec = db.Checksec.byExecutable(targetPath)
        if checksec is None:
            return 0
        attrmap = {
            'aslr': 1,
            'authenticode': 0,
            'cfg': 1,
            'dynamicBase': 1,  # maybe 0?
            'forceIntegrity': 0,
            'gs': 1,
            'highEntropyVA': 0,
            'nx': 1,
        }
        return attrmap


if __name__ == '__main__':
    outdir = r"f:\2"
    print("outdir", outdir)

    pproc = TriageExport(outdir)
    pproc.export()
