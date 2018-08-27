from shutil import copytree, ignore_patterns
import csv
import db
import os
import shutil
import sqlite3
import utilz


class TriageExport:

    def __init__(self, exportDir):
        self.exportDir = exportDir
        self.cols = [ 'crash.runid',
            'crashAddressString',
            'crashReason',
            'crashash',
            'exploitability',
            'instructionPointerString',
            'minidumpPath',
            'ranksString',
            'stackPointerString',
            'tag',
            'formatted'
        ]
        self.sqlExport = 'select %s from crash left join tracer on crash.runid = tracer.runid' % ",".join(self.cols)


    def export(self):

        csvPath = os.path.join(self.exportDir, "triage.csv")
        with sqlite3.connect(db.dbpath) as conn:
            with open( csvPath, "w"  ) as f:
                csvWriter = csv.writer(f, lineterminator='\n' )
                cur = conn.cursor()
                cur = cur.execute(self.sqlExport)
                rows = cur.fetchall()
                csvWriter.writerow(self.cols)
                csvWriter.writerows(rows)
                f.close()

        crashies = db.Crash.getAll()
        for crash in crashies:
            try:
                dstdir = os.path.join( self.exportDir,
                    utilz.sanitizeString(crash.exploitability),
                    utilz.sanitizeString(crash.crashReason),
                    utilz.sanitizeString(crash.crashash),
                    crash.runid )
                #os.makedirs( dstdir, exist_ok=True )
                srcdir = os.path.dirname( crash.minidumpPath )
                print("%s -> %s" % (srcdir, dstdir))
                shutil.copytree( srcdir, dstdir, ignore=ignore_patterns("mem*.dmp") )
            except FileExistsError as x :
                print("File already exists for crash " , crash.minidumpPath, x )



    def setExportDir(self):
        path = QFileDialog.getExistingDirectory(dir='.')
        if len(path) == 0:
            return
        self.exportDir = path
        self.process()


if __name__ == '__main__':

    outdir = r"f:\2"
    print("outdir", outdir)

    pproc = TriageExport(outdir)
    pproc.export()