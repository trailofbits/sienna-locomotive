import harness.config
import glob
import json
import csv
import os
import shutil

from typing import NamedTuple


def noop(*args):
    pass


class RollupMessage(NamedTuple):
    path        : str
    i           : int
    iCnt        : int
    duplicate   : bool


class Rollup(json.JSONEncoder):


    def default(self, o):
        return o.__dict__

    def __init__(self):
        self.csvs       = None
        self.cfg        = harness.config.config
        self.crashashes = {}
        self.runsdir    =  harness.config.sl2_runs_dir
        self.sl2dir     = harness.config.sl2_dir


    # @staticmethod
    # def delerror( function, path, info ):
    #     print("Unable to rm %s because %s" % (path, info))


    def cols(self):
        return 3

    def rows(self):
        return len(self.crashashes.keys())

    @staticmethod
    def safedelete(path):

        shutil.rmtree(path, onerror=print)


    def process(self, cb=noop):
        """
        Does a post process rollup of all the data in the runs dir.  You can optionally specific a callback to get updates
        """
        pattern = "%s/*/triage.json" % self.runsdir
        paths = glob.glob(  pattern )
        print("Processing %d crashes..." % len(paths))
        pathsCnt = len(paths)
        i = 0
        for path in paths:
            i += 1
            with open(path) as f:
                triageJson = json.load(f)
                f.close()
                crashash = triageJson["crashash"]
                if crashash in self.crashashes:
                    rmsg = RollupMessage( path, i, pathsCnt, True )
                    cb( rmsg )
                    dirtodelete = os.path.dirname(path)
                    print("Deleting %s" % dirtodelete)
                    #Rollup.safedelete(dirtodelete)
                else:
                    rmsg = RollupMessage( path, i, pathsCnt, False )
                    cb( rmsg )
                    self.crashashes[crashash] = triageJson


        for k,v in self.crashashes.items():
            print( "%s\t%s" % (v['exploitability'], k) )
        self.persist()

    def toCSV(self):
        if self.csvs != None:
            return self.csvs

        self.csvs = []
        for  crash in self.crashashes.values():
            crash =  crash.copy()
            del crash['tracer']
            crash = [ hex(_) if isinstance(_, int) else _  for _ in crash.values() ]
            self.csvs.append(crash)
        return self.csvs


    def persist(self):
        """
        Saves rollup as csv and json
        """
        outpath = os.path.join( self.sl2dir, "rollup.json" )
        with open(outpath, "w+") as f:
            outobj = {}
            outobj['crashes'] = self.crashashes
            json.dump(self,f, skipkeys=True, default=lambda o: o.__dict__ )

        outpath = os.path.join( self.sl2dir, "rollup.csv" )
        with open(outpath, "w+") as f:
            cvsf = csv.writer( f )
            for  crash in self.toCSV():
                print("crash", crash)
                cvsf.writerow(crash)




def main():

    proc = Rollup()
    proc.process()

if __name__ == "__main__":
    main()