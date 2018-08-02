import harness.config
import glob
import json
import os
import shutil

class Postprocessor:

    def __init__(self):
        self.cfg = harness.config.config
        self.crashashes = {}
        self.runsdir =  harness.config.sl2_runs_dir


    # @staticmethod
    # def delerror( function, path, info ):
    #     print("Unable to rm %s because %s" % (path, info))

    @staticmethod
    def safedelete(path):

        shutil.rmtree(path, onerror=print)

    def process(self):
        pattern = "%s/*/triage.json" % self.runsdir
        paths = glob.glob(  pattern )
        print("Processing %d crashes..." % len(paths))
        for path in paths:
            with open(path) as f:
                triageJson = json.load(f)
                f.close()
                crashash = triageJson["crashash"]
                if crashash in self.crashashes:
                    dirtodelete = os.path.dirname(path)
                    print("Deleting %s" % dirtodelete)
                    Postprocessor.safedelete(dirtodelete)
                else:
                    self.crashashes[crashash] = triageJson


        for k,v in self.crashashes.items():
            print( "%s\t%s" % (v['exploitability'], k) )

        self.persist()

    def persist(self):
        outpath = os.path.join( self.runsdir, "rollup.json" )
        with open(outpath, "w+") as f:
            outobj = {}
            outobj['crashes'] = self.crashashes
            json.dump(outobj,f)





def main():

    proc = Postprocessor()
    proc.process()

if __name__ == "__main__":
    main()