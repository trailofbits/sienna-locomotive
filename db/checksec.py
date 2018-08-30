############################################################################
## @package checksec
#
# This is the python wrapper around winchecksec, a tool that's basically an
# equivalent of checksec.sh
#

from sqlalchemy import *
import os
import harness.config
import subprocess
import json

import db
from db.base import Base

## DB Wrapper for winchecksec
class Checksec(Base):

    __tablename__ = "checksec"

    aslr               = Column( Boolean )
    authenticode       = Column( Boolean )
    cfg                = Column( Boolean )
    dynamicBase        = Column( Boolean )
    forceIntegrity     = Column( Boolean )
    gs                 = Column( Boolean )
    highEntropyVA      = Column( Boolean )
    isolation          = Column( Boolean )
    nx                 = Column( Boolean )
    path               = Column( String, primary_key=True )
    rfg                = Column( Boolean )
    safeSEH            = Column( Boolean )
    seh                = Column( Boolean )

    ## Constructor for checksec object that takes json object from winchecksec
    # @param json object from winchecksec
    def __init__(self, json):
        self.aslr               = json["aslr"]
        self.authenticode       = json["authenticode"]
        self.cfg                = json["cfg"]
        self.dynamicBase        = json["dynamicBase"]
        self.forceIntegrity     = json["forceIntegrity"]
        self.gs                 = json["gs"]
        self.highEntropyVA      = json["highEntropyVA"]
        self.isolation          = json["isolation"]
        self.nx                 = json["nx"]
        self.path               = json["path"]
        self.rfg                = json["rfg"]
        self.safeSEH            = json["safeSEH"]
        self.seh                = json["seh"]


    ## Factory for checksec from executable path
    # Gets checksec information for dll or exe.
    # If it already exists in the db, just return it
    # @param path Path to DLL or EXE
    # @return Checksec obj
    @staticmethod
    def byExecutable( path ):
        cfg = harness.config
        session =  db.getSession()

        ret = session.query( Checksec ).filter( Checksec.path==path ).first()
        if ret:
            return ret
        ret = None
        checker = cfg.config['checksec_path']
        cmd = [ checker, "-j", path ]

        try:
            out = subprocess.check_output(cmd)
            ret = json.loads(out)
            ret = Checksec(ret)
            session.add(ret)
            session.commit()
        except subprocess.CalledProcessError as x:
            print("Exception", x)

        return ret


    ## Creates short string description
    # Returns a strings seperated by pipe symbols that
    # succinctly describes the checksec state of the object
    # @return string
    def shortString(self):
        # TODO: implement other flags
        t = []
        if self.aslr:
            t.append("ASLR")
        if self.authenticode:
            t.append("Authenicode")
        if self.cfg:
            t.append("CFG")
        if self.dynamicBase:
            t.append("DynamicBase")
        if self.forceIntegrity:
            t.append("ForcedIntegrity")
        if self.gs:
            t.append("GS")
        if self.highEntropyVA:
            t.append("HighEntropyVA")
        if self.isolation:
            t.append("Isolation")
        if self.nx:
            t.append("NX")
        if self.rfg:
            t.append("RFG")
        if self.seh:
            t.append("SEH")
        return ' | '.join(t)



def main():
    print("ok")

if __name__ == '__main__':
    main()
