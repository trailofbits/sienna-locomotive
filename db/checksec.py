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

    dynamicBase     = Column( String )
    forceIntegrity  = Column( String )
    isolation       = Column( String )
    nx              = Column( String )
    seh             = Column( String )
    path            = Column( String, primary_key=True )

    ## Constructor for checksec object that takes json object from winchecksec
    # @param json object from winchecksec
    def __init__(self, json):
        # TODO: add other flags like ASLR
        self.dynamicBase     = json["dynamicBase"]
        self.forceIntegrity  = json["forceIntegrity"]
        self.isolation       = json["isolation"]
        self.nx              = json["nx"]
        self.seh             = json["seh"]
        self.path            = json["path"]

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

        checker = cfg.config['checksec_path']
        cmd = [ checker, "-j", path ]
        out = subprocess.check_output(cmd)
        ret = json.loads(out)
        ret = Checksec(ret)

        session.add(ret)
        session.commit()
        return ret


    ## Creates short string description
    # Returns a strings seperated by pipe symbols that
    # succinctly describes the checksec state of the object
    # @return string
    def shortString(self):
        # TODO: implement other flags
        t = []
        if self.nx:
            t.append("NX")
        if self.seh:
            t.append("SEH")
        if self.dynamicBase:
            t.append("DynamicBase")
        if self.forceIntegrity:
            t.append("ForcedIntegrity")
        if self.isolation:
            t.append("Isolation")
        return ' | '.join(t)



def main():
    print("ok")

if __name__ == '__main__':
    main()
