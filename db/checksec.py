from sqlalchemy import *
import os
import harness.config
import subprocess
import json

import db
from db.base import Base


class Checksec(Base):

    __tablename__ = "checksec"


    dynamicBase     = Column( String )
    forceIntegrity  = Column( String )
    isolation       = Column( String )
    nx              = Column( String )
    seh             = Column( String )
    path            = Column( String, primary_key=True )

    def __init__(self, json):
        self.dynamicBase     = json["dynamicBase"]
        self.forceIntegrity  = json["forceIntegrity"]
        self.isolation       = json["isolation"]
        self.nx              = json["nx"]
        self.seh             = json["seh"]
        self.path            = json["path"]

    @staticmethod
    def byExecutable( path ):
        """
        Gets checksec information for dll or exe
        """
        cfg = harness.config
        session =  db.getSession()

        ret = session.query( Checksec ).filter( Checksec.path==path ).first()
        if ret:
            return ret

        checker = cfg.config['checksec_path']
        cmd = [ checker, "-j", path ]
        out = subprocess.getoutput(cmd)
        ret = json.loads(out)
        ret = Checksec(ret)

        session.add(ret)
        session.commit()
        #session.close()
        return ret


    def shortString(self):
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
