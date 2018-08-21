############################################################################
# crash.py
#
# Model for crashing runs in sl2.  Puts basic exploitablity and triage
# info in the database

from sqlalchemy import *
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
import glob
import harness.config
import json
import os
import re
import subprocess

from db.base import Base
import db


class Crash(Base):

    __tablename__ = "crash"

    id                      = Column( Integer, primary_key=True )
    runid                   = Column( String(40)  )
    callStackJson           = Column( String )
    crashAddress            = Column( String(20) )
    crashReason             = Column( String(270) )
    crashash                = Column( String(64) )
    exploitability          = Column( String(32) )
    instructionPointer      = Column( String(20) )
    minidumpPath            = Column( String(270) )
    rank                    = Column( Integer  )
    ranksJson               = Column( String )
    stackPointer            = Column( String(20) )
    tag                     = Column( String(128) )
    tracer                  = relationship(  "Tracer", order_by=db.Tracer.runid, back_populates="crash", uselist=False)

    def __init__(self, j, runid=None):
        try:
            self.runid                  = runid
            self.crashJson              = j
            self.callStackJson          = str(j["callStack"])
            self.crashAddress           = hex(j["crashAddress"])
            self.crashReason            = j["crashReason"]
            self.crashash               = j["crashash"]
            self.exploitability         = j["exploitability"]
            self.instructionPointer     = hex(j["instructionPointer"])
            self.minidumpPath           = j["minidumpPath"]
            self.rank                   = j["rank"]
            self.ranksJson              = str(j["ranks"])
            self.stackPointer           = hex(j["stackPointer"])
            self.tag                    = j["tag"]
        except KeyError:
            raise "Was unable to parse crash json from triager"



    @staticmethod
    def factory( runid, dmpPath=None ):
        """
        Factory for generating triage and exploitability information about a minidump. If
        it already exists in the db, return the row.
        """
        cfg = harness.config
        session = db.getSession()
        runid = str(runid)
        ret = session.query( Crash ).filter( Crash.runid==runid ).first()
        if ret:
            return ret

        if not dmpPath:
            dmpPath = db.utilz.runidToDumpPath(runid)

        if not dmpPath:
            print("Unable to find dumpfile for runid %s" % runid)
            return None

        # Runs triager, which will give us exploitabilty info
        # using 2 engines: Google's breakpad and an reimplementation of Microsofts
        # !exploitable
        cmd = [ cfg.config['triager_path'], dmpPath ]
        out = subprocess.check_output(cmd, shell=False)
        out = out.decode('utf8')
        j = None
        for line in out.splitlines():
            line = line.strip()
            if re.match( r"{.*}", line ):
                j = json.loads(line)

        if not j:
            return None
        try:
            ret = Crash(j, runid)
        except x:
            print("Unable to process cras json")
            return None

        # See if there is a tracer result for this runid
        ret.tracer = db.Tracer.factory(runid)
        session.add(ret)
        session.commit()
        return ret

    def __repr__(self):
        tracerInfo = "None"
        if self.tracer:
            tracerInfo = self.tracer.tracerFormatted
        return """Exploitability: %s   Crash Reason: %s   Crash Address: %s    Crashash: %s    Tag: %s    Tracer: %s""" % (
            self.exploitability, self.crashReason, self.crashAddress, self.crashash, self.tag, tracerInfo )

# Example json
# {'callStack': [
#         140702400817557,
#         140714802676776,
#         140714802901152,
#         140714802766905
#     ],
#     'crashAddress': 140702400817557,
#     'crashReason': 'EXCEPTION_BREAKPOINT',
#     'crashash': 'f96808cfc4798256',
#     'exploitability': 'None',
#     'instructionPointer': 140702400817557,
#     'minidumpPath': 'C:\\Users\\IEUser\\AppData\\Roaming\\Trail of Bits\\fuzzkit\\runs\\4b390ae5-c838-4c7f-b79a-5b47db029036\\initial.4156.dmp',
#     'rank': 0,
#     'ranks': [
#         0,
#         0
#     ],
#     'stackPointer': 77642130192,
#     'tag': 'None/EXCEPTION_BREAKPOINT/f96808cfc4798256'
# }