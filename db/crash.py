############################################################################
# crash.py
#
# Model for crashing runs in sl2.  Puts basic exploitablity and triage
# info in the database

from sqlalchemy import *
from sqlalchemy import ForeignKey
from sqlalchemy import orm
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

    id                          = Column( Integer, primary_key=True )
    runid                       = Column( String(40)  )
    crashAddressString          = Column( String(20) )
    crashReason                 = Column( String(270) )
    crashash                    = Column( String(64) )
    exploitability              = Column( String(32) )
    instructionPointerString    = Column( String(20) )
    minidumpPath                = Column( String(270) )
    rank                        = Column( Integer  )
    stackPointerString          = Column( String(20) )
    tag                         = Column( String(128) )
    tracer                      = relationship(  "Tracer", order_by=db.Tracer.runid, back_populates="crash", uselist=False)
    obj                         = Column( PickleType )


    def __init__(self, j, runid=None):
        try:
            self.runid                      = runid
            self.crashAddressString         = hex(j["crashAddress"])
            self.crashReason                = j["crashReason"]
            self.crashash                   = j["crashash"]
            self.exploitability             = j["exploitability"]
            self.instructionPointerString   = hex(j["instructionPointer"])
            self.minidumpPath               = j["minidumpPath"]
            self.rank                       = j["rank"]
            self.stackPointerString         = hex(j["stackPointer"])
            self.tag                        = j["tag"]
            self.obj                        = j

        except KeyError:
            raise "Was unable to parse crash json from triager"


    @staticmethod
    def rankToExploitability(rank):
        xploitabilities = [ 'None', 'Unknown', 'Low', 'Medium', 'High ']
        return xploitabilities[rank]

    def mergeTracer( self ):
        """ See if there is a tracer result for this runid"""

        tracer = db.Tracer.factory(self.runid)
        if not tracer:
            self.tracer = None
            return
        self.tracer = tracer

    @orm.reconstructor
    def reconstructor(self):
        self.stackPointer           = self.obj["stackPointer"]
        self.ranks                  = self.obj["ranks"]
        self.crashAddress           = self.obj["crashAddress"]
        self.instructionPointer     = self.obj["instructionPointer"]

        if self.tracer:
            self.ranks.append(self.tracer.rank)

        self.rank = max(self.ranks)
        self.exploitability = Crash.rankToExploitability(self.rank)

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

        ret.mergeTracer()
        ret.reconstructor()
        session.add(ret)
        session.commit()
        return ret

    def ranksString(self):
        tmp = [ str(_) for _ in self.ranks ]
        return "-".join(tmp)

    def __repr__(self):
        tracerInfo = "None"
        if self.tracer:
            tracerInfo = self.tracer.formatted
        return """Exploitability: %s (%s)   Crash Reason: %s   Crash Address: %X    Instruction: %X   Crashash: %s    Tag: %s    Tracer: %s""" % (
            self.exploitability,
            self.ranksString(),
            self.crashReason,
            self.crashAddress,
            self.instructionPointer,
            self.crashash,
            self.tag,
            tracerInfo )

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