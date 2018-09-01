############################################################################
## @package crash
# crash.py
#
# Model for crashing runs in sl2.  Puts basic exploitability and triage
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
from sqlalchemy.sql.expression import func

from db.base import Base
import db


## Crash class
# Holds information about a specific crash
# Example json
# <pre>
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
# </pre>
class Crash(Base):

    __tablename__ = "crash"

    id                          = Column( Integer, primary_key=True )
    ## Runid for the crash
    runid                       = Column( String(40)  )
    ## Crash address as hex string
    crashAddressString          = Column( String(20) )
    ## Textual description of crash reason
    crashReason                 = Column( String(270) )
    ## Crashash (Crash Hash).  Identifier for binning related crashes
    crashash                    = Column( String(64) )
    ## Text string description of Exploitability. Can be High, Medium, Low, Unknown, or None.
    exploitability              = Column( String(32) )
    ## Instruction Pointer (pc, eip, rep) as hex string
    instructionPointerString    = Column( String(20) )
    ## Path to minidump for crash
    minidumpPath                = Column( String(270) )
    ## Path to target (PUT)
    targetPath                  = Column( String(270) )
    ## RAX
    rax                         = Column( String(20) )
    ## RBX
    rbx                         = Column( String(20) )
    ## RCX
    rcx                         = Column( String(20) )
    ## RDX
    rdx                         = Column( String(20) )
    ## Integer version of exploitability (0-4, inclusive)
    rank                        = Column( Integer  )
    ## A colon separated list of each engines exploitability.  For example 1:2:2
    ranksString                 = Column( String(8)  )
    ## Stack pointer (rsp) at crash as hex string
    stackPointerString          = Column( String(20) )
    ## Tag or path used to succinctly describe crash bin
    tag                         = Column( String(128) )
    ## Foreign key to tracer results
    tracer                      = relationship(  "Tracer", order_by=db.Tracer.runid, back_populates="crash", uselist=False)
    ## Summary of triage information
    output                      = Column( String )
    ## Pickled object version of json object
    obj                         = Column( PickleType )
    ## Timestamp of the crash
    timestamp                   = Column( DateTime, default=func.now() )

    ## Constructor for crash object
    # @param runid Run ID of crash
    # @param j json object version
    def __init__(self, j, runid=None, targetPath=None):
        try:

            self.runid                      = runid
            ## Json object
            self.obj                        = j
            ## Crash address as hex string
            self.crashAddressString         = hex(j["crashAddress"])
            ## Textual description of crash reason
            self.crashReason                = j["crashReason"]
            ## Crashash (Crash Hash).  Identifier for binning related crashes
            self.crashash                   = j["crashash"]
            ## Text string description of Exploitability. Can be High, Medium, Low, Unknown, or None.
            self.exploitability             = j["exploitability"]
            ## Instruction Pointer (pc, eip, rep) as hex string
            self.instructionPointerString   = hex(j["instructionPointer"])
            ## Path to minidump for crash
            self.minidumpPath               = j["minidumpPath"]
            ## Path to minidump for crash
            self.targetPath                 = targetPath
            ## Integer version of exploitability (0-4, inclusive)
            self.rank                       = j["rank"]
            ## Stack pointer (rsp) at crash as hex string
            self.stackPointerString         = hex(j["stackPointer"])
            ## Tag or path used to succinctly describe crash bin
            self.tag                        = j["tag"]
            ## List of each engines exploitability.  For example [1,2,2]
            self.ranks                      = self.obj["ranks"]
            ## A colon separated list of each engines exploitability.  For example 1:2:2
            self.ranksString                = self.ranksStringGenerate()
            ## Summary of triage information
            self.output                     = j["output"]
            ## RAX
            self.rax                        = hex(j['rax'])
            ## RBX
            self.rbx                        = hex(j['rbx'])
            ## RCX
            self.rcx                        = hex(j['rcx'])
            ## RDX
            self.rdx                        = hex(j['rdx'])


        except KeyError:
            raise "Was unable to parse crash json from triager"


    ## Converts integer rank to exploitability string
    # @param rank integer rank
    # @return string
    @staticmethod
    def rankToExploitability(rank):
        xploitabilities = [ 'None', 'Unknown', 'Low', 'Medium', 'High ']
        return xploitabilities[rank]

    ## Merges results from tracer db row
    # See if there is a tracer result for this runid
    def mergeTracer( self ):
        tracer = db.Tracer.factory(self.runid)
        if not tracer:
            self.tracer = None
            return
        self.tracer = tracer

    ## Reconstructs Crash object from database after it loads
    @orm.reconstructor
    def reconstructor(self):
        self.stackPointer           = self.obj["stackPointer"]
        self.crashAddress           = self.obj["crashAddress"]
        self.instructionPointer     = self.obj["instructionPointer"]

        if hasattr(self, 'ranks'):
            if self.tracer:
                self.ranks.append(self.tracer.rank)

            self.rank = max(self.ranks)
            self.exploitability = Crash.rankToExploitability(self.rank)
            self.ranksString                = self.ranksStringGenerate()

    ## Returns all the crashes in the db as Crash objects
    @staticmethod
    def getAll():
        session = db.getSession()
        return session.query( Crash ).all()

    ## Factory for crash object by runid
    # Factory for generating triage and exploitability information about a minidump. If
    # it already exists in the db, return the row.
    # @param runid Run id
    # @param dmpPath string path to minidump file
    # @return Crash object
    @staticmethod
    def factory( runid, targetPath=None ):
        cfg = harness.config
        session = db.getSession()
        runid = str(runid)
        ret = session.query( Crash ).filter( Crash.runid==runid ).first()
        if ret:
            return ret

        dmpPath = db.utilz.runidToDumpPath(runid)

        if not dmpPath:
            print("Unable to find dumpfile for runid %s" % runid)
            return None

        # Runs triager, which will give us exploitability info
        # using 2 engines: Google's breakpad and an reimplementation of Microsofts
        # !exploitable
        cmd = [ cfg.config['triager_path'], dmpPath ]
        out = subprocess.check_output(cmd, shell=False)
        # TODO: sorry didn't have time to clean this up before leave
        dirname = os.path.dirname( dmpPath )
        path = os.path.join(  dirname, "triage.txt" )
        with open(path, "wb", newline=None) as f:
            f.write(out)

        out = out.decode('utf8')
        j = None
        for line in out.splitlines():
            line = line.strip()
            if re.match( r"{.*}", line ):
                j = json.loads(line)
                j['output'] = out

        if not j:
            return None
        try:
            ret = Crash(j, runid, targetPath)
        except x:
            print("Unable to process crash json")
            return None


        ret.mergeTracer()
        ret.reconstructor()
        session.add(ret)
        session.commit()
        return ret

    ## Converts ranks list to colon seperated string
    def ranksStringGenerate(self):
        tmp = [ str(_) for _ in self.ranks ]
        return ":".join(tmp)

    ## Returns string representation or summary of crash
    def __repr__(self):
        tracerInfo = "None"
        if self.tracer:
            tracerInfo = self.tracer.formatted
        return """Exploitability: %s (%s)   Crash Reason: %s   Crash Address: %X    Instruction: %X   Crashash: %s    Tag: %s    Tracer: %s""" % (
            self.exploitability,
            self.ranksString,
            self.crashReason,
            self.crashAddress,
            self.instructionPointer,
            self.crashash,
            self.tag,
            tracerInfo )
#
