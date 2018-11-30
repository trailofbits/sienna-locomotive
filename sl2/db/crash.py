############################################################################
## @package crash
# crash.py
#
# Model for crashing runs in sl2.  Puts basic exploitability and triage
# info in the database

from sqlalchemy import *
from sqlalchemy import orm
from sqlalchemy.orm import relationship
from sl2.harness import config
import json
import os
import re
import subprocess
from sqlalchemy.sql.expression import func

from .base import Base
from sl2 import db


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

    id = Column(Integer, primary_key=True)
    target_config_slug = Column(String, ForeignKey("targets.target_slug"))
    target_config = relationship("TargetConfig", back_populates="crashes")
    ## Runid for the crash
    runid = Column(String(40))
    ## Crash address as hex string
    crashAddressString = Column(String(20))
    ## Textual description of crash reason
    crashReason = Column(String(270))
    ## Crashash (Crash Hash).  Identifier for binning related crashes
    crashash = Column(String(64))
    ## Text string description of Exploitability. Can be High, Medium, Low, Unknown, or None.
    exploitability = Column(String(32))
    ## Instruction Pointer (pc, eip, rep) as hex string
    instructionPointerString = Column(String(20))
    ## Path to minidump for crash
    minidumpPath = Column(String(270))
    ## Path to target (PUT)
    targetPath = Column(String(270))
    ## Integer version of exploitability (0-4, inclusive)
    rank = Column(Integer)
    ## A colon separated list of each engines exploitability.  For example 1:2:2
    ranksString = Column(String(8))
    ## Stack pointer (rsp) at crash as hex string
    stackPointerString = Column(String(20))
    ## Tag or path used to succinctly describe crash bin
    tag = Column(String(128))
    ## Foreign key to tracer results
    tracer = relationship("Tracer", order_by=db.Tracer.runid, back_populates="crash", uselist=False)
    ## Summary of triage information
    output = Column(String)
    ## Pickled object version of json object
    obj = Column(PickleType)
    ## Timestamp of the crash
    timestamp = Column(DateTime, default=func.now())
    ## register follow
    ## The contents of the cs register at the time of the crash
    cs = Column(String(20))
    ## The contents of the dr0 register at the time of the crash
    dr0 = Column(String(20))
    ## The contents of the dr1 register at the time of the crash
    dr1 = Column(String(20))
    ## The contents of the dr2 register at the time of the crash
    dr2 = Column(String(20))
    ## The contents of the dr3 register at the time of the crash
    dr3 = Column(String(20))
    ## The contents of the dr6 register at the time of the crash
    dr6 = Column(String(20))
    ## The contents of the dr7 register at the time of the crash
    dr7 = Column(String(20))
    ## The contents of the ds register at the time of the crash
    ds = Column(String(20))
    ## The contents of the eflags register at the time of the crash
    eflags = Column(String(20))
    ## The contents of the es register at the time of the crash
    es = Column(String(20))
    ## The contents of the fs register at the time of the crash
    fs = Column(String(20))
    ## The contents of the gs register at the time of the crash
    gs = Column(String(20))
    ## The contents of the mx_csr register at the time of the crash
    mx_csr = Column(String(20))
    ## The contents of the r10 register at the time of the crash
    r10 = Column(String(20))
    ## The contents of the r11 register at the time of the crash
    r11 = Column(String(20))
    ## The contents of the r12 register at the time of the crash
    r12 = Column(String(20))
    ## The contents of the r13 register at the time of the crash
    r13 = Column(String(20))
    ## The contents of the r14 register at the time of the crash
    r14 = Column(String(20))
    ## The contents of the r15 register at the time of the crash
    r15 = Column(String(20))
    ## The contents of the r8 register at the time of the crash
    r8 = Column(String(20))
    ## The contents of the r9 register at the time of the crash
    r9 = Column(String(20))
    ## The contents of the rax register at the time of the crash
    rax = Column(String(20))
    ## The contents of the rbp register at the time of the crash
    rbp = Column(String(20))
    ## The contents of the rbx register at the time of the crash
    rbx = Column(String(20))
    ## The contents of the rcx register at the time of the crash
    rcx = Column(String(20))
    ## The contents of the rdi register at the time of the crash
    rdi = Column(String(20))
    ## The contents of the rdx register at the time of the crash
    rdx = Column(String(20))
    ## The contents of the rip register at the time of the crash
    rip = Column(String(20))
    ## The contents of the rsi register at the time of the crash
    rsi = Column(String(20))
    ## The contents of the rsp register at the time of the crash
    rsp = Column(String(20))
    ## The contents of the ss register at the time of the crash
    ss = Column(String(20))

    ## Constructor for crash object
    # @param runid Run ID of crash
    # @param j json object version
    def __init__(self, j, slug, runid=None, targetPath=None):
        try:

            self.runid = runid
            ## Json object
            self.output = j["output"]
            del (j["output"])
            self.obj = j

            self.stackPointer = self.obj["stackPointer"]
            self.crashAddress = self.obj["crashAddress"]
            self.instructionPointer = self.obj["instructionPointer"]

            self.target_config_slug = slug

            ## Crash address as hex string
            self.crashAddressString = hex(j["crashAddress"])
            ## Textual description of crash reason
            self.crashReason = j["crashReason"]
            ## Crashash (Crash Hash).  Identifier for binning related crashes
            self.crashash = j["crashash"]
            ## Text string description of Exploitability. Can be High, Medium, Low, Unknown, or None.
            self.exploitability = j["exploitability"]
            ## Instruction Pointer (pc, eip, rep) as hex string
            self.instructionPointerString = hex(j["instructionPointer"])
            ## Path to minidump for crash
            self.minidumpPath = j["minidumpPath"]
            ## Path to target binary
            self.targetPath = targetPath
            ## Integer version of exploitability (0-4, inclusive)
            self.rank = j["rank"]
            ## Stack pointer (rsp) at crash as hex string
            self.stackPointerString = hex(j["stackPointer"])
            ## Tag or path used to succinctly describe crash bin
            self.tag = j["tag"]
            ## List of each engines exploitability.  For example [1,2,2]
            self.ranks = j["ranks"]
            ## A colon separated list of each engines exploitability.  For example 1:2:2
            self.ranksString = self.ranksStringGenerate()
            ## Summary of triage information
            regs = [
                "cs",
                "dr0",
                "dr1",
                "dr2",
                "dr3",
                "dr6",
                "dr7",
                "ds",
                "eflags",
                "es",
                "fs",
                "gs",
                "mx_csr",
                "r10",
                "r11",
                "r12",
                "r13",
                "r14",
                "r15",
                "r8",
                "r9",
                "rax",
                "rbp",
                "rbx",
                "rcx",
                "rdi",
                "rdx",
                "rip",
                "rsi",
                "rsp",
                "ss",
            ]
            for reg in regs:
                setattr(self, reg, hex(j[reg]))

        except KeyError:
            raise Exception("Was unable to parse crash json from triager")

    @property
    def int_exploitability(self):
        return {"High": 10, "Medium": 20, "Low": 30, "Unknown": 40}[self.exploitability]

    @property
    def occurrences(self):
        session = db.getSession()
        return session.query(Crash).filter(Crash.crashash == self.crashash).count()

    ## Converts integer rank to exploitability string
    # @param rank integer rank
    # @return string
    @staticmethod
    def rankToExploitability(rank):
        xploitabilities = ["None", "Unknown", "Low", "Medium", "High "]
        return xploitabilities[rank]

    ## Merges results from tracer db row
    # See if there is a tracer result for this runid
    def mergeTracer(self):
        tracer = db.Tracer.factory(self.runid)
        if not tracer:
            self.tracer = None
            return
        self.tracer = tracer

    ## Reconstructs Crash object from database after it loads
    @orm.reconstructor
    def reconstructor(self):
        self.stackPointer = self.obj["stackPointer"]
        self.crashAddress = self.obj["crashAddress"]
        self.instructionPointer = self.obj["instructionPointer"]

        if hasattr(self, "ranks"):
            if self.tracer:
                self.ranks.append(self.tracer.rank)

            self.rank = max(self.ranks)
            self.exploitability = Crash.rankToExploitability(self.rank)
            self.ranksString = self.ranksStringGenerate()

    ## Returns all the crashes in the db as Crash objects
    @staticmethod
    def getAll():
        session = db.getSession()
        return session.query(Crash).all()

    ## Factory for crash object by runid
    # Factory for generating triage and exploitability information about a minidump. If
    # it already exists in the db, return the row.
    # @param runid Run id
    # @param dmpPath string path to minidump file
    # @return Crash object
    @staticmethod
    def factory(runid, slug=None, targetPath=None):
        cfg = config
        session = db.getSession()
        runid = str(runid)
        ret = session.query(Crash).filter(Crash.runid == runid).first()
        if ret:
            return ret

        dmpPath = db.utilz.runidToDumpPath(runid)

        if not dmpPath:
            print("Unable to find dumpfile for runid %s" % runid)
            return None

        # Runs triager, which will give us exploitability info
        # using 2 engines: Google's breakpad and an reimplementation of Microsofts
        # !exploitable
        cmd = [cfg.config["triager_path"], dmpPath]
        out = subprocess.check_output(cmd, shell=False)
        # TODO: sorry didn't have time to clean this up before leave
        dirname = os.path.dirname(dmpPath)
        path = os.path.join(dirname, "triage.txt")
        with open(path, "wb", newline=None) as f:
            f.write(out)

        out = out.decode("utf8")
        j = None
        for line in out.splitlines():
            line = line.strip()
            if re.match(r"{.*}", line):
                j = json.loads(line)
                j["output"] = out

        if not j:
            return None
        try:
            ret = Crash(j, slug, runid, targetPath)
        except:
            print("Unable to process crash json")
            return None

        ret.mergeTracer()
        ret.reconstructor()
        session.add(ret)
        session.commit()
        return ret

    ## Converts ranks list to colon seperated string
    def ranksStringGenerate(self):
        tmp = [str(_) for _ in self.ranks]
        return ":".join(tmp)

    ## Returns string representation or summary of crash
    def __repr__(self):
        tracerInfo = "None"
        if self.tracer:
            tracerInfo = self.tracer.formatted
        return (
            """Exploitability: %s (%s)   Crash Reason: %s   Crash Address: %X    Instruction: %X   Crashash: %s    Tag: %s    Tracer: %s"""
            % (
                self.exploitability,
                self.ranksString,
                self.crashReason,
                self.crashAddress,
                self.instructionPointer,
                self.crashash,
                self.tag,
                tracerInfo,
            )
        )


#
