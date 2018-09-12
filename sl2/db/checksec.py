############################################################################
## @package checksec
#
# This is the python wrapper around winchecksec, a tool that's basically an
# equivalent of checksec.sh
#

from sqlalchemy import *
from sl2.harness import config
import subprocess
import json

from sl2 import db
from .base import Base
from .utilz import hash_file


## DB Wrapper for winchecksec
class Checksec(Base):
    PROBABILITIES = {
        'aslr': 0.792031321971442,
        'authenticode': 0.374942422846614,
        'cfg': 0.492860432980193,
        'dynamicBase': 0.796867802855827,
        'forceIntegrity': 0.0322432058959005,
        'gs': 0.652003684937817,
        'highEntropyVA': 0.437586365730078,
        'isolation': 1.0,
        'nx': 0.795485951174574,
        'rfg': 0.0631045601105481,
        'safeSEH': 0.257254721326578,
        'seh': 0.913403961308153
    }

    __tablename__ = "checksec"

    hash = Column(String(64), primary_key=True, unique=True)
    aslr = Column(Boolean)
    authenticode = Column(Boolean)
    cfg = Column(Boolean)
    dynamicBase = Column(Boolean)
    forceIntegrity = Column(Boolean)
    gs = Column(Boolean)
    highEntropyVA = Column(Boolean)
    isolation = Column(Boolean)
    nx = Column(Boolean)
    rfg = Column(Boolean)
    safeSEH = Column(Boolean)
    seh = Column(Boolean)
    path = Column(String)

    ## Constructor for checksec object that takes json object from winchecksec
    # @param json object from winchecksec
    def __init__(self, json_d):
        self.hash = hash_file(json_d["path"])
        self.aslr = json_d["aslr"]
        self.authenticode = json_d["authenticode"]
        self.cfg = json_d["cfg"]
        self.dynamicBase = json_d["dynamicBase"]
        self.forceIntegrity = json_d["forceIntegrity"]
        self.gs = json_d["gs"]
        self.highEntropyVA = json_d["highEntropyVA"]
        self.isolation = json_d["isolation"]
        self.nx = json_d["nx"]
        self.rfg = json_d["rfg"]
        self.safeSEH = json_d["safeSEH"]
        self.seh = json_d["seh"]
        self.path = json_d["path"]

    ## Factory for checksec from executable path
    # Gets checksec information for dll or exe.
    # If it already exists in the db, just return it
    # @param path Path to DLL or EXE
    # @return Checksec obj
    @staticmethod
    def byExecutable(path):
        cfg = config
        session = db.getSession()
        session.expire_on_commit = False

        ret = session.query(Checksec).filter(Checksec.hash == hash_file(path)).first()
        if ret:
            session.close()
            return ret
        checker = cfg.config['checksec_path']
        cmd = [checker, "-j", path]

        try:
            out = subprocess.check_output(cmd)
            ret = json.loads(out)
            ret = Checksec(ret)
            session.add(ret)
            session.commit()
            session.close()
        except subprocess.CalledProcessError as x:
            print("Exception", x)

        return ret

    ## Returns value between 0 and 1 as a percentage of the rarity of protection flags.
    # If a binary has a flag that's rarely implemented (like RFG) it will more quickly increase this value
    def protectionPercent(self):
        probsMax = 0
        probsSum = 0

        for k, mean in self.PROBABILITIES.items():
            x = int(self.__getattribute__(k))
            grab = 1 - mean
            if x == 1:
                probsSum = probsSum + grab
            probsMax += grab

        return probsSum / probsMax

    ## Creates short string description
    # Returns a strings seperated by pipe symbols that
    # succinctly describes the checksec state of the object
    # @return string
    def shortString(self):
        t = []
        if self.aslr:
            t.append("ASLR")
        if self.authenticode:
            t.append("Authenticode")
        if self.cfg:
            t.append("CFG")
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
        if self.safeSEH:
            t.append("SafeSEH")
        tags = ' | '.join(t)

        return "%3.0f%% (%s)" % (self.protectionPercent() * 100, tags)
