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


## class Checksec
# Encodes the information output by WinCheckSec into the database.
# See https://github.com/trailofbits/winchecksec for more information
class Checksec(Base):
    PROBABILITIES = {
        "aslr": 0.792_031_321_971_442,
        "authenticode": 0.374_942_422_846_614,
        "cfg": 0.492_860_432_980_193,
        "dynamicBase": 0.796_867_802_855_827,
        "forceIntegrity": 0.032_243_205_895_900_5,
        "gs": 0.652_003_684_937_817,
        "highEntropyVA": 0.437_586_365_730_078,
        "isolation": 1.0,
        "nx": 0.795_485_951_174_574,
        "rfg": 0.063_104_560_110_548_1,
        "safeSEH": 0.257_254_721_326_578,
        "seh": 0.913_403_961_308_153,
    }

    __tablename__ = "checksec"

    ## Hash of the binary -- serves as the primary key for this executable throughout all child tables
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
        checker = cfg.config["checksec_path"]
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
    def _protection_percent(self):
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
    def short_description(self):
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
        tags = " | ".join(t)

        return "{0:3.0f}% ({1})".format(self._protection_percent() * 100, tags)
