############################################################################
## @package tracer
# tracer.py
#
# db model for tracer.cpp json results

from sqlalchemy import *
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

from sl2 import db
from .base import Base


regs = ["rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"]


## Represents a tracer run
# The tracer is an SL2 DynamoRio client that runs after a crash to
# gain more information about exploitability using taint analysis.  This class
# Loads up the json file with the results and stores it in the db
#
# Example json file
# <pre>
#     "exception": "EXCEPTION_BREAKPOINT",
#     "instruction": "int3",
#     "last_calls": [
#         140699242861232,
#         140699242861064,
#         140699242861064,
#         140699242861056,
#         140699242861184
#     ],
#     "last_insns": [
#         140699242309722,
#         140699242309725,
#         140699242309727,
#         140699242309730,
#         140699242310037
#     ],
#     "location": 140699242310037,
#     "reason": "breakpoint",
#     "regs": [
#         {
#             "reg": "rax",
#             "tainted": false,
#             "value": 1080890113
#         },
#         //...............................................
#     ],
#     "score": 25,
#     "tainted_addrs": [
#         {
#             "size": 8,
#             "start": 2645403054665
#         }
#     ]
# }
# </pre>
class Tracer(Base):
    __tablename__ = 'tracer'

    ## Runid for the tracer run
    runid = Column(String(40), primary_key=True)
    ## Pickled object form of json object
    addrs = Column(PickleType)
    ## Formatted succinct string version of tracer results
    formatted = Column(String)
    ## Foreign key to crash object
    crash = relationship("Crash", back_populates="tracer", uselist=False)
    ## Unique crash id
    crashId = Column(Integer, ForeignKey('crash.id'))
    ## The exploitability rank based solely on tracer
    rank = Column(Integer)

    exception = Column(String)
    instruction = Column(String)
    reason = Column(String)

    call0 = Column(Integer)
    call1 = Column(Integer)
    call2 = Column(Integer)
    call3 = Column(Integer)
    call4 = Column(Integer)

    insn0 = Column(Integer)
    insn1 = Column(Integer)
    insn2 = Column(Integer)
    insn3 = Column(Integer)
    insn4 = Column(Integer)

    rax = Column(Integer)
    rbx = Column(Integer)
    rcx = Column(Integer)
    rdx = Column(Integer)
    rsp = Column(Integer)
    rbp = Column(Integer)
    rsi = Column(Integer)
    rdi = Column(Integer)
    r8 = Column(Integer)
    r9 = Column(Integer)
    r10 = Column(Integer)
    r11 = Column(Integer)
    r12 = Column(Integer)
    r13 = Column(Integer)
    r14 = Column(Integer)
    r15 = Column(Integer)
    rip = Column(Integer)

    regTaint = Column(Integer)

    pc_tainted = Column(Boolean)
    stack_tainted = Column(Boolean)
    is_ret = Column(Boolean)
    is_indirect = Column(Boolean)
    is_direct = Column(Boolean)
    is_call = Column(Boolean)
    mem_write = Column(Boolean)
    mem_read = Column(Boolean)
    tainted_src = Column(Boolean)
    tainted_dst = Column(Boolean)

    ## Constructor for a Tracer object
    # @param runid Run ID of tracer run
    # @param formatted String formatting results
    # @param rawJson json object used for pickling
    def __init__(self, runid, formatted, rawJson):
        self.runid = runid
        self.formatted = formatted
        self.addrs = rawJson["tainted_addrs"]  # TODO - record memory map so these are actually useful
        self.rank = rawJson["score"] / 25

        self.exception = rawJson["exception"]
        self.instruction = rawJson["instruction"]
        self.reason = rawJson["reason"]

        for i in range(5):
            setattr(self, "call{}".format(i), rawJson["last_calls"][i])
            setattr(self, "insn{}".format(i), rawJson["last_insns"][i])

        flattened_regs = {}
        for reg in rawJson["regs"]:
            flattened_regs[reg["reg"]] = (reg["value"], reg["tainted"])

        reg_taint = 0
        for index, reg in enumerate(regs):
            if reg in flattened_regs:
                setattr(self, reg, flattened_regs[reg][0])
            else:
                print("[!] The tracer didn't return a value for {}".format(reg))
            if flattened_regs[reg][1]:
                reg_taint += (1 << index)
        self.regTaint = reg_taint

        self.pc_tainted = rawJson["pc_tainted"]
        self.stack_tainted = rawJson["stack_tainted"]
        self.is_ret = rawJson["is_ret"]
        self.is_indirect = rawJson["is_indirect"]
        self.is_direct = rawJson["is_direct"]
        self.is_call = rawJson["is_call"]
        self.mem_write = rawJson["mem_write"]
        self.mem_read = rawJson["mem_read"]
        self.tainted_src = rawJson["tainted_src"]
        self.tainted_dst = rawJson["tainted_dst"]

    ## Factory for create or retrieving tracer object from db
    # @param runid Runid of the tracer run
    # @param formatted String summary of tracer run
    # @param raw json object
    @staticmethod
    def factory(runid, formatted=None, raw=None):
        runid = str(runid)
        session = db.getSession()
        ret = session.query(Tracer).filter(Tracer.runid == runid).first()
        if ret:
            return ret

        if not formatted and not raw:
            print("Could not find tracer for runid ", runid)
            return None

        ret = Tracer(runid, formatted, raw)

        session.add(ret)
        session.commit()
