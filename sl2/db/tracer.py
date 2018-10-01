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

    ## The string-ified exception code
    exception = Column(String)
    ## Disassembly of the instruction that caused the crash
    instruction = Column(String)
    ## Brief explanation of the exception
    reason = Column(String)

    ## Address of the most recent function call
    call0 = Column(String(20))
    ## Address of the second most recent function call
    call1 = Column(String(20))
    ## Address of the 3rd most recent function call
    call2 = Column(String(20))
    ## Address of the 4th most recent function call
    call3 = Column(String(20))
    ## Address of the 5th most recent function call
    call4 = Column(String(20))

    ## Address of the most recent instuction
    insn0 = Column(String(20))
    ## Address of the second most recent instruction
    insn1 = Column(String(20))
    ## Address of the 3rd most recent instruction
    insn2 = Column(String(20))
    ## Address of the 4th most recent instruction
    insn3 = Column(String(20))
    ## Address of the 5th most recent instruction
    insn4 = Column(String(20))

    # Contents of the rax register
    rax = Column(String(20))
    # Contents of the rbx register
    rbx = Column(String(20))
    # Contents of the rcx register
    rcx = Column(String(20))
    # Contents of the rdx register
    rdx = Column(String(20))
    # Contents of the rsp register
    rsp = Column(String(20))
    # Contents of the rbp register
    rbp = Column(String(20))
    # Contents of the rsi register
    rsi = Column(String(20))
    # Contents of the rdi register
    rdi = Column(String(20))
    # Contents of the r8 register
    r8 = Column(String(20))
    # Contents of the r9 register
    r9 = Column(String(20))
    # Contents of the r10 register
    r10 = Column(String(20))
    # Contents of the r11 register
    r11 = Column(String(20))
    # Contents of the r12 register
    r12 = Column(String(20))
    # Contents of the r13 register
    r13 = Column(String(20))
    # Contents of the r14 register
    r14 = Column(String(20))
    # Contents of the r15 register
    r15 = Column(String(20))
    # Contents of the rip register
    rip = Column(String(20))

    ## A bitmap containing the taint state of each register in the following order:
    ## "rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi",
    ## "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"
    regTaint = Column(Integer)

    ## Result of the `pc_tainted` check performed by the tracer -- Indicates whether RIP is tainted
    pc_tainted = Column(Boolean)
    ## Result of the `stack_tainted` check performed by the tracer -- Indicates whether the stack pointer is tainted
    stack_tainted = Column(Boolean)
    ## Result of the `is_ret` check performed by the tracer -- Indicates whether the crashing instruction is a return
    is_ret = Column(Boolean)
    ## Result of the `is_indirect` check performed by the tracer -- Indicates whether the crash is on an indirect branch
    is_indirect = Column(Boolean)
    ## Result of the `is_direct` check performed by the tracer -- Indicates whether the crash is on a direct branch
    is_direct = Column(Boolean)
    ## Result of the `is_call` check performed by the tracer -- Indicates whether the crash is on a call
    is_call = Column(Boolean)
    ## Result of the `mem_write` check performed by the tracer -- Indicates whether the crash occurs on a memory write
    mem_write = Column(Boolean)
    ## Result of the `mem_read` check performed by the tracer -- Indicates whether the crash occurs on a memory read
    mem_read = Column(Boolean)
    ## Result of the `tainted_src` check performed by the tracer -- Indicates whether the src of a memory r/w is tainted
    tainted_src = Column(Boolean)
    ## Result of the `tainted_dst` check performed by the tracer -- Indicates whether the dst of a memory r/w is tainted
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
            setattr(self, "call{}".format(i), hex(rawJson["last_calls"][i]))
            setattr(self, "insn{}".format(i), hex(rawJson["last_insns"][i]))

        flattened_regs = {}
        for reg in rawJson["regs"]:
            flattened_regs[reg["reg"]] = (reg["value"], reg["tainted"])

        reg_taint = 0
        for index, reg in enumerate(regs):
            if reg in flattened_regs:
                setattr(self, reg, hex(flattened_regs[reg][0]))
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
