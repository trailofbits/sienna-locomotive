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
    obj = Column(PickleType)
    ## Formatted succinct string version of tracer results
    formatted = Column(String)
    ## Foreign key to crash object
    crash = relationship("Crash", back_populates="tracer", uselist=False)
    ## Unique crash id
    crashId = Column(Integer, ForeignKey('crash.id'))
    ## The exploitability rank based solely on tracer
    rank = Column(Integer)
    ## Constructor for a Tracer object
    # @param runid Run ID of tracer run
    # @param formatted String formatting results
    # @param rawJson json object used for pickling
    def __init__(self, runid, formatted, rawJson):
        self.runid = runid
        self.formatted = formatted
        self.obj = rawJson
        self.rank = self.obj["score"] / 25

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
