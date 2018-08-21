############################################################################
# tracer.py
#
# db model for tracer.cpp json results

from sqlalchemy import *
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
import harness.config
import json
import os

import db
from db.base import Base


class Tracer(Base):

    __tablename__ = 'tracer'

    runid               = Column( String(40), primary_key=True )

    tracerJson          = Column( PickleType )
    tracerFormatted     = Column( String )
    crash               = relationship( "Crash", back_populates="tracer", uselist=False )
    crashId             = Column(Integer, ForeignKey('crash.id'))

    def __init__(self, runid, formatted, rawJson):
        self.runid              = runid
        self.tracerFormatted    = formatted
        self.tracerJson         = rawJson

    @staticmethod
    def factory( runid, formatted=None, raw=None ):

        runid=str(runid)
        session = db.getSession()
        ret = session.query( Tracer ).filter( Tracer.runid==runid ).first()
        if ret:
            return ret

        if not formatted and not raw:
            print("Could not find tracer for runid ", runid)
            return None

        ret = Tracer( runid, formatted, raw )
        session.add(ret)
        session.commit()
        #session.close()



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