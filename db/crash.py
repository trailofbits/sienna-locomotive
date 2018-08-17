from sqlalchemy import *
import os
import harness.config


from db.base import Base


class Crash(Base):

    __tablename__ = "crash"

    exploitability  = Column( Integer )
    runid           = Column( String, primary_key=True )

    def __init__(self, json):
        pass
