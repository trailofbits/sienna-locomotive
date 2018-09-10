from sqlalchemy import *
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

import time

from sl2 import db
from .base import Base

class RunBlock(Base):
    __tablename__ = 'runs'

    id = Column(Integer, primary_key=True)
    target_config_slug = Column(String, ForeignKey("targets.target_slug"))
    target_config = relationship("TargetConfig", back_populates="runs")
    started = Column(DateTime)
    ended = Column(DateTime, default=func.now())
    runs = Column(Integer)
    crashes = Column(Integer)

    def __init__(self, runid, formatted, rawJson):
        pass

class SessionManager(object):

    def __init__(self, block_size=25):
        self.block_size = block_size
        self.runs_counted = 0
        self.crash_counter = 0
        self.started = time.time()

    def __enter__(self):
        self.started = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._handle_completion()

    def _handle_completion(self):
        # get coverage
        # record new run block
        print("Finished", self.runs_counted, "runs in", time.time() - self.started, "seconds, with", self.crash_counter, "crashes")

    def _reset(self):
        self.runs_counted = 0
        self.crash_counter = 0
        self.started = time.time()

    def run_complete(self, found_crash=False):
        self.runs_counted += 1
        if found_crash:
            self.crash_counter += 1

        if self.runs_counted == self.block_size:
            self._handle_completion()
            self._reset()
