from sqlalchemy import *
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

import datetime
import struct

from sl2 import db
from .base import Base
from sl2.db.coverage import CoverageRecord


class RunBlock(Base):
    __tablename__ = 'runs'

    id = Column(Integer, primary_key=True)
    target_config_slug = Column(String, ForeignKey("targets.target_slug"))
    target_config = relationship("TargetConfig", back_populates="runs")

    coverage = relationship("CoverageRecord", back_populates="run_block", uselist=False)

    started = Column(DateTime)
    ended = Column(DateTime, default=datetime.datetime.utcnow)
    runs = Column(Integer)
    crashes = Column(Integer)

    def __init__(self, target_slug, started, runs, crashes):
        self.target_config_slug = target_slug
        self.started = started
        self.runs = runs
        self.crashes = crashes

def read_coverage_information(arena_id):
    if arena_id is not None:
        msg = arena_id.encode('utf-16')[:-2]
        # with open(config.sl2_server_pipe_path, 'r+b', 0) as pipe:
        #     pipe.write(struct.pack('B', 15))
        #     pipe.seek(0)
        #
        #     pipe.write(struct.pack('I', len(msg)) + msg)
        #     pipe.seek(0)
        #
        #     n = struct.unpack('I', pipe.read(4))[0]
        #     bucketing = pipe.read(n)
        #     pipe.seek(0)
        #     n = struct.unpack('I', pipe.read(4))[0]
        #     score = pipe.read(n)
        #     pipe.seek(0)
        #     n = struct.unpack('I', pipe.read(4))[0]
        #     num_remaining = pipe.read(n)
        #     pipe.seek(0)
        #
        #     print("Bucketing:", bucketing)
        #     print("Score:", score)
        #     print("Num Remaining:", num_remaining)
        #
        #     return bucketing, score, num_remaining
    return False, 0, 0

class SessionManager(object):

    def __init__(self, target_slug, block_size=25):
        self.target_slug = target_slug
        self.block_size = block_size
        self.runs_counted = 0
        self.crash_counter = 0
        self.started = datetime.datetime.utcnow()
        self.last_arena = None

    def __enter__(self):
        self.started = datetime.datetime.utcnow()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._handle_completion()

    def _handle_completion(self):
        bucketing, score, remaining = read_coverage_information(self.last_arena)

        session = db.getSession()

        record = RunBlock(self.target_slug, self.started, self.runs_counted, self.crash_counter)
        cov = CoverageRecord(record, bucketing, score, remaining)  # TODO Get coverage

        session.add(record)
        session.add(cov)
        session.commit()

    def _reset(self):
        self.runs_counted = 0
        self.crash_counter = 0
        self.started = datetime.datetime.utcnow()

    def run_complete(self, run, found_crash=False):
        self.last_arena = run.last_arena
        self.runs_counted += 1
        if found_crash:
            self.crash_counter += 1

        if self.runs_counted == self.block_size:
            self._handle_completion()
            self._reset()
