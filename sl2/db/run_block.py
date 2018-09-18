from sqlalchemy import *
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

import datetime

from sl2 import db
from .base import Base
from sl2.db.coverage import PathRecord


class RunBlock(Base):
    __tablename__ = 'runs'

    id = Column(Integer, primary_key=True)
    target_config_slug = Column(String, ForeignKey("targets.target_slug"))
    target_config = relationship("TargetConfig", back_populates="runs")

    paths = relationship("PathRecord", back_populates="run_block")

    started = Column(DateTime)
    ended = Column(DateTime, default=datetime.datetime.utcnow)
    runs = Column(Integer)
    crashes = Column(Integer)

    bucketing = Column(Boolean)
    score = Column(Integer)
    num_tries_remaining = Column(Integer)

    num_paths = Column(Integer)
    path_coverage = Column(Numeric)

    def __init__(self, target_slug, started, runs, crashes, bucketing, score, num_tries_remaining):
        self.target_config_slug = target_slug
        self.started = started
        self.runs = runs
        self.crashes = crashes
        self.bucketing = bucketing
        self.score = score
        self.num_tries_remaining = num_tries_remaining

        self.num_paths, self.path_coverage = PathRecord.estimate_current_path_coverage(target_slug)


class SessionManager(object):

    def __init__(self, target_slug, block_size=25):
        self.target_slug = target_slug
        self.block_size = block_size
        self.runs_counted = 0
        self.crash_counter = 0
        self.started = datetime.datetime.utcnow()
        self.run_dict = {"hash": None, "bkt": False, "scr": -1, "rem": -1}

    def __enter__(self):
        self.started = datetime.datetime.utcnow()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._handle_completion()

    def _handle_completion(self):
        session = db.getSession()

        record = RunBlock(self.target_slug, self.started, self.runs_counted, self.crash_counter,
                          self.run_dict["bkt"], self.run_dict["scr"], self.run_dict["rem"])

        session.add(record)
        session.commit()

    def _reset(self):
        self.runs_counted = 0
        self.crash_counter = 0
        self.started = datetime.datetime.utcnow()

    def run_complete(self, run, found_crash=False):
        self.run_dict = run.coverage if run.coverage is not None else {"hash": None, "bkt": False, "scr": -1, "rem": -1}
        self.runs_counted += 1
        if self.run_dict["hash"]:
            PathRecord.incrementPath(self.run_dict["hash"], self.target_slug)
        if found_crash:
            self.crash_counter += 1

        if self.runs_counted == self.block_size:
            self._handle_completion()
            self._reset()
