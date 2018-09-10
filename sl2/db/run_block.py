from sqlalchemy import *
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

import datetime

from sl2 import db
from .base import Base
from sl2.db.coverage import CoverageRecord
from sl2.harness.instrument import read_coverage_information


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


class SessionManager(object):

    def __init__(self, target_slug, block_size=25):
        self.target_slug = target_slug
        self.block_size = block_size
        self.runs_counted = 0
        self.crash_counter = 0
        self.started = datetime.datetime.utcnow()

    def __enter__(self):
        self.started = datetime.datetime.utcnow()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._handle_completion()

    def _handle_completion(self):
        bucketing, score, remaining = read_coverage_information()

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

    def run_complete(self, found_crash=False):
        self.runs_counted += 1
        if found_crash:
            self.crash_counter += 1

        if self.runs_counted == self.block_size:
            self._handle_completion()
            self._reset()
