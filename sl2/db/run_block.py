from sqlalchemy import *
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

import datetime

from sl2 import db
from .base import Base
from sl2.db.coverage import PathRecord


## class RunBlock
# Stores information about a given set of runs. Can hold up to 25 runs by default (configured in the session manager)
class RunBlock(Base):
    __tablename__ = "runs"

    ## Unique ID for this block
    id = Column(Integer, primary_key=True)
    ## Slug mapping this block of runs to the config for their target
    target_config_slug = Column(String, ForeignKey("targets.target_slug"))
    ## Virtual member mapping to parents via the ORM
    target_config = relationship("TargetConfig", back_populates="runs")
    ## Virtual member mapping to parents via the ORM
    paths = relationship("PathRecord", back_populates="run_block")

    ## Timstamp for when this block started
    started = Column(DateTime)
    ## Timestamp for when this block ended
    ended = Column(DateTime, default=datetime.datetime.utcnow)

    ## Number of runs in this block
    runs = Column(Integer)
    ## Number of crashes found in this block
    crashes = Column(Integer)

    ## Whether bucketing was turned on during this block
    bucketing = Column(Boolean)
    ## The coverage score at the end of this block
    score = Column(Integer)
    ## The number of tries remaining for the given mutation strategy at the end of this block
    num_tries_remaining = Column(Integer)

    ## Number of unique execution paths discovered through the target program
    num_paths = Column(Integer)
    ## Estimated percentage of all unique excution paths covered
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


## class SessionManager
#  Decorator that allows for easy incorporation of run statistics into the database
class SessionManager(object):

    ## Constructor for crash object
    # @param target_slug - unique identifier for this target
    # @param block_size -- number of runs to store in one block
    def __init__(self, target_slug, block_size=25):
        self.target_slug = target_slug
        self.block_size = block_size
        self.runs_counted = 0
        self.crash_counter = 0
        self.started = datetime.datetime.utcnow()
        self.run_dict = {"hash": None, "bkt": False, "scr": -1, "rem": -1}

    ## Entrance for the decorator. Store the time the session manager was created
    def __enter__(self):
        self.started = datetime.datetime.utcnow()
        return self

    ## Exit for the decorator. Calls _handle_completion
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._handle_completion()

    ## Handles writing of the results to the database
    def _handle_completion(self):
        session = db.getSession()

        record = RunBlock(
            self.target_slug,
            self.started,
            self.runs_counted,
            self.crash_counter,
            self.run_dict["bkt"],
            self.run_dict["scr"],
            self.run_dict["rem"],
        )

        session.add(record)
        session.commit()

    ## Resets the session manager back to its original state
    def _reset(self):
        self.runs_counted = 0
        self.crash_counter = 0
        self.started = datetime.datetime.utcnow()

    ## Called each time a run completes. Will dump results to the database every `block_size` calls
    #  @param run - run object containing coverage information
    #  @param found_crash - boolean indicating whether a crash occurred
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
