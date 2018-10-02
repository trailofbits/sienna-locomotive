from sqlalchemy import *
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
import datetime

from sl2 import db
from .base import Base


## class PathRecord
#  Records unique execution paths through a given target
class PathRecord(Base):
    __tablename__ = 'paths'

    ## Stores the hash of the coverage table that we use to identify paths
    hash = Column(String(64), primary_key=True)
    ## Ties the path record to the target binary configuration
    target_config_slug = Column(String, ForeignKey("targets.target_slug"))
    target_config = relationship("TargetConfig", back_populates="paths")

    ## Ties the path record to the block of runs in which it was first encountered
    run_block_id = Column(String, ForeignKey("runs.id"))
    run_block = relationship("RunBlock")

    # coverage = relationship("CoverageRecord", back_populates="run_block", uselist=False)
    ## Stores the exact time this path was first seen
    created = Column(DateTime, default=datetime.datetime.utcnow)
    ## Stores the timstamp of the last encounter with this path
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    ## Stores the total number of times this path has been seen
    count = Column(Integer)

    ## Create an empty record with the hash of the path and the target
    def __init__(self, pathhash, target_slug):
        self.hash = pathhash
        self.target_config_slug = target_slug
        self.count = 1

    ## Creates a new path record for paths we haven't seen before. Otherwise, finds the matching database record for the
    ## given path hash and increments it
    @staticmethod
    def incrementPath(pathhash, target_slug):
        session = db.getSession()
        session.expire_on_commit = False

        ret = session.query(PathRecord).filter(PathRecord.hash == pathhash).first()
        if ret:
            ret.count = ret.count + 1
            ret.last_seen = datetime.datetime.utcnow()
        else:
            ret = PathRecord(pathhash, target_slug)
            session.add(ret)

        session.commit()
        session.close()

    ## Uses a Chao1 estimator to estimate the current fraction of the total unique paths that have been analyzed so far
    #  @return (num_paths, estimated) - tuple containing the number of unique paths and a float from [0,1] estimating
    #   the fraction of possible paths that have been evaluated so far.
    @staticmethod
    def estimate_current_path_coverage(target_slug):
        session = db.getSession()
        target_query = session.query(PathRecord).filter(PathRecord.target_config_slug == target_slug)
        num_paths = target_query.count()
        num_singletons = target_query.filter(PathRecord.count == 1).count()
        num_doubletons = target_query.filter(PathRecord.count == 2).count()
        num_runs = sum(x.count for x in target_query.all())

        session.close()
        # TODO - is it fair to calculate assuming at least one doubleton here?
        c = num_paths / (num_paths + ((num_runs - 1) / num_runs) * ((num_singletons ** 2) / (2 * max(num_doubletons, 1))))
        print("Total Paths:", num_paths,
              # "Singletons:", num_singletons,
              # "Doubletons:", num_doubletons,
              "Total Runs:", num_runs,
              "Estimated Path Fraction:", c)
        return num_paths, c
