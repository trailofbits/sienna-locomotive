from sqlalchemy import *
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

from .base import Base


class CoverageRecord(Base):
    __tablename__ = 'coverage'

    id = Column(Integer, primary_key=True)
    run_block_id = Column(String, ForeignKey("runs.id"))
    run_block = relationship("RunBlock", back_populates="coverage", uselist=False)

    bucketing = Column(Boolean)
    score = Column(Integer)
    num_tries_remaining = Column(Integer)

    def __init__(self, run_block_id, bucketing, score, num_tries_remaining):
        self.run_block_id = run_block_id
        self.bucketing = bucketing
        self.score = score
        self.num_tries_remaining = num_tries_remaining
