############################################################################
## @package TargetConfig
#
# Tracks different run configurations for individual binaries
#

from sqlalchemy import *
from sqlalchemy.orm import relationship

import db
from db.base import Base
from db.utilz import hash_file


## DB Wrapper for Target Config Files
class TargetConfig(Base):
    __tablename__ = "targets"

    target_slug = Column(String, primary_key=True, unique=True)
    hash = Column(String(64), ForeignKey("checksec.hash"))
    path = Column(String)

    crashes = relationship("Crash", back_populates="target_config")

    ## Constructor for checksec object that takes json object from winchecksec
    # @param slug
    # @param path
    def __init__(self, slug, path):
        self.target_slug = slug
        self.hash = hash_file(path)
        self.path = path

    ## Factory for checksec from executable path
    # Gets checksec information for dll or exe.
    # If it already exists in the db, just return it
    # @param slug
    # @param path Path to DLL or EXE
    # @return TargetConfig
    @staticmethod
    def bySlug(slug, path):
        session = db.getSession()

        ret = session.query(TargetConfig).filter(TargetConfig.target_slug == slug).first()
        if ret is None:
            ret = TargetConfig(slug, path)
            session.add(ret)
            session.commit()

        return ret
