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

    ## Takes the slug referring to the target configuration (including arguments) and the path to the binary
    # @param slug
    # @param path
    def __init__(self, slug, path):
        self.target_slug = slug
        self.hash = hash_file(path)
        self.path = path

    ## Factory based on slug and path
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
