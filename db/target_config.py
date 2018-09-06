############################################################################
## @package TargetConfig
#
# Tracks different run configurations for individual binaries
#

from sqlalchemy import *

import db
from db.base import Base
from db.utilz import hash_file


## DB Wrapper for winchecksec
class TargetConfig(Base):
    __tablename__ = "target_configs"

    target_slug = Column(String, primary_key=True, unique=True)
    hash = Column(String(64), ForeignKey("checksec.hash"))
    path = Column(String)

    ## Constructor for checksec object that takes json object from winchecksec
    # @param json object from winchecksec
    def __init__(self, slug, path):
        self.target_slug = slug
        self.hash = hash_file(path)
        self.path = path

    ## Factory for checksec from executable path
    # Gets checksec information for dll or exe.
    # If it already exists in the db, just return it
    # @param path Path to DLL or EXE
    # @return Checksec obj
    @staticmethod
    def bySlug(slug, path):
        session = db.getSession()

        ret = session.query(TargetConfig).filter(TargetConfig.target_slug == slug).first()
        if ret is None:
            ret = TargetConfig(slug, path)
            session.add(ret)
            session.commit()

        return ret
