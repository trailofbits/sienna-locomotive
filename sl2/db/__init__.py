############################################################################
## @package db
# Main interface for accessing the sl2 database

from sqlalchemy import create_engine
from sqlalchemy.pool import *
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sl2.harness import config
import os
from . import base

## Imports of the other classes
from .conf import Conf
from .tracer import Tracer
from .checksec import Checksec
from .crash import Crash
from .target_config import TargetConfig
from .run_block import RunBlock

from . import utilz


## Gets sqlalchemy database session
# Used to get a session for db stuff.  You can't reuse a session or db objects across
# @return sqlalchemy database session
def getSession():
    return Session()


## Checks database and ABI version number
# This will check the ABI version (config.VERSION) in python against
# the version number if the database. If it's not in the database, we know
# this is a clean run so we go ahead and store it.  If there is a version number
# in the db, and it's less than the config.VERSION, we know there is mismatch with the
# ABI version and will throw and error to protect the user
def checkVersionNumber():
    versionNow = config.VERSION
    confVersion = Conf.factory('version')
    if not confVersion:
        Conf.factory("version", versionNow)
        return

    if confVersion.value < versionNow:
        msg = """Current configuration version %d is older than software version of %d .
This means your configuration and data in the SL2 directory are older than the current code.
Options include:
  * Run  ./make reconfig
  * Remove the SL2 directory in %s
        """ % (confVersion.value, versionNow, config.sl2_dir)
        print("!" * 77)
        print(msg)
        print("!" * 77)
        xception = BaseException(msg)
        raise xception


## File path to db
dbpath = '%s/%s' % (config.sl2_dir, 'sl2.db')

## URL to db for sqlalchemy
dburl = os.path.join('sqlite:///%s' % dbpath)

## sqlalchemy database engine
engine = create_engine(dburl, poolclass=NullPool)

base.Base.metadata.create_all(engine)
session_factory = sessionmaker(bind=engine)
Session = scoped_session(session_factory)
Session().commit()

# Checks for version mismatch
checkVersionNumber()
