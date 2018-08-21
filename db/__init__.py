############################################################################
# Main interface for accessing the sl2 database

from sqlalchemy import create_engine
from sqlalchemy.pool import *
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from harness import config
import os
import db.base


dburl = os.path.join( 'sqlite:///%s/%s'% ( config.sl2_dir, 'sl2.db' ) )
engine = create_engine(dburl, poolclass=NullPool )

from .checksec import Checksec
from .crash import Crash

db.base.Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
Session = scoped_session(Session)
Session().commit()


def getSession():
    """
    Used to get a session for db stuff.  You can't reuse a session or db objects across
    threads
    """
    return Session()
