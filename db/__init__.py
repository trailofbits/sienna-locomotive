from sqlalchemy import create_engine
from sqlalchemy.pool import *
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from harness import config
import os
import db.base


# check_same_thread=False
dburl = os.path.join( 'sqlite:///%s/%s'% ( config.sl2_dir, 'sl2.db' ) )


#engine = create_engine(dburl, poolclass=SingletonThreadPool)
#engine = create_engine(dburl, poolclass=QueuePool )
#engine = create_engine(dburl, poolclass=NullPool, connect_args={'check_same_thread': False}, echo=True)
engine = create_engine(dburl, poolclass=NullPool )

from .checksec import Checksec
from .crash import Crash

db.base.Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
Session = scoped_session(Session)

Session().commit()


def getSession():
    return Session()
