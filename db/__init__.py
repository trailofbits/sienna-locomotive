############################################################################
# Main interface for accessing the sl2 database

from sqlalchemy import create_engine
from sqlalchemy.pool import *
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from harness import config
import os
import db.base



def getSession():
    """
    Used to get a session for db stuff.  You can't reuse a session or db objects across
    threads
    """
    return Session()



def checkVersionNumber():
    versionNow = config.VERSION
    confVersion = db.Conf.factory('version')
    if not confVersion:
        print("There is no existing version. adding")
        db.Conf.factory( "version", versionNow )
        return

    if confVersion.value < versionNow:
        msg = """Current configuration version %d is older than software version of %d .
This means your configuration and data in the SL2 directory are older than the current code.
Options include:
  * Run  ./make reconfig
  * Remove the SL2 directory in %s
        """ % (confVersion.value, versionNow, config.sl2_dir)
        print("!"*77)
        print(msg)
        print("!"*77)
        xception = BaseException(msg)
        raise( xception )

    else:
        print("Versions match!", versionNow )




dburl = os.path.join( 'sqlite:///%s/%s'% ( config.sl2_dir, 'sl2.db' ) )
engine = create_engine(dburl, poolclass=NullPool )
from .conf import Conf
from .tracer import Tracer
from .checksec import Checksec
from .crash import Crash

from . import utilz

db.base.Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
Session = scoped_session(Session)
Session().commit()


checkVersionNumber()

