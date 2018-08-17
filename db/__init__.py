from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from harness import config
import os
import db.base

dburl = os.path.join( 'sqlite:///%s/%s'% ( config.sl2_dir, 'sl2.db' ) )

engine = create_engine(dburl)

from .checksec import Checksec
from .crash import Crash

db.base.Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

session.commit()

config.session = session

def persist(obj):
    session.add(obj)
    session.commit()