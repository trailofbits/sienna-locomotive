############################################################################
# conf
#
# Basic configration key/value pairs for db

from sqlalchemy import *
from sqlalchemy import ForeignKey
from sqlalchemy import orm
from sqlalchemy.orm import relationship
from sqlalchemy.sql.expression import func

from db.base import Base
import db


class Conf(Base):

    __tablename__ = "conf"

    key                         = Column( String, primary_key=True )
    value                       = Column( Integer )

    def __init__(self, key, value):
        self.key            = key
        self.value          = value

    @staticmethod
    def factory( key, value=None ):
        """
        Gets key/value from db
        """
        session = db.getSession()

        ret = session.query( Conf ).filter( Conf.key==key ).first()
        if ret:
            return ret

        if not value:
            return None

        conf = Conf(key,value)
        session.add(conf)
        session.commit()

        return conf
