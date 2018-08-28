############################################################################
## @package conf
# Basic configration key/value pairs for db

from sqlalchemy import *
from sqlalchemy import ForeignKey
from sqlalchemy import orm
from sqlalchemy.orm import relationship
from sqlalchemy.sql.expression import func

from db.base import Base
import db

## Configuration key/value pairs
# currently this is only used for the ABI Version (conf.VERSION) but could be used
# for all kinds of configuration
class Conf(Base):

    __tablename__ = "conf"

    key                         = Column( String, primary_key=True )
    value                       = Column( Integer )

    ## Constructor
    # @param key key string
    # @param value value string for storage
    def __init__(self, key, value):
        self.key            = key
        self.value          = value

    ## Gets key/value from db
    # @param key key string
    # @param value value string for storage
    # @return Conf object with key/value pair
    @staticmethod
    def factory( key, value=None ):
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
