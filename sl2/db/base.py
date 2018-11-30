############################################################################
## @package base
# This is broken up into it's own file to avoid a cycle.  It's used as the
# base class for all our sqlalchemy classes
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
