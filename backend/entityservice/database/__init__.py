from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from .util import *

from .authorization import *
from .deletion import *
from .insertions import *
from .metrics import *
from .selections import *

from .models import models

engine = create_engine(get_database_uri())
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))

