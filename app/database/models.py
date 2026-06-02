# from sqlalchemy import Column
# from sqlalchemy import String
# from sqlalchemy import Integer
# from sqlalchemy import Text




# class FindingDB(Base):
#     __tablename__ = "findings"

#     id = Column(String, primary_key=True)

#     finding_hash = Column(String)

#     tool = Column(String)
#     type = Column(String)

#     title = Column(String)

#     severity = Column(String)

#     file = Column(String)

#     line = Column(Integer)

#     description = Column(Text)

#     status = Column(String)

#     created_at = Column(String)



from sqlalchemy import Column
from sqlalchemy import String
from sqlalchemy import Integer
from sqlalchemy import Text

from app.database.connection import Base


class FindingDB(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True)

    finding_hash = Column(String)

    tool = Column(String)
    type = Column(String)

    title = Column(String)

    severity = Column(String)

    file = Column(String)

    line = Column(Integer)

    description = Column(Text)

    status = Column(String)

    created_at = Column(String)

    occurrence_count = Column(Integer, default=1)

    last_seen = Column(String)