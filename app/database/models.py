# from sqlalchemy import Column
# from sqlalchemy import String
# from sqlalchemy import Integer
# from sqlalchemy import Text

# from app.database.connection import Base


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

#     occurrence_count = Column(Integer, default=1)

#     last_seen = Column(String)


from uuid import uuid4
from sqlalchemy import Column, String, Integer, Text
from app.database.connection import Base


class FindingDB(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))

    tool = Column(String, index=True)
    type = Column(String, index=True)

    title = Column(String)
    severity = Column(String)

    file = Column(String)
    line = Column(Integer, nullable=True)

    description = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)

    finding_hash = Column(String, unique=True, index=True)

    status = Column(String, default="open")

    occurrence_count = Column(Integer, default=1)

    created_at = Column(String)
    last_seen = Column(String)