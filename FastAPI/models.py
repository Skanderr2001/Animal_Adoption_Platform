from sqlalchemy import Column, Integer, String, Boolean
from database import Base

class Animal(Base):
    __tablename__ = 'animals'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    species = Column(String)
    age = Column(Integer)
    color= Column(String)
    is_adopted= Column(Boolean)









