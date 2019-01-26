from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import User, Category, Item, Base

# connect to the database
engine = create_engine('sqlite:///catagories.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

catagories = ("Soccer", "Basketball", "Baseball", "Frisbee",
              "Snowboarding", "Rock Climbing", "Foosball", "Skating", "Hockey")

# add catagories to the database
for category in catagories:
    c = Category(name=category)
    session.add(c)
    session.commit()

print "added catagories"