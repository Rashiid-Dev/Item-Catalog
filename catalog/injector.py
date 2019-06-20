from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, CatItem, User

engine = create_engine('sqlite:///catalog_database.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()

# Categories + User

user1 = User(name='Abdirashiid Jama', email='rashiid.py@gmail.com',
             picture='https://lh6.googleusercontent.com/-sVcI-LPVb-0/AAAAAAAAAAI/AAAAAAAAAAc/JfhLrXf4Po4/s96-c/photo.jpg')

session.add(user1)
session.commit()


category1 = Category(name='Football', user=user1)

session.add(category1)
session.commit()

catItem1 = CatItem(name="Ball", description="Beautiful Champions League ball",
                   category=category1, user=user1)

session.add(catItem1)
session.commit()

catItem2 = CatItem(name="Shirt", description="Ajax Number 13 Shirt",
                   category=category1, user=user1)

session.add(catItem2)
session.commit()

catItem3 = CatItem(name="Shoes", description="Nike Football Shoes",
                   category=category1, user=user1)

session.add(catItem3)
session.commit()

category2 = Category(name='Basketball', user=user1)

session.add(category2)
session.commit()

catItem1 = CatItem(name="Jersey",
                   description="A original Chicago Bulls jersey",
                   category=category2, user=user1)

session.add(catItem1)
session.commit()

catItem2 = CatItem(name="Shoes", description="Adidas Basketball Shoes",
                   category=category2, user=user1)

session.add(catItem2)
session.commit()

catItem3 = CatItem(name="Shorts", description="Chicago Bulls Original Shorts",
                   category=category2, user=user1)

session.add(catItem3)
session.commit()

category3 = Category(name='Snowboarding', user=user1)

session.add(category1)
session.commit()

catItem1 = CatItem(name="Goggles", description="Stylish non-fog goggles",
                   category=category3, user=user1)

session.add(catItem1)
session.commit()

catItem2 = CatItem(name="Snowboard",
                   description="Snowboard with custom design",
                   category=category3, user=user1)

session.add(catItem2)
session.commit(),

catItem3 = CatItem(name="Socks",
                   description="Quality socks to keep the cold away",
                   category=category3, user=user1)

session.add(catItem3)
session.commit()


print "Datbase has been filled!"
