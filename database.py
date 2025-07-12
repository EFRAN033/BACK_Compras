# database.py

import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

# El motor de SQLAlchemy para la conexión
engine = create_engine(DATABASE_URL)

# Una fábrica de sesiones para interactuar con la BD
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Una clase base de la cual heredarán todos nuestros modelos ORM
Base = declarative_base()