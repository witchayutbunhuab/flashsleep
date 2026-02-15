from database import Base, engine
import models

# Create tables
Base.metadata.create_all(bind=engine)
