from sqlmodel import SQLModel, Session, create_engine
from database.settings import settings


engine = create_engine(settings.database_url)


def get_session():
    with Session(engine) as session:
        yield session


def conn():
    SQLModel.metadata.create_all(engine)