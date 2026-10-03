import pytest
import pytest_asyncio
import httpx

from sqlmodel import SQLModel, Session, create_engine
from sqlalchemy.pool import StaticPool

from models.appointments import Appointment
from models.users import User

from database.connection import get_session

from main import app


test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={
        "check_same_thread": False
    },
    poolclass=StaticPool
)


SQLModel.metadata.create_all(
    test_engine
)


def override_get_session():
    with Session(test_engine) as session:
        yield session


app.dependency_overrides[get_session] = override_get_session


@pytest_asyncio.fixture
async def default_client():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        yield client