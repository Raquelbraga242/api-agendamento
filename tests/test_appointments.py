import pytest
import httpx

from sqlmodel import Session

from tests.conftest import test_engine

from models.users import User

from security.password import hash_password


@pytest.mark.asyncio
async def test_list_appointments(
    default_client: httpx.AsyncClient
):
    with Session(test_engine) as session:
        user = User(
            username="teste_lista",
            password=hash_password.create_hash("123456"),
            role="profissional"
        )

        session.add(user)
        session.commit()

    login = await default_client.post(
        "/token",
        data={
            "username": "teste_lista",
            "password": "123456"
        }
    )

    assert login.status_code == 200

    token = login.json()["access_token"]

    response = await default_client.get(
        "/appointment/",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 200