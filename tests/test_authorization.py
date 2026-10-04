import pytest
import httpx

from datetime import datetime, timezone

from sqlmodel import Session

from tests.conftest import test_engine

from models.users import User
from models.appointments import Appointment

from security.password import hash_password
from unittest.mock import Mock

from main import app
from security.auth import validar_token_jwt


@pytest.mark.asyncio
async def test_professional_cannot_access_other_appointment(
    default_client: httpx.AsyncClient
):
    with Session(test_engine) as session:
        profissional1 = User(
            username="profissional1",
            password=hash_password.create_hash("123456"),
            role="profissional"
        )

        profissional2 = User(
            username="profissional2",
            password=hash_password.create_hash("123456"),
            role="profissional"
        )

        session.add(profissional1)
        session.add(profissional2)
        session.commit()
        session.refresh(profissional1)
        session.refresh(profissional2)

        consulta1 = Appointment(
            patient_id=101,
            professional_id=profissional1.id,
            date_time=datetime(
            2026, 10, 3, 10, 0,
            tzinfo=timezone.utc
            ),
            notes="Consulta do profissional 1"
        )

        consulta2 = Appointment(
            patient_id=202,
            professional_id=profissional2.id,
            date_time=datetime(
            2026, 10, 3, 11, 0,
            tzinfo=timezone.utc
            ),
            notes="Consulta do profissional 2"
        )

        session.add(consulta1)
        session.add(consulta2)
        session.commit()
        session.refresh(consulta1)
        session.refresh(consulta2)

    login = await default_client.post(
        "/token",
        data={
            "username": "profissional1",
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

    appointments = response.json()

    ids = [
        appointment["id"]
        for appointment in appointments
    ]

    assert consulta1.id in ids
    assert consulta2.id not in ids
@pytest.mark.asyncio
async def test_rejects_extra_field_in_appointment(
    default_client: httpx.AsyncClient
):
    with Session(test_engine) as session:
        profissional = User(
            username="profissional_validacao",
            password=hash_password.create_hash("123456"),
            role="profissional"
        )

        session.add(profissional)
        session.commit()
        session.refresh(profissional)

    login = await default_client.post(
        "/token",
        data={
            "username": "profissional_validacao",
            "password": "123456"
        }
    )

    assert login.status_code == 200

    token = login.json()["access_token"]

    response = await default_client.post(
        "/appointment/new",
        headers={
            "Authorization": f"Bearer {token}"
        },
        json={
            "patient_id": 303,
            "professional_id": profissional.id,
            "date_time": "2026-10-4T10:00:00+00:00",
            "notes": "Consulta",
            "audit_token": "tentativa-de-alteracao"
        }
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_html_escapes_malicious_content(
    default_client: httpx.AsyncClient
):
    with Session(test_engine) as session:
        profissional = User(
            username="profissional_html",
            password=hash_password.create_hash("123456"),
            role="profissional"
        )

        session.add(profissional)
        session.commit()
        session.refresh(profissional)

        consulta = Appointment(
            patient_id=404,
            professional_id=profissional.id,
            date_time=datetime(
                2026, 10, 4, 11, 0,
                tzinfo=timezone.utc
            ),
            notes="<script>alert('xss')</script>"
        )

        session.add(consulta)
        session.commit()

    login = await default_client.post(
        "/token",
        data={
            "username": "profissional_html",
            "password": "123456"
        }
    )

    assert login.status_code == 200

    token = login.json()["access_token"]

    response = await default_client.get(
        "/appointment/html",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 200
    assert "<script>" not in response.text
    assert "&lt;script&gt;" in response.text



@pytest.mark.asyncio
async def test_laboratory_authorization_with_mocked_jwt(
    default_client: httpx.AsyncClient
):
    mock_jwt = Mock(
        return_value={
            "role": "laboratorio",
            "scope": "laboratory:availability",
            "client_id": "lab-test"
        }
    )

    def mocked_validar_token_jwt():
        return mock_jwt()

    app.dependency_overrides[validar_token_jwt] = mocked_validar_token_jwt

    try:
        response = await default_client.get(
            "/laboratory/availability"
        )

        assert response.status_code == 200
        assert response.json()["client_id"] == "lab-test"

        mock_jwt.assert_called_once_with()

    finally:
        app.dependency_overrides.pop(
            validar_token_jwt,
            None
        )