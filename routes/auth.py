import logging
import os

from fastapi import APIRouter, Depends, HTTPException, Form
from fastapi.security import OAuth2PasswordRequestForm

from sqlmodel import Session, select

from database.connection import get_session
from models.users import User, UserCreate

from security.password import hash_password

from security.auth import (
    gerar_token,
    get_current_user,
    admin_mfa_required,
    MFA_CODE
)
from fastapi import APIRouter, Depends, HTTPException, Form, Request
from security.rate_limit import limiter


logger = logging.getLogger("api-agendamento.security")


auth_router = APIRouter(tags=["Authentication"])

@auth_router.post("/token")
@limiter.limit("5/minute")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session)
):
    user = session.exec(
        select(User).where(
            User.username == form_data.username
        )
    ).first()

    if user is None:
        logger.warning(
            "Falha de login para usuário informado"
        )
        raise HTTPException(
            status_code=401,
            detail="Usuário ou senha inválidos"
        )

    if not hash_password.verify_password(
        form_data.password,
        user.password
    ):
        logger.warning(
            "Falha de login para usuário informado"
        )
        raise HTTPException(
            status_code=401,
            detail="Usuário ou senha inválidos"
        )

    mfa_verified = not user.mfa_enabled

    token = gerar_token(
        user.username,
        user.role,
        mfa_verified
    )

    return {
        "access_token": token,
        "token_type": "Bearer"
    }


@auth_router.post("/token-m2m")
async def token_m2m(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    scope: str = Form(...)
):
    lab_client_id = os.getenv("LAB_CLIENT_ID")
    lab_client_secret = os.getenv("LAB_CLIENT_SECRET")

    if not lab_client_id or not lab_client_secret:
        raise RuntimeError(
            "Credenciais do laboratório não configuradas"
        )

    if grant_type != "client_credentials":
        logger.warning(
            "grant_type inválido no acesso M2M"
        )
        raise HTTPException(
            status_code=400,
            detail="grant_type inválido"
        )

    if client_id != lab_client_id:
        logger.warning(
            "Cliente M2M inválido"
        )
        raise HTTPException(
            status_code=401,
            detail="Cliente inválido"
        )

    if client_secret != lab_client_secret:
        logger.warning(
            "Credencial M2M inválida"
        )
        raise HTTPException(
            status_code=401,
            detail="Cliente inválido"
        )

    if scope != "laboratory:availability":
        logger.warning(
            "Escopo M2M inválido"
        )
        raise HTTPException(
            status_code=400,
            detail="Escopo inválido"
        )

    token = gerar_token(
        client_id,
        "laboratorio",
        None,
        "laboratory:availability",
        client_id
    )

    return {
        "access_token": token,
        "token_type": "Bearer",
        "scope": "laboratory:availability"
    }


@auth_router.post("/signup")
async def signup(
    data: UserCreate,
    session: Session = Depends(get_session)
):
    new_user = User(
        username=data.username,
        password=hash_password.create_hash(data.password),
        role=data.role,
        mfa_enabled=data.mfa_enabled
    )

    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    return {
        "message": "Usuário criado com sucesso",
        "username": new_user.username,
        "role": new_user.role
    }


@auth_router.post("/mfa/verify")
async def verify_mfa(
    mfa_code: str,
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Acesso negado"
        )

    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=403,
            detail="MFA não habilitado"
        )

    if mfa_code != MFA_CODE:
        logger.warning(
            "Falha de MFA"
        )
        raise HTTPException(
            status_code=401,
            detail="Código MFA inválido"
        )

    token = gerar_token(
        current_user.username,
        current_user.role,
        True
    )

    return {
        "access_token": token,
        "token_type": "Bearer"
    }


@auth_router.get("/admin")
async def admin_area(
    current_user: User = Depends(admin_mfa_required)
):
    return {
        "message": "Área administrativa",
        "username": current_user.username
    }