import logging
import os

from datetime import datetime, timedelta, timezone

import jwt
from jwt.exceptions import InvalidTokenError

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

from sqlmodel import Session, select

from database.connection import get_session
from models.users import User
from database.settings import settings


logger = logging.getLogger("api-agendamento.security")


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

SECRET_KEY = settings.secret_key
ALGORITHM = "HS256"

MFA_CODE = "123456"


def gerar_token(
    username: str,
    role: str,
    mfa_verified: bool | None = True,
    scope: str = "",
    client_id: str | None = None
):
    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY não configurada")

    expiracao = datetime.now(timezone.utc) + timedelta(minutes=30)

    dados = {
        "sub": username,
        "role": role,
        "exp": expiracao
    }

    if mfa_verified is not None:
        dados["mfa_verified"] = mfa_verified

    if scope:
        dados["scope"] = scope

    if client_id:
        dados["client_id"] = client_id

    token = jwt.encode(
        dados,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return token


def validar_token_jwt(
    token: str = Depends(oauth2_scheme)
):
    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY não configurada")

    erro = HTTPException(
        status_code=401,
        detail="Token inválido ou expirado",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username = payload.get("sub")

        if username is None:
            logger.warning("Token JWT sem usuário")
            raise erro

        return payload

    except InvalidTokenError:
        logger.warning("Token JWT inválido ou expirado")
        raise erro


def get_current_user(
    payload: dict = Depends(validar_token_jwt),
    session: Session = Depends(get_session)
):
    username = payload.get("sub")

    user = session.exec(
        select(User).where(User.username == username)
    ).first()

    if user is None:
        logger.warning("Usuário do token não encontrado")
        raise HTTPException(
            status_code=401,
            detail="Usuário não encontrado"
        )

    return user


def get_current_user_mfa(
    current_user: User = Depends(get_current_user),
    payload: dict = Depends(validar_token_jwt)
):
    if (
        current_user.role == "admin"
        and current_user.mfa_enabled
        and not payload.get("mfa_verified", False)
    ):
        logger.warning(
            "Administrador tentou acessar recurso sem MFA"
        )
        raise HTTPException(
            status_code=403,
            detail="MFA necessário"
        )

    return current_user


class RoleChecker:
    def __init__(self, allowed_roles):
        self.allowed_roles = allowed_roles

    def __call__(
        self,
        current_user: User = Depends(get_current_user_mfa)
    ):
        if current_user.role not in self.allowed_roles:
            logger.warning(
                "Acesso negado por papel de usuário"
            )
            raise HTTPException(
                status_code=403,
                detail="Acesso negado"
            )

        return current_user


admin_required = RoleChecker(["admin"])

profissional_required = RoleChecker(["profissional"])


def admin_mfa_required(
    current_user: User = Depends(get_current_user_mfa)
):
    if current_user.role != "admin":
        logger.warning(
            "Usuário não administrador tentou acessar área admin"
        )
        raise HTTPException(
            status_code=403,
            detail="Acesso negado"
        )

    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=403,
            detail="MFA não habilitado para administrador"
        )

    return current_user


def laboratory_required(
    payload: dict = Depends(validar_token_jwt)
):
    if payload.get("role") != "laboratorio":
        logger.warning(
            "Acesso negado ao laboratório"
        )
        raise HTTPException(
            status_code=403,
            detail="Acesso negado"
        )

    scopes = payload.get("scope", "").split()

    if "laboratory:availability" not in scopes:
        logger.warning(
            "Escopo insuficiente para laboratório"
        )
        raise HTTPException(
            status_code=403,
            detail="Escopo insuficiente"
        )

    return payload