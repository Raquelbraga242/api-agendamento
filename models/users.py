import re
from typing import Optional, Literal

from pydantic import ConfigDict, field_validator
from sqlmodel import SQLModel, Field


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str
    password: str
    role: str
    mfa_enabled: bool = False


class UserCreate(SQLModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(
        min_length=3,
        max_length=30
    )

    password: str

    role: Literal[
        "profissional",
        "recepcionista"
    ]

    mfa_enabled: bool = False

    @field_validator("username")
    @classmethod
    def validar_username(cls, value):
        if not re.fullmatch(r"[A-Za-z0-9_]+", value):
            raise ValueError(
                "Username deve conter apenas letras, números e _"
            )

        return value