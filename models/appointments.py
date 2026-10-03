from typing import Optional
from datetime import datetime

from pydantic import BaseModel, ConfigDict
from sqlmodel import SQLModel, Field


class Appointment(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    patient_id: int
    professional_id: int
    date_time: datetime
    status: str = Field(default="agendada")
    notes: Optional[str] = None
    audit_token: str = Field(default="interno")


class AppointmentCreate(SQLModel):
    model_config = ConfigDict(extra="forbid")

    patient_id: int
    professional_id: int
    date_time: datetime
    notes: Optional[str] = None


class AppointmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    patient_id: int
    professional_id: int
    date_time: datetime
    status: str
    notes: Optional[str] = None