from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.templating import Jinja2Templates

from sqlmodel import Session, select

from typing import List

from database.connection import get_session

from models.appointments import (
    Appointment,
    AppointmentCreate,
    AppointmentResponse
)

from models.users import User

from security.auth import (
    get_current_user_mfa,
    profissional_required
)


appointment_router = APIRouter(tags=["Appointments"])


templates = Jinja2Templates(
    directory="templates"
)

def get_appointment_statement(
    current_user: User,
    appointment_id: int | None = None
):
    if current_user.role == "admin":
        statement = select(Appointment)

    elif current_user.role == "profissional":
        statement = select(Appointment).where(
            Appointment.professional_id == current_user.id
        )

    else:
        raise HTTPException(
            status_code=403,
            detail="Acesso negado"
        )

    if appointment_id is not None:
        statement = statement.where(
            Appointment.id == appointment_id
        )

    return statement


@appointment_router.post(
    "/new",
    response_model=AppointmentResponse
)
async def create_appointment(
    data: AppointmentCreate,
    current_user: User = Depends(profissional_required),
    session: Session = Depends(get_session)
):
    if data.professional_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Profissional só pode criar suas próprias consultas"
        )

    new_appointment = Appointment(
        **data.model_dump()
    )

    session.add(new_appointment)
    session.commit()
    session.refresh(new_appointment)

    return new_appointment


@appointment_router.get(
    "/",
    response_model=List[AppointmentResponse]
)
async def list_appointments(
    current_user: User = Depends(get_current_user_mfa),
    session: Session = Depends(get_session)
):
    statement = get_appointment_statement(
        current_user
    )

    appointments = session.exec(
        statement
    ).all()

    return appointments


@appointment_router.get("/html")
async def appointments_html(
    request: Request,
    current_user: User = Depends(get_current_user_mfa),
    session: Session = Depends(get_session)
):
    statement = get_appointment_statement(
        current_user
    )

    appointments = session.exec(
        statement
    ).all()

    return templates.TemplateResponse(
        request=request,
        name="appointments.html",
        context={
            "appointments": appointments
        }
    )


@appointment_router.get(
    "/{appointment_id}",
    response_model=AppointmentResponse
)
async def get_appointment(
    appointment_id: int,
    current_user: User = Depends(get_current_user_mfa),
    session: Session = Depends(get_session)
):
    statement = get_appointment_statement(
        current_user,
        appointment_id
    )

    appointment = session.exec(
        statement
    ).first()

    if appointment is None:
        raise HTTPException(
            status_code=404,
            detail="Consulta não encontrada"
        )

    return appointment