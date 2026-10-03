from fastapi import APIRouter, Depends

from security.auth import laboratory_required


laboratory_router = APIRouter(
    prefix="/laboratory",
    tags=["Laboratory"]
)


@laboratory_router.get("/availability")
async def laboratory_availability(
    payload: dict = Depends(laboratory_required)
):
    return {
        "message": "Acesso autorizado ao laboratório",
        "client_id": payload.get("client_id"),
        "scope": payload.get("scope")
    }