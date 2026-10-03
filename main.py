from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from database.connection import conn
from routes.appointments import appointment_router
from routes.auth import auth_router
from routes.laboratory import laboratory_router
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from security.rate_limit import limiter

app = FastAPI(title="API de Agendamento Clínico")

app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler
)

origens_permitidas = [
    "https://meu-frontend-confiavel.com",
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origens_permitidas,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"]
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"

    return response

app.include_router(appointment_router, prefix="/appointment")
app.include_router(auth_router)
app.include_router(laboratory_router)

@app.on_event("startup")
def on_startup():
    conn()

@app.get("/")
async def home():
    return {"message": "Bem-vindo à API de Agendamento Clínico!"}