"""Autenticación de la API de soporte: tokens de sesión emitidos por el servicio de cuentas."""
from dataclasses import dataclass

from fastapi import Header, HTTPException

# En producción viene del servicio de cuentas; aquí, una tabla en memoria para el piloto.
SESSIONS = {
    "tok-alice": {"user_id": "u-1", "tenant_id": "acme", "role": "customer"},
    "tok-bob": {"user_id": "u-2", "tenant_id": "globex", "role": "customer"},
    "tok-agent": {"user_id": "u-9", "tenant_id": "acme", "role": "support_agent"},
}


@dataclass
class User:
    user_id: str
    tenant_id: str
    role: str


def current_user(authorization: str = Header(default="")) -> User:
    token = authorization.removeprefix("Bearer ").strip()
    session = SESSIONS.get(token)
    if not session:
        raise HTTPException(status_code=401, detail="no autenticado")
    return User(**session)
