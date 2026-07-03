import bcrypt
from fastapi import Depends, HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import settings

SESSION_COOKIE = "wg_admin_session"

_serializer = URLSafeTimedSerializer(settings.secret_key, salt="wg-admin-session")
_password_hash = bcrypt.hashpw(settings.admin_password.encode(), bcrypt.gensalt())


def verify_credentials(username: str, password: str) -> bool:
    if username != settings.admin_username:
        return False
    return bcrypt.checkpw(password.encode(), _password_hash)


def create_session_token() -> str:
    return _serializer.dumps({"user": settings.admin_username})


def validate_session_token(token: str) -> bool:
    try:
        _serializer.loads(token, max_age=settings.session_max_age)
        return True
    except (BadSignature, SignatureExpired):
        return False


def require_login(request: Request) -> None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token or not validate_session_token(token):
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"},
        )


logged_in = Depends(require_login)
