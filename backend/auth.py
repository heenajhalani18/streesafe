import os
from datetime import datetime, timedelta

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Header
from sqlalchemy.orm import Session

from database import get_db, User, Responder

SECRET_KEY = os.environ.get("STREESAFE_SECRET", "dev-secret-change-in-production")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24 * 7  # 1 week


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def create_token(subject_id: int, role: str = "user") -> str:
    payload = {
        "sub": str(subject_id),
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # Default to "user" for tokens issued before roles existed (backward compatible).
        return {"id": int(payload["sub"]), "role": payload.get("role", "user")}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired, please log in again")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")


def get_current_user(
    authorization: str = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    claims = decode_token(authorization.split(" ", 1)[1])
    if claims["role"] != "user":
        raise HTTPException(status_code=403, detail="This action requires a requester account, not a responder account")
    user = db.query(User).get(claims["id"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def get_current_responder(
    authorization: str = Header(default=None),
    db: Session = Depends(get_db),
) -> Responder:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    claims = decode_token(authorization.split(" ", 1)[1])
    if claims["role"] != "responder":
        raise HTTPException(status_code=403, detail="This action requires a responder account")
    responder = db.query(Responder).get(claims["id"])
    if not responder:
        raise HTTPException(status_code=401, detail="Responder not found")
    return responder
