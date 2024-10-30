import jwt
import uuid
import logging
from datetime import datetime, timedelta
from passlib.context import CryptContext
from src.config import Config

passwd_context = CryptContext(
    schemes=["bcrypt"],
)

ACCESS_TOKEN_EXPIRY = 3600


def generate_passwd_hash(password: str) -> str:
    hash_p = passwd_context.hash(password)

    return hash_p


def verify_passwd(password: str, hash_passwd: str) -> bool:
    return passwd_context.verify(password, hash_passwd)


def create_access_token(data: dict, expiry: timedelta = None, refresh: bool = False):
    payload = {}
    payload["user"] = data
    payload["exp"] = datetime.now() + (expiry if expiry is not None else timedelta(seconds=ACCESS_TOKEN_EXPIRY))
    payload["jti"] = str(uuid.uuid4())
    payload["refresh"] = refresh

    token = jwt.encode(
        payload=payload,
        key=Config.JWT_SECRET_KEY,
        algorithm=Config.JWT_ALGORITHM,
    )

    return token


def decode_token(token: str) -> dict:
    try:
        token_data = jwt.decode(
            jwt=token,
            key=Config.JWT_SECRET_KEY,
            algorithms=[Config.JWT_ALGORITHM]
        )
        return token_data
    except jwt.PyJWTError as e:
        logging.exception(e)
        return None
