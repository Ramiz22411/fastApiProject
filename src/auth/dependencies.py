from fastapi.security import HTTPBearer
from fastapi.security.http import HTTPAuthorizationCredentials
from .utils import decode_token
from fastapi import Request, status
from fastapi.exceptions import HTTPException
from src.db.redis import token_in_blocklist


class TokenBearer(HTTPBearer):
    def __init__(self, auto_error=True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request) -> HTTPAuthorizationCredentials | None:
        creds = await super().__call__(request)
        token = creds.credentials

        token_data = decode_token(token)

        if not self.token_valid(token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Invalid token or expired",
                    "resolution": "Please login again"
                }
            )

        if await token_in_blocklist(token_data["jti"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Token has been revoked",
                    "resolution": "Please login again"
                }
            )

        self.verifi_token_data(token_data)

        return token_data

    def token_valid(self, token: str) -> bool:
        token_data = decode_token(token)

        return token_data is not None

    def verifi_token_data(self, token_data):
        raise NotImplementedError("Please override this method in child classes")


class AccessTokenBearer(TokenBearer):

    def verifi_token_data(self, token_data: dict) -> None:
        if token_data and token_data["refresh"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Provide an access token")


class RefreshTokenBearer(TokenBearer):

    def verifi_token_data(self, token_data: dict) -> None:
        if token_data and not token_data["refresh"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Provide a refresh token")
