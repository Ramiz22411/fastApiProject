from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse

from .service import UserService
from .utils import create_access_token, verify_passwd
from .dependencies import RefreshTokenBearer, AccessTokenBearer, get_current_user, RoleChecker
from .schemas import UserCreateModel, UserModel, UserLoginModel, UserBooksModel

from sqlmodel.ext.asyncio.session import AsyncSession

from src.db.main import get_session
from src.db.redis import add_jti_to_blocklist

from src.error import (
    UserAlreadyExists,
    InvalidCredentials,
    InvalidToken
)

auth_router = APIRouter()
user_service = UserService()
role_checker = RoleChecker(["admin", "user"])
REFRESH_TOKEN_EXPIRY = 2


# Bearer = Token

@auth_router.post("/signup", status_code=status.HTTP_201_CREATED, response_model=UserModel)
async def create_user(user_data: UserCreateModel, session: AsyncSession = Depends(get_session)):
    email = user_data.email
    user_exists = await user_service.user_exists(email, session)

    if user_exists:
        raise UserAlreadyExists()

    new_user = await user_service.create_user(user_data, session)

    return new_user


@auth_router.post("/login", status_code=status.HTTP_200_OK)
async def login_user(login_data: UserLoginModel, session: AsyncSession = Depends(get_session)):
    email = login_data.email
    password = login_data.password

    user = await user_service.get_user_by_email(email, session)

    if user is not None:
        password_valid = verify_passwd(password, user.password_hash)

        if password_valid:
            access_token = create_access_token(
                data={
                    'email': user.email,
                    'user_uid': str(user.uid),
                    "role": user.role
                }
            )

            refresh_token = create_access_token(
                data={
                    'email': user.email,
                    'user_uid': str(user.uid)
                },
                refresh=True,
                expiry=timedelta(days=REFRESH_TOKEN_EXPIRY)
            )

            return JSONResponse(
                content={
                    "message": "Login successful",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": {
                        "email": user.email,
                        "uid": str(user.uid),
                    }
                }
            )
    raise InvalidCredentials()


@auth_router.get("/refresh_token")
async def get_new_access_token(token_details: dict = Depends(RefreshTokenBearer())):
    expiry_timestamp = token_details['exp']

    if datetime.fromtimestamp(expiry_timestamp) > datetime.now():
        new_access_token = create_access_token(
            data=token_details["user"]
        )
        return JSONResponse(content={
            "access_token": new_access_token,
        })
    raise InvalidToken()


@auth_router.get("/me", response_model=UserBooksModel)
async def get_curr_user(user=Depends(get_current_user), _: bool = Depends(role_checker)):
    return user


@auth_router.post("/logout")
async def revoke_token(token_details: dict = Depends(AccessTokenBearer())):
    jti = token_details['jti']

    await add_jti_to_blocklist(jti)

    return JSONResponse(
        content={"message": "Logout successful"},
        status_code=status.HTTP_200_OK)
