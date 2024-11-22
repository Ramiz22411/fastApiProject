from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, status
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse

from .service import UserService
from src.email import mail, create_message
from .utils import create_access_token, verify_passwd, decode_url_save_token, url_save_token, generate_passwd_hash
from .dependencies import RefreshTokenBearer, AccessTokenBearer, get_current_user, RoleChecker
from .schemas import UserCreateModel, UserLoginModel, UserBooksModel, EmailModel, PasswordResetModel, \
    PasswordRequestModel

from sqlmodel.ext.asyncio.session import AsyncSession

from src.db.main import get_session
from src.db.redis import add_jti_to_blocklist
from src.config import Config

from src.error import (
    UserAlreadyExists,
    InvalidCredentials,
    InvalidToken,
    UserNotFound,
)

auth_router = APIRouter()
user_service = UserService()
role_checker = RoleChecker(["admin", "user"])
REFRESH_TOKEN_EXPIRY = 2


# Bearer = Token

@auth_router.post("/send_email")
async def send_email(emails: EmailModel):
    emails = emails.addresses

    html = "<h1>Welcome to the app</h1>"

    message = create_message(
        recipients=emails,
        subjects="welcome",
        body=html,
    )

    await mail.send_message(message)

    return {"message": "Email sent!"}


@auth_router.post("/signup", status_code=status.HTTP_201_CREATED)
async def create_user(user_data: UserCreateModel, session: AsyncSession = Depends(get_session)):
    email = user_data.email
    user_exists = await user_service.user_exists(email, session)

    if user_exists:
        raise UserAlreadyExists()

    new_user = await user_service.create_user(user_data, session)

    token = url_save_token({"email": email})

    link = f"http://{Config.DOMAIN}/api/v1/auth/verify/{token}"
    html = f"""
        <h1>Verify your email</h1>
        <p>Please click this <a href="{link}">link</a> to verify your email</p>
    """
    message = create_message(
        recipients=[email],
        subjects="Verify your email",
        body=html,
    )
    await mail.send_message(message)
    return {"message": "Account created! Check your email to verify your account",
            "user": new_user}


@auth_router.get("/verify/{token}")
async def verifi_account(token: str, session: AsyncSession = Depends(get_session)):
    token_date = decode_url_save_token(token)

    user_email = token_date.get("email")

    if user_email:
        user = await user_service.get_user_by_email(user_email, session)

        if not user:
            raise UserNotFound()
        await user_service.update_user(user, {"is_verified": True}, session)

        return JSONResponse(content={"message": "Account verified!"}, status_code=status.HTTP_200_OK)
    return JSONResponse(content={"message": "ERROR occurred during verification"},
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


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


@auth_router.post("/password-reset")
async def password_reset(email_data: PasswordRequestModel):
    email = email_data.email

    token = url_save_token({"email": email})

    link = f"http://{Config.DOMAIN}/api/v1/auth/verify-reset-password/{token}"

    html = f"""
        <h1>Reset your password</h1>
        <p>Please click<a href="{link}">link</a>to reset your password</p>
    """

    subject = "Reset Password"

    message = create_message(
        recipients=[email],
        subjects=subject,
        body=html,
    )

    await mail.send_message(message)

    return JSONResponse(content={"message": "Check your email to reset your password"},
                        status_code=status.HTTP_200_OK)


@auth_router.post("/verify-reset-password/{token}")
async def verify_resset_password(token: str, passwords: PasswordResetModel,
                                 session: AsyncSession = Depends(get_session)):
    new_password = passwords.new_password
    confirm_new_password = passwords.confirm_password

    if new_password != confirm_new_password:
        raise HTTPException(detail="Password do not match", status_code=status.HTTP_400_BAD_REQUEST)

    token_data = decode_url_save_token(token)
    user_email = token_data.get("email")

    if user_email:
        user = await user_service.get_user_by_email(user_email, session)

        if not user:
            raise UserNotFound()

        password_hash = generate_passwd_hash(new_password)
        await user_service.update_user(user, {"password_hash": password_hash}, session)

        return JSONResponse(
            content={"message": "Password updated!"}, status_code=status.HTTP_200_OK
        )

    return JSONResponse(
        content={"message": "ERROR occurred during password reset"},
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
    )
