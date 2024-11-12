from fastapi import APIRouter, Depends, status
from fastapi.exceptions import HTTPException
from src.db.main import get_session
from sqlmodel.ext.asyncio.session import AsyncSession
from .schemas import ReviewCreateModel
from .service import ReviewService

from src.db.models import User
from src.auth.dependencies import RoleChecker, get_current_user
from src.error import BookNotFound

review_router = APIRouter()
review_service = ReviewService()
admin_checker = RoleChecker(["admin"])
user_checker = RoleChecker(["user", "admin"])


@review_router.get("/", dependencies=[Depends(admin_checker)])
async def get_all_reviews(session: AsyncSession = Depends(get_session)):
    books = await review_service.get_all_reviews(session)

    return books


@review_router.get("/{review_uid}", dependencies=[Depends(user_checker)])
async def get_review(review_uid: str, session: AsyncSession = Depends(get_session)):
    book = await review_service.get_review(review_uid, session)

    if book:
        return book
    else:
        raise BookNotFound()


@review_router.post("/book/{book_uid}", dependencies=[Depends(user_checker)])
async def create_review(book_uid: str,
                        review_data: ReviewCreateModel,
                        current_user: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    new_review = await review_service.add_new_review(user_email=current_user.email,
                                                     review_data=review_data,
                                                     book_uid=book_uid,
                                                     session=session)
    return new_review


@review_router.delete("/{review_uid}", dependencies=[Depends(user_checker)],
                      status_code=status.HTTP_204_NO_CONTENT)
async def delete_review(review_uid: str, current_user: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    await review_service.delete_review(review_uid=review_uid, email_user=current_user.email, session=session)

    return None
