from fastapi import APIRouter, Depends
from src.db.main import get_session
from sqlmodel.ext.asyncio.session import AsyncSession
from .schemas import ReviewCreateModel
from .service import ReviewService

from src.db.models import User
from src.auth.dependencies import get_current_user

review_router = APIRouter()
review_service = ReviewService()


@review_router.post("/book/{book_uid}")
async def create_review(book_uid: str,
                        review_data: ReviewCreateModel,
                        current_user: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    new_review = await review_service.add_new_review(user_email=current_user.email,
                                                     review_data=review_data,
                                                     book_uid=book_uid,
                                                     session=session)
    return new_review
