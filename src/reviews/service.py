import logging
from fastapi import status
from src.db.models import Review
from sqlmodel import select, desc
from .schemas import ReviewCreateModel
from src.auth.service import UserService
from src.books.service import BookService
from fastapi.exceptions import HTTPException
from sqlmodel.ext.asyncio.session import AsyncSession
from src.error import BookNotFound

book_service = BookService()
user_service = UserService()


class ReviewService:

    async def add_new_review(self, user_email: str, book_uid: str, review_data: ReviewCreateModel,
                             session: AsyncSession):
        try:
            book = await book_service.get_book(book_uid=book_uid, session=session)
            user = await user_service.get_user_by_email(email=user_email, session=session)
            review_data_dict = review_data.model_dump()

            if not book:
                raise BookNotFound()
            if not user:
                raise BookNotFound()
            new_review = Review(**review_data_dict, user=user, book=book)

            session.add(new_review)

            await session.commit()

            return new_review
        except Exception as e:
            logging.exception(e)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="Oops ... Somthing went wrong")

    async def get_review(self, review_uid: str, session: AsyncSession):
        statement = select(Review).where(Review.uid == review_uid)

        result = await session.exec(statement)

        return result.first()

    async def get_all_reviews(self, session: AsyncSession):
        statement = select(Review).order_by(desc(Review.created_at))

        result = await session.exec(statement)

        return result.all()

    async def delete_review(self, review_uid: str, email_user: str, session: AsyncSession):
        user = await user_service.get_user_by_email(email_user, session)

        review = await self.get_review(review_uid, session)

        if not review or (review.user != user):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot delete review")

        await session.delete(review)

        await session.commit()
