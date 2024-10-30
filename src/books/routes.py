from fastapi import APIRouter, status, Depends
from typing import List

from sqlmodel.ext.asyncio.session import AsyncSession

from .schemas import BookUpdate, CreateBookModel, Book
from fastapi.exceptions import HTTPException
from src.db.main import get_session
from src.books.service import BookService
from src.auth.dependencies import AccessTokenBearer

book_router = APIRouter()
book_service = BookService()
access_token_bearer = AccessTokenBearer()


@book_router.get("/", response_model=List[Book])
async def get_all_books(session: AsyncSession = Depends(get_session), user_details=Depends(access_token_bearer)):
    books = await book_service.get_all_books(session)
    return books


@book_router.post("/", status_code=status.HTTP_201_CREATED, response_model=Book)
async def creat_book(book_data: CreateBookModel,
                     session: AsyncSession = Depends(get_session), user_details=Depends(access_token_bearer)) -> dict:
    new_book = await book_service.create_book(book_data, session)

    return new_book


@book_router.get("/{book_uid}", response_model=Book)
async def get_detail(book_uid: str, session: AsyncSession = Depends(get_session),
                     user_details=Depends(access_token_bearer)) -> dict:
    book = await book_service.get_book(book_uid, session)
    if book:
        return book
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Book not found")


@book_router.delete("/{book_uid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_book(book_uid: str, session: AsyncSession = Depends(get_session),
                      user_details=Depends(access_token_bearer)):
    book_to_delete = await book_service.delete_book(book_uid, session)
    if book_to_delete:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Book not found")
    else:
        return {}


@book_router.patch("/{book_uid}", response_model=Book)
async def update_book(book_uid: str,
                      book_data_update: BookUpdate,
                      session: AsyncSession = Depends(get_session), user_details=Depends(access_token_bearer)) -> dict:
    updated_book = await book_service.update_book(book_uid, book_data_update, session)
    if updated_book is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Book not found")
    else:
        return updated_book