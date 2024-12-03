from fastapi import APIRouter, status, Depends
from typing import List

from sqlmodel.ext.asyncio.session import AsyncSession

from .schemas import BookUpdate, CreateBookModel, Book, BookDetails
from src.db.main import get_session
from src.books.service import BookService
from src.auth.dependencies import AccessTokenBearer, RoleChecker
from src.error import BookNotFound, InsufficientPermissions

book_router = APIRouter()
book_service = BookService()
access_token_bearer = AccessTokenBearer()
role_checker = RoleChecker(["user", "admin"])


@book_router.get("/", response_model=List[Book], dependencies=[Depends(role_checker)])
async def get_all_books(session: AsyncSession = Depends(get_session),
                        token_details: dict=Depends(access_token_bearer)):
    """Get All Books"""
    books = await book_service.get_all_books(session)
    return books

@book_router.get("/user/{user_uid}", response_model=List[Book], dependencies=[Depends(role_checker)])
async def get_user_book_submission(user_uid:str, session: AsyncSession = Depends(get_session),
                                   token_details: dict=Depends(access_token_bearer)):
    books = await book_service.get_user_books(user_uid, session)
    return books

@book_router.post("/", status_code=status.HTTP_201_CREATED, response_model=Book,
                  dependencies=[Depends(role_checker)])
async def creat_book(book_data: CreateBookModel,
                     session: AsyncSession = Depends(get_session), token_details: dict=Depends(access_token_bearer)) -> dict:
    user_uid = token_details.get("user")["user_uid"]
    new_book = await book_service.create_book(book_data, user_uid, session)

    return new_book


@book_router.get("/{book_uid}", response_model=BookDetails, dependencies=[Depends(role_checker)])
async def get_detail(book_uid: str, session: AsyncSession = Depends(get_session),
                     token_details: dict=Depends(access_token_bearer)) -> dict:
    book = await book_service.get_book(book_uid, session)
    if book:
        return book
    else:
        raise BookNotFound()


@book_router.delete("/{book_uid}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(role_checker)])
async def delete_book(book_uid: str, session: AsyncSession = Depends(get_session),
                      token_details: dict=Depends(access_token_bearer)):
    book_to_delete = await book_service.delete_book(book_uid, session)
    if book_to_delete:
        raise BookNotFound()
    else:
        return {}


@book_router.patch("/{book_uid}", response_model=Book, dependencies=[Depends(role_checker)])
async def update_book(book_uid: str,
                      book_data_update: BookUpdate,
                      session: AsyncSession = Depends(get_session), token_details: dict=Depends(access_token_bearer)) -> dict:
    updated_book = await book_service.update_book(book_uid, book_data_update, session)
    if updated_book is None:
        raise BookNotFound()
    else:
        return updated_book
