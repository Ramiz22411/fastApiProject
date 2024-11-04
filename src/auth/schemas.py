import uuid

from src.books.schemas import CreateBookModel, Book
from pydantic import BaseModel, Field
from datetime import datetime
from typing import List

class UserCreateModel(BaseModel):
    first_name: str = Field(max_length=25)
    last_name: str = Field(max_length=25)
    username: str = Field(min_length=8)
    email: str = Field(max_length=50)
    password: str = Field(min_length=6)


class UserModel(BaseModel):
    uid: uuid.UUID
    username: str
    email: str
    first_name: str
    last_name: str
    is_verified: bool
    password_hash: str = Field(exclude=True)
    created_at: datetime
    updated_at: datetime
    books: List["Book"]

class UserLoginModel(BaseModel):
    email: str = Field(max_length=50)
    password: str = Field(min_length=6)
