import uuid
from pydantic import BaseModel
from datetime import datetime, date


class Book(BaseModel):
    uid: uuid.UUID
    title: str
    author: str
    publisher: str
    publisher_date: date
    pages_count: int
    language: str
    created_at: datetime
    updated_at: datetime

class CreateBookModel(BaseModel):
    title: str
    author: str
    publisher: str
    publisher_date: str
    pages_count: int
    language: str


class BookUpdate(BaseModel):
    title: str
    author: str
    publisher: str
    pages_count: int
    language: str
