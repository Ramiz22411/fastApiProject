from fastapi import FastAPI
from src.books.routes import book_router
from contextlib import asynccontextmanager
from src.db.main import init_db
from src.auth.routers import auth_router
from src.reviews.routes import review_router
from src.tags.routes import tags_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f'server is starting ....')
    await init_db()
    yield
    print(f'server has been stopped')


version = "v1"
app = FastAPI(
    title="bookly",
    description="A REST AOI for book review web service",
    version=version,
)

app.include_router(book_router, prefix=f"/api/{version}/books", tags=["books"])
app.include_router(auth_router, prefix=f"/api/{version}/auth", tags=["auth"])
app.include_router(review_router, prefix=f"/api/{version}/review", tags=["review"])
app.include_router(tags_router, prefix=f"/api/{version}/tags", tags=["tags"])
