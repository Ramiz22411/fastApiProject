from fastapi import FastAPI
from src.books.routes import book_router
from contextlib import asynccontextmanager
from src.db.main import init_db
from src.auth.routers import auth_router


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
    lifespan=lifespan,
)

app.include_router(book_router, prefix=f"/api/{version}/books", tags=["books"])
app.include_router(auth_router, prefix=f"/api/{version}/auth", tags=["auth"])
