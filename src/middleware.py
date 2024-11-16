import time
import logging

from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
logger = logging.getLogger("uvicorn.access")
logger.disabled = True


def register_middleware(app: FastAPI):
    @app.middleware("http")
    async def custom_logging(request: Request, call_next):
        state_time = time.time()

        print("before")
        response = await call_next(request)
        process_time = time.time() - state_time
        message = f'{request.method} - {request.url.path} - complete after {process_time}s'
        print(message)
        return response

    app.add_middleware(
        CORSMiddleware,
        allowed_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=True,
    )

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1:8000", "127.0.0.1:3000"],
    )