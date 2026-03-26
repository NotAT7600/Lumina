"""Lumina - Agentic Penetration Testing System - FastAPI backend."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routers.scan_router import router as scan_router

app = FastAPI(title="Lumina Pentest API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://frontend:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/hello")
def hello():
    """Health check — kept for backwards compatibility."""
    return {"message": "Lumina Pentest API is running"}


app.include_router(scan_router)

