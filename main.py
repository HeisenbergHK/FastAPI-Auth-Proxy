import time
import uuid
from typing import Dict, Optional

import httpx
from fastapi import Body, Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

# Initialize FastAPI application
app = FastAPI()

# Central authentication service URL
AUTH_URL = "https://auth-central-challange.vercel.app"

# Bearer token security scheme for authentication
security = HTTPBearer()

# Token storage (in production, use Redis or database)
token_storage: Dict[str, Dict] = {}
session_storage: Dict[str, str] = {}  # session_id -> user_id


class User(BaseModel):
    email: str
    password: str


class TokenData(BaseModel):
    access_token: str
    refresh_token: str
    user_id: str


def store_tokens(user_id: str, access_token: str, refresh_token: str):
    """Store tokens with timestamps"""
    current_time = time.time()
    token_storage[user_id] = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "access_expires_at": current_time + 120,  # 2 minutes
        "refresh_expires_at": current_time + 240,  # 4 minutes
    }


def cleanup_expired_sessions():
    """Clean up expired sessions and tokens"""
    expired_users = []

    for user_id, tokens in token_storage.items():
        if is_token_expired(tokens["refresh_expires_at"]):
            expired_users.append(user_id)

    for user_id in expired_users:
        del token_storage[user_id]
        # Remove associated sessions
        expired_sessions = [
            sid for sid, uid in session_storage.items() if uid == user_id
        ]
        for sid in expired_sessions:
            del session_storage[sid]


def is_token_expired(expires_at: float) -> bool:
    """Check if token is expired"""
    return time.time() >= expires_at


async def get_valid_token(user_id: str) -> Optional[str]:
    """Get valid access token, refresh if needed"""
    cleanup_expired_sessions()  # Clean up expired data

    if user_id not in token_storage:
        return None

    tokens = token_storage[user_id]

    # Check if refresh token is expired
    if is_token_expired(tokens["refresh_expires_at"]):
        del token_storage[user_id]
        return None

    # If access token is valid, return it
    if not is_token_expired(tokens["access_expires_at"]):
        return tokens["access_token"]

    # Refresh access token
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{AUTH_URL}/refresh", json={"refresh_token": tokens["refresh_token"]}
        )

    if resp.status_code == 200:
        new_tokens = resp.json()
        store_tokens(user_id, new_tokens["access_token"], new_tokens["refresh_token"])
        return new_tokens["access_token"]

    # Refresh failed, remove tokens
    del token_storage[user_id]
    return None


@app.get("/")
def root():
    """
    Root endpoint for health check and API verification.

    Returns:
        dict: Simple greeting message confirming API is running
    """
    return {"Hello": "World"}


@app.post("/register")
async def register(user: User):
    """
    Register a new user by proxying to the central authentication service.

    Args:
        user (User): User registration data containing email and password

    Returns:
        dict: Response from the central authentication service

    Raises:
        HTTPException: If the central service returns a non-200 status code
    """
    async with httpx.AsyncClient() as client:
        # Forward registration request to central auth service
        resp = await client.post(f"{AUTH_URL}/register", json=user.dict())

    # Handle non-successful responses from central service
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())

    return resp.json()


@app.post("/login")
async def login(
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    grant_type: str = Form("password"),
    scope: str = Form(""),
    client_id: str = Form("string"),
    client_secret: str = Form("string"),
):
    data = {
        "grant_type": grant_type,
        "username": username,
        "password": password,
        "scope": scope,
        "client_id": client_id,
        "client_secret": client_secret,
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{AUTH_URL}/login",
            data=data,
            headers={"accept": "application/json"},
        )

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())

    tokens = resp.json()
    # Store tokens and create session
    store_tokens(username, tokens["access_token"], tokens["refresh_token"])

    session_id = str(uuid.uuid4())
    session_storage[session_id] = username
    response.set_cookie(
        key="session_id", value=session_id, httponly=True, max_age=240
    )  # 4 minutes

    return tokens


@app.post("/refresh")
async def refresh(refresh_token: str = Body(..., embed=True)):
    """
    Refresh access token using a valid refresh token.

    Args:
        refresh_token (str): Valid refresh token obtained during login

    Returns:
        dict: New access and refresh tokens from central service

    Raises:
        HTTPException: If token refresh fails or refresh token is invalid
    """
    async with httpx.AsyncClient() as client:
        # Forward refresh token request to central service
        resp = await client.post(
            f"{AUTH_URL}/refresh", json={"refresh_token": refresh_token}
        )

    # Handle refresh token errors
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())

    return resp.json()


@app.get("/protected")
async def protected(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{AUTH_URL}/protected",
            headers={"Authorization": f"Bearer {token}"},
        )

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())

    return resp.json()


@app.get("/debug-session")
async def debug_session(request: Request):
    """Debug endpoint to check session status"""
    session_id = request.cookies.get("session_id")
    return {
        "session_id": session_id,
        "session_exists": session_id in session_storage if session_id else False,
        "active_sessions": list(session_storage.keys()),
        "stored_users": list(token_storage.keys()),
    }


@app.get("/protected-auto")
async def protected_auto(request: Request):
    """Protected route with automatic token refresh"""
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(
            status_code=401, detail="No session cookie found. Please login first."
        )

    if session_id not in session_storage:
        raise HTTPException(
            status_code=401, detail="Invalid session. Please login again."
        )

    user_id = session_storage[session_id]
    token = await get_valid_token(user_id)
    if not token:
        # Clean up expired session
        if session_id in session_storage:
            del session_storage[session_id]
        raise HTTPException(status_code=401, detail="Session expired")

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{AUTH_URL}/protected",
            headers={"Authorization": f"Bearer {token}"},
        )

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())

    return resp.json()


@app.post("/logout")
async def logout(request: Request, response: Response):
    """Logout and clear session"""
    session_id = request.cookies.get("session_id")
    if session_id and session_id in session_storage:
        user_id = session_storage[session_id]
        # Clean up tokens and session
        if user_id in token_storage:
            del token_storage[user_id]
        del session_storage[session_id]

    response.delete_cookie("session_id")
    return {"message": "Logged out successfully"}
