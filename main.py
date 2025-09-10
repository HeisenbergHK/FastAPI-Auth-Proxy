from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def root():
    return {"Hello": "World"}


from pydantic import BaseModel


class User(BaseModel):
    email: str
    password: str


import httpx
from fastapi import Body

AUTH_URL = "https://auth-central-challange.vercel.app"


import httpx
from fastapi import FastAPI, HTTPException

app = FastAPI()

AUTH_URL = "https://auth-central-challange.vercel.app"


@app.post("/register")
async def register(user: User):
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{AUTH_URL}/register", json=user.dict())

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())

    return resp.json()


from fastapi import Form


@app.post("/login")
async def login(
    username: str = Form(...),
    password: str = Form(...),
    grant_type: str = Form("password"),
    scope: str = Form(""),
    client_id: str = Form("string"),
    client_secret: str = Form("string"),
):
    """
    Login proxy: forwards form data to the central auth service.
    """
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
            data=data,  # IMPORTANT: use `data` for form-urlencoded
            headers={"accept": "application/json"},
        )

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())

    return resp.json()


from fastapi import Body


@app.post("/refresh")
async def refresh(refresh_token: str = Body(..., embed=True)):
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{AUTH_URL}/refresh", json={"refresh_token": refresh_token}
        )

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())

    return resp.json()


from fastapi import Depends, Header
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

security = HTTPBearer()


@app.get("/protected")
async def protected(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials  # the access_token

    async with httpx.AsyncClient() as client:
        # Forward to central auth service's /protected
        resp = await client.get(
            f"{AUTH_URL}/protected",
            headers={"Authorization": f"Bearer {token}"},
        )

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())

    return resp.json()
