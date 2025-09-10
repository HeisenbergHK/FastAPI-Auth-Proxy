from fastapi import FastAPI, HTTPException, Body, Form, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
import httpx

# Initialize FastAPI application
app = FastAPI()

# Central authentication service URL
AUTH_URL = "https://auth-central-challange.vercel.app"

# Bearer token security scheme for authentication
security = HTTPBearer()


class User(BaseModel):
    """
    Pydantic model for user registration data.
    
    Attributes:
        email (str): User's email address
        password (str): User's password
    """
    email: str
    password: str


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
    username: str = Form(...),
    password: str = Form(...),
    grant_type: str = Form("password"),
    scope: str = Form(""),
    client_id: str = Form("string"),
    client_secret: str = Form("string"),
):
    """
    Authenticate user using OAuth2 password grant flow by proxying to central auth service.
    
    This endpoint follows OAuth2 specification using form-urlencoded data.
    
    Args:
        username (str): User's username/email for login
        password (str): User's password
        grant_type (str): OAuth2 grant type (default: "password")
        scope (str): OAuth2 scope (default: empty)
        client_id (str): OAuth2 client identifier (default: "string")
        client_secret (str): OAuth2 client secret (default: "string")
        
    Returns:
        dict: Authentication tokens (access_token, refresh_token, etc.) from central service
        
    Raises:
        HTTPException: If authentication fails or central service returns error
    """
    # Prepare OAuth2 compliant form data
    data = {
        "grant_type": grant_type,
        "username": username,
        "password": password,
        "scope": scope,
        "client_id": client_id,
        "client_secret": client_secret,
    }

    async with httpx.AsyncClient() as client:
        # Forward login request with form-urlencoded data (not JSON)
        resp = await client.post(
            f"{AUTH_URL}/login",
            data=data,  # Use 'data' for form-urlencoded, 'json' for application/json
            headers={"accept": "application/json"},
        )

    # Handle authentication errors
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())

    return resp.json()


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
            f"{AUTH_URL}/refresh", 
            json={"refresh_token": refresh_token}
        )

    # Handle refresh token errors
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())

    return resp.json()


@app.get("/protected")
async def protected(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Access protected resources by validating Bearer token with central service.
    
    This endpoint requires Bearer token authentication and forwards the request
    to the central service for token validation and resource access.
    
    Args:
        credentials (HTTPAuthorizationCredentials): Bearer token from Authorization header
        
    Returns:
        dict: Protected resource data from central service
        
    Raises:
        HTTPException: If token is invalid, expired, or access is denied
    """
    # Extract Bearer token from credentials
    token = credentials.credentials

    async with httpx.AsyncClient() as client:
        # Forward request to central service with Bearer token
        resp = await client.get(
            f"{AUTH_URL}/protected",
            headers={"Authorization": f"Bearer {token}"},
        )

    # Handle authorization errors
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())

    return resp.json()