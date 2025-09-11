# FastAPI-Auth-Proxy

*This app handles user registration, login, token refresh, and protected routes by forwarding requests to the central auth service with automatic token refresh capability.*

## Features
- User registration (/register)
- Login with form data (/login)
- Manual token refresh (/refresh)
- Protected routes with Bearer token (/protected)
- **Automatic token refresh** for seamless user experience (/protected-auto)
- Token storage with expiration tracking
- Uses async HTTP requests for performance
- Input validation with Pydantic
- Token handling with HTTP Bearer authentication

## Tech Stack
- __FastAPI__ – Python web framework for building APIs
- __Pydantic__ – Data validation
- __HTTPX__ – Async HTTP client
- __Python3.10+__

## Installation

1. Clone the repository:
```
git clone https://github.com/your-username/fastapi-auth-proxy.git
cd fastapi-auth-proxy
```

2. Create a virtual environment:
```
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
.venv\Scripts\activate     # Windows
```

3. Install dependencies:
```
pip install -r requirements.txt
```

## Environment Variables

The app uses the central authentication service URL:
```
AUTH_URL = "https://auth-central-challange.vercel.app"
```

You can optionally move this to an environment variable for flexibility:
```
export AUTH_URL="https://auth-central-challange.vercel.app"
```

## Running the App
Start the FastAPI server using Uvicorn:
```
uvicorn main:app --reload
```
- The API will run at: http://127.0.0.1:8000
- Open API docs at: http://127.0.0.1:8000/docs

## Token Expiration
- **Access Token**: 2 minutes
- **Refresh Token**: 4 minutes
- The app automatically handles token refresh when needed

## API Endpoints

### 1. Register
#### POST /register
Request Body (JSON):
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

### 2. Login
#### POST /login
Request Body (Form Data):
```
username: user@example.com
password: password123
grant_type: password
scope: ""
client_id: string
client_secret: string
```
- **Note**: Tokens are automatically stored for the user after successful login

### 3. Manual Token Refresh
#### POST /refresh
Request Body (JSON):
```json
{
  "refresh_token": "your-refresh-token"
}
```

### 4. Protected Route (Manual Token)
#### GET /protected
Headers:
```
Authorization: Bearer <access_token>
```
- Requires manual token management

### 5. Protected Route (Automatic Refresh)
#### GET /protected-auto
- **New Feature**: Automatically refreshes expired access tokens
- Uses session cookies from login (no parameters needed)
- No need to manually handle token expiration
- Returns 401 if session expired or refresh token expired

### 6. Logout
#### POST /logout
- Clears session and stored tokens
- Removes authentication cookies

## Automatic Token Management
The app now includes intelligent token management:
- **Session-based authentication**: Login creates a secure session cookie
- Tokens are stored server-side with expiration timestamps
- Access tokens are automatically refreshed when expired
- Users don't need to handle token refresh manually
- Session expires when refresh token expires (4 minutes)
- Automatic cleanup of expired sessions and tokens

## Usage Flow
1. **Login** → Creates session cookie + stores tokens
2. **Access /protected-auto** → Uses session cookie (no Bearer token needed)
3. **Automatic refresh** → Happens transparently when access token expires
4. **Logout** → Clears session and tokens

### Notes
- All requests to the central auth service are proxied
- Session-based authentication with HTTP-only cookies
- Token storage is in-memory (use Redis/database in production)
- Async calls for better performance
- Input validation with Pydantic models