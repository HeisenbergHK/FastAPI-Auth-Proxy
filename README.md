# FastAPI-Auth-Proxy

*This app handles user registration, login, token refresh, and protected routes by forwarding requests to the central auth service.*

## Features
- User registration (/register)
- Login with form data (/login)
- Refresh access tokens (/refresh)
- Access token-protected routes (/protected)
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

## API Endpoints

1. Register

#### POST /register
Request Body (JSON):
```
{
  "email": "user@example.com",
  "password": "password123"
}
```
- Response: Forwards the response from the central auth service.

2. Login

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
- Response: Access token and refresh token from central auth service.

3. Refresh Token

#### POST /refresh
Request Body (JSON):
```
{
  "refresh_token": "your-refresh-token"
}
```
- Response: New access token and refresh token.

4. Protected Route

#### GET /protected
Headers:
```
Authorization: Bearer <access_token>
```

- Response: Data returned by central auth service if token is valid.

### Notes
- All requests to the central auth service are proxied, so your API does not handle password storage.
- The app uses async calls for better performance.
- Input validation is enforced using Pydantic models.