from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
import firebase_admin
from firebase_admin import credentials, auth

# Initialize Firebase Admin
cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)

app = FastAPI()

async def verify_token(request: Request):
    """Extract and verify Firebase ID token from Authorization header."""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    parts = auth_header.split()
    if parts[0].lower() != "bearer" or len(parts) != 2:
        raise HTTPException(status_code=401, detail="Invalid Authorization header")

    token = parts[1]

    try:
        decoded = auth.verify_id_token(token)
        return decoded
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@app.get("/protected")
async def protected_route(user=Depends(verify_token)):
    uid = user["uid"]
    return {"message": f"Hello {uid}, you are authenticated!"}


# Reading roles
def require_role(required_role: str):
    async def role_checker(user=Depends(verify_token)):
        claims = user.get("role") or user.get("roles") or user.get("customClaims") or user
        user_role = user.get("role")

        if user_role != required_role:
            raise HTTPException(status_code=403, detail="Forbidden: insufficient role")

        return user

    return role_checker

# Example of a route that requires the "admin" role
@app.get("/admin-only")
async def admin_route(user=Depends(require_role("admin"))):
    return {"message": f"Welcome admin {user['uid']}"}