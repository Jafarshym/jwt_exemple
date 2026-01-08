from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from datetime import datetime, timedelta
from pydantic import BaseModel

app = FastAPI()

# Конфигурация
SECRET_KEY = "your_secret_key_here"  # На практике используйте .env
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 6

# Модели данных
class User(BaseModel):
    username: str
    password: str

class TokenData(BaseModel):
    username: str

# Фейковая БД пользователей
fake_users_db = {
    "john": {
        "username": "john",
        "password": "secret",
        "disabled": False
    }
}

# Схема аутентификации
security = HTTPBearer()

# Генерация токенов
def create_tokens(username: str):
    # Access token
    access_payload = {
        "sub": username,
        "type": "access",
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    access_token = jwt.encode(access_payload, SECRET_KEY, algorithm=ALGORITHM)
    
    # Refresh token
    refresh_payload = {
        "sub": username,
        "type": "refresh",
        "exp": datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    }
    refresh_token = jwt.encode(refresh_payload, SECRET_KEY, algorithm=ALGORITHM)
    
    return access_token, refresh_token

# Проверка токена
def verify_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise JWTError("Invalid subject")
        return TokenData(username=username)
    except JWTError as e:
        raise HTTPException(
            status_code=401,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Зависимость для проверки access token
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> TokenData:
    token = credentials.credentials
    return verify_token(token)

# Роут для входа
@app.post("/login")
async def login(user: User, response: Response):
    # Проверка пользователя (в реальном приложении - хеширование пароля)
    db_user = fake_users_db.get(user.username)
    if not db_user or db_user["password"] != user.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Генерация токенов
    access_token, refresh_token = create_tokens(user.username)
    
    # Установка refresh token в httpOnly cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,  # Защита от XSS
        secure=True,     # Только через HTTPS
        samesite="lax",  # Защита от CSRF
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60  # Срок действия
    )
    
    return {"access_token": access_token}

# Роут для обновления токена
@app.post("/refresh")
async def refresh_token(request: Request):
    # Получаем refresh token из куки
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing")
    
    try:
        # Проверяем токен
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        token_type = payload.get("type")
        
        # Убеждаемся, что это refresh token
        if not username or token_type != "refresh":
            raise JWTError("Invalid token type")
        
        # Генерируем новый access token
        new_access_token, _ = create_tokens(username)
        return {"access_token": new_access_token}
    
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

# Защищенный роут
@app.get("/protected")
async def protected_route(request: Request, current_user: TokenData = Depends(get_current_user)):
    # Конкретно Authorization
    auth_header = request.headers.get("Authorization")
    print("Authorization header:", auth_header)
    return {
        "message": f"Hello, {current_user.username}!",
        "status": "You have access to protected content"
    }

# Выход (очистка куки)
@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie("refresh_token")
    return {"message": "Logged out successfully"}

# Запуск приложения (для теста)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)